'use strict';
// Backend contract tests — structural guards over the critical invariants of
// index.js. No server boot, no DB: they read the source and assert that the
// safety-relevant shapes stay intact, so an accidental edit (including from a
// parallel thread) that drops auth, leaks a hash, or inverts a role turns red.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const src = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
const lines = src.split('\n');

// Mutation endpoints that are intentionally public (auth flows + contact form).
// Every OTHER mutation must carry an auth guard. Keep this list tight.
const PUBLIC_MUTATIONS = new Set([
  'POST /api/auth/login',
  'POST /api/auth/forgot-password',
  'POST /api/auth/reset-password',
  'POST /api/auth/accept-invitation',
  'POST /api/auth/password-reset/request',
  'POST /api/contact',
  'POST /api/public/client-errors',   // PR-1: browser error reports (public limiter, scrubbed, 204)
  'POST /api/feed/ops/measurements',   // IM-1: hospital feed, guarded by OPS_FEED_TOKEN (constant-time), 404 when unset
]);

function mutationEndpoints() {
  const re = /app\.(post|put|delete|patch)\('(\/api\/[^']+)'(.*)$/;
  const out = [];
  for (const line of lines) {
    const m = line.match(re);
    if (m) out.push({ key: `${m[1].toUpperCase()} ${m[2]}`, guards: m[3] });
  }
  return out;
}

test('every mutation endpoint is authenticated unless explicitly public', () => {
  const unguarded = [];
  for (const ep of mutationEndpoints()) {
    const guarded = /authenticateToken|requireAuthority|Portfolio\.write/.test(ep.guards);
    if (!guarded && !PUBLIC_MUTATIONS.has(ep.key)) unguarded.push(ep.key);
  }
  assert.deepEqual(unguarded, [], `these mutations lack an auth guard: ${unguarded.join(', ')}`);
});

test('the public auth endpoints stay behind the strict auth rate limiter', () => {
  for (const ep of mutationEndpoints()) {
    if (/POST \/api\/auth\/(login|forgot-password|reset-password|accept-invitation)/.test(ep.key)) {
      assert.match(ep.guards, /authLimiter/, `${ep.key} must use authLimiter`);
    }
  }
});

test('request validation strips unknown keys (no silent passthrough of unexpected fields)', () => {
  assert.match(src, /schema\.validate\(req\.body,\s*\{[^}]*stripUnknown:\s*true/,
    'validate() must call Joi with stripUnknown:true');
});

test('the personal-context resolver keeps the correct role precedence', () => {
  // Projects: the lead resolves first and co-investigator is the fallback.
  assert.match(src, /lead_investigator_id === sid \? 'lead'/,
    'project role must resolve the lead first');
  assert.match(src, /'co-investigator'/, 'project role must fall back to co-investigator');
  // Trials: PI resolves first.
  assert.match(src, /principal_investigator_id === sid \? 'PI'/,
    'trial role must resolve PI first');
});

test('the resolver fetches projects where the person leads and where they collaborate', () => {
  // Tolerant of the technical_lead_id term added between lead and co (PR #35).
  assert.match(src, /lead_investigator_id\.eq\.\$\{sid\}[^)]*co_investigators\.cs/,
    'project .or filter must cover lead and co-investigator');
});

test('the public invitation preview returns only name + email, never a secret', () => {
  const idx = src.indexOf("app.get('/api/auth/invitation'");
  assert.ok(idx !== -1, 'the invitation preview endpoint must exist');
  const body = src.slice(idx, idx + 1400);
  // The response the endpoint sends must be name/email/expiry only.
  assert.match(body, /res\.json\(\{\s*valid:\s*true,\s*full_name[^}]*email[^}]*\}\)/,
    'the preview response must be name + email (+ expiry) only');
  assert.doesNotMatch(body, /res\.json\([^)]*password_hash/,
    'the preview must never send a password hash');
});
