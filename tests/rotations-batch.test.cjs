'use strict';
// Contract for POST /api/rotations/batch (reviewed MIR rotations import).
// Structural assertions over index.js (no live DB in CI), matching the repo style.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const src = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');

function handler(route, method='post'){
  const needle=`app.${method}('${route}'`;
  const start=src.indexOf(needle);
  assert.ok(start!==-1, `${method.toUpperCase()} ${route} not found`);
  const end=src.indexOf('\napp.', start+needle.length);
  return src.slice(start, end===-1?src.length:end);
}
const h = handler('/api/rotations/batch');

test('batch import is authority-gated on sync.rotations.commit (scope all)', () => {
  assert.match(h, /requireAuthority\('sync\.rotations\.commit',\{scopes:\['all'\]\}\)/);
});

test('supports dry-run check and real commit from one endpoint', () => {
  assert.match(h, /const dryRun=req\.body\?\.dry_run===true/);
  assert.match(h, /if\(dryRun\)\{ ready\+\+; results\.push\(\{\.\.\.tag,status:'ready'\}\); continue; \}/);
  assert.match(h, /status:dryRun\?'needs_attention':'not_saved'/);
});

test('bounded batch size', () => {
  assert.match(h, /rotations\.length>300/);
});

test('resolves an existing unit or creates one on the fly (never rejects the file)', () => {
  assert.match(h, /if\(r\.training_unit_id\) return r\.training_unit_id/);
  assert.match(h, /from\('training_units'\)\.select\('id'\)\.eq\('unit_code',code\)/);
  assert.match(h, /from\('training_units'\)\.insert\(/);
  // a dry run must not create units
  assert.match(h, /if\(dryRun\)\{ unitByCode\[code\]='\(new\)'; return '\(new\)'; \}/);
});

test('idempotent: an identical resident+unit+window is skipped, not duplicated', () => {
  assert.match(h, /\.eq\('resident_id',r\.resident_id\)\.eq\('training_unit_id',training_unit_id\)\s*\n?\s*\.eq\('start_date',start\)\.eq\('end_date',end\)/);
  assert.match(h, /status:'skipped',message:'Already imported/);
});

test('overlap/capacity go through the shared rotation decision engine + trigger backstop', () => {
  assert.match(h, /buildRotationDecision\(payload,\{action:'assign'\}\)/);
  assert.match(h, /enforceRotationDecision\(\{decision, override:r\.decision_override, req, action:'assign'\}\)/);
  assert.match(h, /e\.code==='P0001'/);
});

test('supervisor is optional: explicit, else unit default, else null (never fabricated)', () => {
  assert.match(h, /let supervisor=r\.supervising_attending_id\|\|null/);
  assert.match(h, /select\('default_supervisor_id'\)/);
  assert.match(h, /supervisor=u\?\.default_supervisor_id\|\|null/);
});

test('status is derived from dates, not trusted from the file', () => {
  assert.match(h, /const rotation_status = start>today \? 'scheduled' : \(end<today \? 'completed' : 'active'\)/);
});
