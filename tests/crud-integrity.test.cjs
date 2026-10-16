'use strict';
// CRUD integrity guards (structural, no server/DB). Each test pins a defect that
// was found in production data/code so it cannot silently come back.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const src = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
const route = (sig) => {
  const a = src.indexOf(sig); assert.ok(a >= 0, 'route missing: ' + sig);
  const b = src.indexOf('\napp.', a + sig.length);
  return src.slice(a, b > 0 ? b : undefined);
};

test('rotations: remove works at any stage and permanent delete is role-gated', () => {
  const r = route("app.delete('/api/rotations/:id'");
  assert.match(r, /req\.query\.mode === 'remove'/);
  assert.match(r, /String\(req\.query\.permanent\) === 'true'/);
  assert.match(r, /\['system_admin', 'department_head'\]\.includes\(req\.user\.role\)/);
  // permanent branch must run its role check before any delete()
  const perm = r.slice(r.indexOf("req.query.permanent"), r.indexOf("req.query.mode === 'remove'"));
  assert.ok(perm.indexOf('403') < perm.indexOf('.delete()'), 'role check precedes hard delete');
});

test('restore rebuilds hard-deleted rows from the audit trail', () => {
  const r = route("app.put('/api/restore/:table/:id'");
  assert.match(r, /from\('audit_log'\)/);
  assert.match(r, /\.eq\('action', 'DELETE'\)/);
});

test('attachments use real columns and private storage, not the local disk', () => {
  const up = route("app.post('/api/attachments/upload'");
  for (const col of ['file_name', 'file_url', 'file_size', 'mime_type', 'uploaded_by']) assert.ok(up.includes(col + ':'), col);
  for (const bad of ['original_filename', 'file_path', 'description:']) assert.ok(!up.includes(bad), 'stale column ' + bad);
  assert.match(up, /storage\.from\(ATTACHMENT_BUCKET\)\.upload/);
  assert.ok(!/fs\.unlinkSync/.test(route("app.delete('/api/attachments/:id'")), 'no local-disk delete');
});

test('availability and department impact only read columns that exist', () => {
  assert.ok(!src.includes('current_resident_count'), 'training_units has no current_resident_count');
  const impact = route("app.get('/api/departments/:id/impact'");
  assert.ok(!/resident_rotations'\)\.select\([^)]*\bsupervisor_id\b/.test(impact), 'resident_rotations has no supervisor_id');
  assert.match(impact, /supervising_attending_id/);
});

test('previously unguarded write routes now check permission', () => {
  assert.match(route("app.post('/api/live-status'"), /only post a clinical status in your own name/);
  assert.match(route("app.delete('/api/live-status/:id'"), /only clear your own clinical status/);
  assert.match(route("app.post('/api/hospitals'"), /checkPermission\('departments', 'create'\)/);
  assert.match(route("app.put('/api/brain/:id'"), /authenticateToken, isAdmin/);
  assert.match(route("app.delete('/api/brain/:id'"), /authenticateToken, isAdmin/);
  assert.match(route("app.post('/api/brain'"), /b\.kind !== 'failed_query'/);
  assert.match(route("app.post('/api/notify/test'"), /authenticateToken, isAdmin/);
  assert.match(route("app.delete('/api/grounded/watchlist/:id'"), /\.eq\('user_id', req\.user\.id\)/);
});

test('saves no longer fail silently', () => {
  assert.ok(!/from\('(clinical_trial_lines|innovation_project_lines)'\)\.delete\(\)\.eq\('(clinical_trial_id|innovation_project_id)'/.test(src), 'no delete-all-then-insert link sync');
  assert.match(src, /async function syncResearchLineLinks/);
  assert.match(route("app.put('/api/clinical-trials/:id/execution-clearance'"), /saveExecutionClearance\('clinical_trial_id'/);
  assert.match(route("app.put('/api/innovation-projects/:id/execution-clearance'"), /saveExecutionClearance\('innovation_project_id'/);
  const abs = route("app.post('/api/absence-records'");
  const rec = abs.slice(abs.indexOf('Generate recurring instances'), abs.indexOf("recurringWarning = 'The first"));
  assert.ok(rec.length > 0 && !rec.includes('setImmediate(') && rec.includes('await (async () =>'), 'recurring repeats are awaited before responding');
  assert.match(abs, /recurringWarning/);
  assert.match(route("app.put('/api/notifications/:id/read'"), /if \(error\) throw error/);
});
