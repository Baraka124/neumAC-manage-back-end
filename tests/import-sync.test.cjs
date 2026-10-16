'use strict';
// Import Phase D — re-import as sync (structural guards).
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const src = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
const route = (sig) => { const a = src.indexOf(sig); assert.ok(a >= 0, 'missing ' + sig); const b = src.indexOf('\napp.', a + sig.length); return src.slice(a, b > 0 ? b : undefined); };

test('imported rotations carry structured provenance (file, sheet, actor) and a sync key', () => {
  const r = route("app.post('/api/rotations/batch'");
  assert.match(r, /sync_source:\{file:/);
  assert.match(r, /sync_key:r\.sync_key/);
});

test('replace only ever targets an earlier IMPORTED rotation of the same resident', () => {
  const r = route("app.post('/api/rotations/batch'");
  assert.match(r, /Only rotations created by an earlier import can be replaced from a file/);
  assert.match(r, /A rotation can only be replaced by one of the same resident/);
  assert.match(r, /excludeId:replaced\?\.id\|\|null/);                    // the dry run ignores the row being replaced
});

test('replace hides the old row before inserting and restores it if the insert fails', () => {
  const r = route("app.post('/api/rotations/batch'");
  const hide = r.indexOf('update({deleted_at:nowIso'), ins = r.indexOf(".insert(row)"), restore = r.indexOf('update(restore)');
  assert.ok(hide > 0 && ins > hide && restore > ins, 'hide → insert → restore-on-error order');
});

test('applied imports are logged (import_runs) behind the import authority', () => {
  assert.match(route("app.post('/api/import-runs'"), /importAuthority\(/);
  assert.match(route("app.get('/api/import-runs'"), /importAuthority\(/);
});
