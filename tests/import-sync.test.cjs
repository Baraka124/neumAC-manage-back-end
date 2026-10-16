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

test('replace targets the same resident; a hand-entered rotation only with an approved replacement', () => {
  const r = route("app.post('/api/rotations/batch'");
  assert.match(r, /if\(!old\.sync_source && r\.replace_confirmed!==true\) throw Error\('This rotation was entered by hand\. Approve the replacement in the preview first\.'\)/);
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

test('existing-records lookup returns provenance behind the import authority', () => {
  const r = route("app.post('/api/imports/existing'");
  assert.match(r, /importAuthority\(/);
  assert.match(r, /sync_source, sync_key/);
  assert.match(r, /\.is\('deleted_at', null\)/);
});
