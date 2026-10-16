'use strict';
// Import memory (Phase B): saved mappings + layout memory.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const src = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
const route = (sig) => { const a = src.indexOf(sig); assert.ok(a >= 0, 'missing ' + sig); const b = src.indexOf('\napp.', a + sig.length); return src.slice(a, b > 0 ? b : undefined); };

test('import keys normalise exactly like the browser parsers', () => {
  const line = src.split('\n').find(l => l.startsWith('const importKey ='));
  const importKey = eval('(' + line.replace('const importKey =', '').replace(/;\s*$/, '') + ')');
  assert.equal(importKey('  SUEÑO '), 'sueno');
  assert.equal(importKey('Dra. Ana   Santalla'), 'ana santalla');
  assert.equal(importKey('ROT  EXT'), 'rot ext');
});

test('every import-memory route is authenticated and gated by the matching import authority', () => {
  for (const sig of ["app.get('/api/import-aliases'", "app.put('/api/import-aliases'", "app.delete('/api/import-aliases/:id'", "app.get('/api/import-layouts/:type'", "app.put('/api/import-layouts/:type'"]) {
    const r = route(sig);
    assert.match(r.split('\n')[0], /authenticateToken/, sig);
    assert.match(r, /importAuthority\(/, sig);
  }
  assert.match(src, /rotation_resident:\s*\{ authority: 'sync\.rotations\.commit'/);
  assert.match(src, /oncall_staff:\s*\{ authority: 'sync\.oncall\.commit'/);
});

test('saving a mapping validates the target (resident must be an active resident)', () => {
  const r = route("app.put('/api/import-aliases'");
  assert.match(r, /Person is not registered as a resident/);
  assert.match(r, /Person is not active/);
  assert.match(r, /onConflict: 'import_type,source_key'/);
});
