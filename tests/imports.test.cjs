'use strict';
const test = require('node:test'), assert = require('node:assert');
const fs = require('fs'), path = require('path');
const I = require('../imports.js');
const src = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
const sql = fs.readFileSync(path.join(__dirname, '..', 'migrations', '2026-10-17_import_im1_mappings_batches.sql'), 'utf8');

const types = {
  t1: { id: 't1', unit_id: 'u1', label: 'Espirometrías', kind: 'flow', active: true },
  t2: { id: 't2', unit_id: 'u1', label: 'Consultas por patología', kind: 'flow', active: true, breakdown: 'condition' },
  t3: { id: 't3', unit_id: 'u2', label: 'Lista de espera', kind: 'stock', active: true },
  t4: { id: 't4', unit_id: 'u2', label: 'Apagada', kind: 'flow', active: false }
};
const mappings = [
  { system: 'his', external_key: 'ESP', type_id: 't1', unit_id: 'u1' },
  { system: 'his', external_key: 'CX-EPOC', type_id: 't2', unit_id: 'u1', category_code: 'copd' },
  { system: 'his', external_key: 'CX-ASMA', type_id: 't2', unit_id: 'u1', category_code: 'asthma' },
  { system: 'his', external_key: 'LE', type_id: 't3', unit_id: 'u2' },
  { system: 'his', external_key: 'OFF', type_id: 't4', unit_id: 'u2' },
  { system: 'other', external_key: 'ESP', type_id: 't3', unit_id: 'u2' }
];
const categories = { condition: ['copd', 'asthma', 'ild'] };
const plan = (csv, existing = []) => I.planImport({ rows: I.parseFile(csv).rows, system: 'his', today: '2026-10-17', mappings, types, categories, existing });

test('CSV: ; delimiter, Spanish headers, quotes, BOM, DD/MM/YYYY', () => {
  const p = I.parseFile('﻿Código;Fecha;Valor\r\n"ESP";15/10/2026;12\r\nLE;2026-10-16;"40"\r\n');
  assert.equal(p.rows.length, 2); assert.deepEqual(p.rows[0], { line: 2, key: 'ESP', date: '15/10/2026', value: '12', category: null });
  assert.equal(I.parseDate('15/10/2026'), '2026-10-15'); assert.equal(I.parseDate('31/02/2026'), null); assert.equal(I.parseDate('2026-10-15T08:00'), '2026-10-15');
});

test('patient-like columns reject the whole file (CSV and feed)', () => {
  for (const h of ['NHC', 'Nombre', 'DNI', 'paciente_id', 'Fecha nacimiento', 'SIP']) {
    const p = I.parseFile(`key,date,value,${h}\nESP,2026-10-15,1,x\n`);
    assert.ok(p.error && /patient data/.test(p.error), h);
  }
  assert.ok(I.fromFeed([{ key: 'ESP', date: '2026-10-15', value: 1, nhc: '123' }]).error);
  assert.ok(!I.parseFile('key,date,value,servicio\nESP,2026-10-15,1,NML\n').error);   // other columns are just ignored
});

test('missing columns, empty, too big', () => {
  assert.match(I.parseFile('key,value\nESP,1').error, /date/);
  assert.match(I.parseFile('').error, /empty/);
  assert.match(I.parseFile('key,date,value\n' + 'ESP,2026-10-15,1\n'.repeat(I.MAX_ROWS + 1)).error, /More than|larger/);
});

test('plan: insert, aggregation into breakdown, row errors', () => {
  const p = plan('key,date,value\nESP,2026-10-15,12\nCX-EPOC,2026-10-15,5\nCX-ASMA,2026-10-15,3\nCX-EPOC,2026-10-15,1\nNOPE,2026-10-15,1\nESP,2026-10-18,1\nESP,15/10/2026,x\nOFF,2026-10-15,2\n');
  assert.equal(p.plan.insert, 2);
  const bd = p.writes.find(w => w.type_id === 't2');
  assert.deepEqual(bd.breakdown, { asthma: 3, copd: 6 }); assert.equal(bd.value, 9);
  assert.equal(p.errors.length, 4); assert.deepEqual(p.unknown_keys, ['NOPE']);
  assert.ok(p.errors.some(e => /Future/.test(e.error))); assert.ok(p.errors.some(e => /switched off/.test(e.error)));
});

test('plan: system scopes the keys', () => {
  const p = I.planImport({ rows: I.parseFile('key,date,value\nESP,2026-10-15,7').rows, system: 'other', today: '2026-10-17', mappings, types, categories });
  assert.equal(p.writes[0].type_id, 't3');
});

test('plan: never overwrites manual; unchanged is skipped; import value is updated', () => {
  const csv = 'key,date,value\nESP,2026-10-15,12\nESP,2026-10-14,5\nLE,2026-10-15,40\n';
  const p = plan(csv, [
    { type_id: 't1', measured_on: '2026-10-15', value: 10, source: 'manual' },
    { type_id: 't1', measured_on: '2026-10-14', value: 5, source: 'import' },
    { type_id: 't3', measured_on: '2026-10-15', value: 38, source: 'feed' }]);
  assert.deepEqual(p.plan.manual_kept, [{ label: 'Espirometrías', date: '2026-10-15', manual: 10, file: 12 }]);
  assert.equal(p.plan.unchanged, 1); assert.equal(p.plan.update, 1); assert.equal(p.writes.length, 1); assert.equal(p.writes[0].value, 40);
});

test('plan: two snapshots of a stock on one day is an error', () => {
  const p = plan('key,date,value\nLE,2026-10-15,40\nLE,2026-10-15,41\n');
  assert.equal(p.errors.length, 1); assert.equal(p.writes[0].value, 40);
});

test('checksum: same content in any order/format is the same; different value differs', () => {
  const a = plan('key,date,value\nESP,2026-10-15,12\nLE,2026-10-15,40\n').checksum;
  const b = plan('Clave;Fecha;Valor\nLE;15/10/2026;40\nESP;15/10/2026;12\n').checksum;
  const c = plan('key,date,value\nESP,2026-10-15,13\nLE,2026-10-15,40\n').checksum;
  assert.equal(a, b); assert.notEqual(a, c); assert.equal(a.length, 64);
});

test('mapping validation and feed token', () => {
  assert.ok(I.validateMapping({ system: 'HIS', external_key: 'ESP', unit_id: 'u', type_id: 't' }).value.system === 'his');
  assert.ok(I.validateMapping({ system: 'h', external_key: 'ESP', unit_id: 'u', type_id: 't' }).error);
  assert.ok(I.validateMapping({ system: 'his', external_key: 'a b', unit_id: 'u', type_id: 't' }).error);
  assert.equal(I.tokenOk('abc', 'abc'), true); assert.equal(I.tokenOk('abd', 'abc'), false); assert.equal(I.tokenOk('', ''), false); assert.equal(I.tokenOk('x', ''), false);
});

test('routes: department-only, server re-plans on commit, feed off without token', () => {
  for (const r of ["get('/api/ops/import/mappings'", "post('/api/ops/import/mappings'", "put('/api/ops/import/mappings/:id'", "delete('/api/ops/import/mappings/:id'",
    "post('/api/ops/import/preview'", "post('/api/ops/import/commit'", "get('/api/ops/import/batches'", "post('/api/ops/import/batches/:id/undo'"])
    assert.match(src, new RegExp(`app\\.${r.replace(/[()/:]/g, m => '\\' + m)}, authenticateToken, opsDeptOnlyEarly`), r);
  assert.match(src, /app\.post\('\/api\/feed\/ops\/measurements', publicApiLimiterGuarded[\s\S]{0,120}if \(!OPS_FEED_TOKEN\) return res\.status\(404\)/);
  assert.match(src, /Imports\.tokenOk\(given, OPS_FEED_TOKEN\)/);
  assert.match(src, /already_imported\) return res\.status\(409\)/);
});

test('SQL: once per checksum, manual kept in the transaction, undo leaves hand edits', () => {
  assert.match(sql, /unique index if not exists ops_import_batches_once on public\.ops_import_batches \(system, checksum\) where status = 'committed'/);
  assert.match(sql, /if cur\.source = 'manual' then kept := kept \+ 1; continue; end if;/);
  assert.match(sql, /where import_batch_id = p_batch and source in \('import','feed'\)/);
  assert.match(sql, /enable row level security/); assert.doesNotMatch(sql, /\b(nhc|dni|patient_name|nombre)\b/i);
  for (const f of ['ops_import_commit', 'ops_import_undo']) assert.match(sql, new RegExp(`revoke all on function public\\.${f}\\(`));
});

test('feed is not blocked by the release check or maintenance mode', () => {
  assert.match(src, /if\(!req\.path\.startsWith\('\/feed\/'\) && !\['GET','HEAD','OPTIONS'\]/);
  assert.match(src, /req\.path\.startsWith\('\/feed\/'\)\) return next\(\)/);
});
