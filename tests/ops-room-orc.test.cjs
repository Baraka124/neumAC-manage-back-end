'use strict';
// Pneumo Ops Room OR-C: catalogues as data + target history (the past is judged with the target in force then).
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const O = require('../ops-room.js');
const T = '2026-10-16';

test('target in force: latest valid_from on or before the date', () => {
  const h = [{ valid_from: '2026-01-01', value: 40 }, { valid_from: '2026-09-01', value: 30 }, { valid_from: '2027-01-01', value: 25 }];
  assert.equal(O.targetAt(h, '2026-08-31').value, 40);
  assert.equal(O.targetAt(h, '2026-09-01').value, 30);
  assert.equal(O.targetAt(h, T).value, 30);
  assert.equal(O.targetAt(h, '2025-12-31'), null);
});

test('indicator: each period judged with the target in force on its last day; changing it never rewrites the past', () => {
  const data = { measurements: [{ type_id: 'le', measured_on: '2026-08-20', value: 35 }, { type_id: 'le', measured_on: '2026-09-20', value: 35 }, { type_id: 'le', measured_on: '2026-10-10', value: 35 }] };
  const def = { kind: 'stock_latest', params: { type_id: 'le' }, period: 'month', direction: 'max',
    targets: [{ valid_from: '2026-01-01', value: 40, direction: 'max' }, { valid_from: '2026-09-15', value: 30, direction: 'max' }] };
  const r = O.computeIndicator(def, data, T);
  const byStart = Object.fromEntries(r.series.map(s => [s.start, s]));
  assert.equal(byStart['2026-08-01'].target, 40); assert.equal(byStart['2026-08-01'].met, true);    // August keeps its 40
  assert.equal(byStart['2026-09-01'].target, 30); assert.equal(byStart['2026-09-01'].met, false);   // in force on 30 Sep
  assert.equal(r.target_now.value, 30); assert.equal(r.status, 'not_met');
  assert.equal(byStart['2026-05-01'].target, 40);
  // No history yet → periods before the first entry have no target
  assert.equal(O.computeIndicator({ ...def, targets: [{ valid_from: '2026-10-01', value: 30 }] }, data, T).series.find(s => s.start === '2026-08-01').met, null);
  // Pre-OR-C (no `targets` array): the single target applies everywhere
  assert.equal(O.computeIndicator({ ...def, targets: undefined, target: 40 }, data, T).status, 'met');
});

test('interconsultas: each request measured against the target in force when it was received', () => {
  const tf = (p, d) => (p === 'urgent' ? (d >= '2026-10-10' ? 12 : 24) : 168);
  const rows = [
    { priority: 'urgent', status: 'answered', received_at: '2026-10-05T08:00:00Z', answered_at: '2026-10-05T26:00:00Z'.replace('26:00', '23:00') },   // 15h, target 24 → ✓
    { priority: 'urgent', status: 'answered', received_at: '2026-10-12T08:00:00Z', answered_at: '2026-10-12T23:00:00Z' }];                              // 15h, target 12 → ✗
  const s = O.interconsultStats(rows, '2026-10-16T12:00:00Z', '2026-09-16T00:00:00Z', tf);
  assert.equal(s.by_priority.urgent.within_target_pct, 50);
  assert.equal(s.by_priority.urgent.target_hours, 12);                          // today's target
  assert.deepEqual(O.interconsultClock(rows[1], '2026-10-16T12:00:00Z', tf), { hours: 15, target_hours: 12, over: true, answered: true });
  assert.equal(O.indicatorValue({ kind: 'interconsult_within_target_pct' }, { start: '2026-10-01', end: T }, { interconsults: rows, icTargets: tf }, T), 50);
});

test('catalogues: built-in fallback before the migration; database rows replace a list once present', () => {
  const fb = O.catalogFallback();
  assert.ok(fb.ic_service.some(i => i.code === 'cardiologia' && i.label === 'Cardiología'));
  assert.deepEqual(O.activeCodes(fb, 'ic_priority'), ['urgent', 'preferente', 'ordinary']);
  const cat = O.catalogFrom([{ catalog: 'incident_category', code: 'it', label: 'Informática', sort: 1, active: true }, { catalog: 'incident_category', code: 'equipment', label: 'Equipo', sort: 2, active: false }]);
  assert.deepEqual(O.activeCodes(cat, 'incident_category'), ['it']);
  assert.equal(O.labelsOf(cat, 'incident_category').equipment, 'Equipo');      // switched off: still labelled for old records
  assert.equal(cat.roster_role.length, 3);                                       // untouched lists keep the fallback
});

test('catalogue edits: fixed list, locked items, code from the label, calibration default', () => {
  assert.match(O.validateCatalogItem('ic_priority', { label: 'Muy urgente' }).error, /fixed/);
  assert.match(O.validateCatalogItem('roster_role', { active: false }, { existing: { locked: true } }).error, /cannot be switched off/);
  assert.deepEqual(O.validateCatalogItem('ic_service', { label: 'Cirugía Vascular' }).value, { code: 'cirugia_vascular', label: 'Cirugía Vascular', sort: 100 });
  assert.deepEqual(O.validateCatalogItem('device_type', { label: 'Pulsioxímetro', meta: { calibration_days: 365 } }).value.meta, { calibration_days: 365 });
  assert.match(O.validateCatalogItem('device_type', { label: 'X1', meta: { calibration_days: 0 } }).error, /1–3650/);
  assert.match(O.validateCatalogItem('nope', { label: 'x' }).error, /Unknown list/);
  assert.equal(O.validateCatalogItem('ic_priority', { label: 'Urgente (≤ 24 h)' }, { existing: { locked: true } }).value.label, 'Urgente (≤ 24 h)');   // rename allowed
});

test('lists drive validation: roles, incident categories, services and reasons', () => {
  const att = { id: 'a', staff_type: 'attending_physician', employment_status: 'active' };
  assert.equal(O.validateRosterEntry({ staff: att, role: 'tutor' }, T, ['coordinator', 'tutor']).value.role, 'tutor');
  assert.equal(O.validateIncident({ category: 'it', title: 'Sin red' }, { categories: ['it'] }).value.category, 'it');
  assert.match(O.validateInterconsult({ requesting_service: 'Cardiología' }, '2026-10-16T12:00:00Z', { services: ['cardiologia'] }).error, /from the list/);
  assert.equal(O.validateInterconsult({ requesting_service: 'cardiologia', reason_category: 'tos' }, '2026-10-16T12:00:00Z', { services: ['cardiologia'], reasons: ['tos'] }).value.reason_category, 'tos');
});

test('target entries: date, range, direction', () => {
  assert.deepEqual(O.validateTargetEntry({ value: '30', direction: 'max' }, T).value, { value: 30, direction: 'max', valid_from: T, note: null });
  assert.equal(O.validateTargetEntry({ value: '' }, T).value.value, null);                       // "no target from this date"
  assert.match(O.validateTargetEntry({ value: -1 }, T).error, /from 0/);
  assert.match(O.validateTargetEntry({ value: 1, valid_from: '2028-01-01' }, T).error, /a year ahead/);
  assert.match(O.validateTargetEntry({ value: 1, direction: 'up' }, T).error, /min or max/);
});

const src = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
test('routes: configuration is head of department / admin; reads with Units read; indicator targets with the indicator\'s guard', () => {
  assert.match(src, /app\.get\('\/api\/ops\/catalog', authenticateToken, Portfolio\.read\('training_units'\)/);
  for (const r of ["post\\('/api/ops/catalog/:catalog'", "put\\('/api/ops/catalog/:catalog/:code'", "post\\('/api/ops/targets/ic/:priority'"]) assert.match(src, new RegExp(`app\\.${r}, authenticateToken, opsDeptOnlyEarly`));
  assert.match(src, /app\.post\('\/api\/ops\/units\/:unitId\/indicators\/:indId\/targets', authenticateToken, Portfolio\.write\('training_units'\)/);
  assert.match(src, /app\.post\('\/api\/ops\/indicators\/:indId\/targets', authenticateToken, opsDeptOnlyEarly/);
  assert.match(src, /a role switched off later stays valid for the people who already have it/);
});

test('migration: catalogue + targets tables, RLS, audit, provisional IC targets dated, no patient columns', () => {
  const sql = fs.readFileSync(path.join(__dirname, '..', 'migrations', '2026-10-17_ops_room_orc_catalogues_targets.sql'), 'utf8');
  for (const t of ['ops_catalog_items', 'ops_targets']) { assert.match(sql, new RegExp(`create table if not exists public\\.${t} \\(`)); assert.match(sql, new RegExp(`alter table public\\.${t} enable row level security`)); }
  assert.match(sql, /\('ic_priority','urgent',24,'2026-01-01','Provisional/);
  assert.match(sql, /drop constraint if exists ops_incidents_category_check/);
  assert.doesNotMatch(sql.replace(/--[^\n]*/g, ''), /patient|nhc|dni|historia/i);
});
