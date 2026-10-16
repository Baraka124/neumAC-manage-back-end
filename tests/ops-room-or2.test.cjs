'use strict';
// Pneumo Ops Room OR-2: resources (+ history), measures (activity / pending), incidents.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const O = require('../ops-room.js');
const T = '2026-10-16';

test('resource validation: kind, name, calibration interval', () => {
  assert.deepEqual(O.validateResource({ kind: 'device', name: ' Pletismógrafo ', identifier: 'SN-1', calibration_interval_days: 180 }).value,
    { kind: 'device', name: 'Pletismógrafo', identifier: 'SN-1', calibration_interval_days: 180 });
  assert.match(O.validateResource({ kind: 'robot', name: 'x' }).error, /room, bed or device/);
  assert.match(O.validateResource({ kind: 'bed', name: '' }).error, /name/);
  assert.match(O.validateResource({ kind: 'device', name: 'x', calibration_interval_days: 0 }).error, /1–3650/);
  assert.deepEqual(O.validateResource({ notes: 'ok' }, { partial: true }).value, { notes: 'ok' });
});

test('events drive resource state: status, calibration (interval → next due), loans', () => {
  const dev = { kind: 'device', status: 'available', calibration_interval_days: 180 };
  assert.deepEqual(O.applyResourceEvent(dev, { event_type: 'status', to_status: 'out_of_service', note: 'No enciende' }, T).patch, { status: 'out_of_service' });
  assert.deepEqual(O.applyResourceEvent(dev, { event_type: 'calibration', event_on: '2026-10-10' }, T).patch, { last_calibrated_on: '2026-10-10', next_calibration_due: '2027-04-08' });
  assert.deepEqual(O.applyResourceEvent(dev, { event_type: 'loan_out', due_on: '2026-10-18' }, T).patch, { status: 'lent', loan_due_back: '2026-10-18' });
  assert.deepEqual(O.applyResourceEvent({ ...dev, status: 'lent' }, { event_type: 'loan_return' }, T).patch, { status: 'available', loan_due_back: null });
});

test('event guards: no future dates, beds/rooms are not lent, lent devices must return first', () => {
  assert.match(O.applyResourceEvent({ kind: 'device', status: 'available' }, { event_type: 'note', note: 'x', event_on: '2026-10-20' }, T).error, /on or before today/);
  assert.match(O.applyResourceEvent({ kind: 'bed', status: 'available' }, { event_type: 'loan_out', due_on: '2026-10-20' }, T).error, /Only devices/);
  assert.match(O.applyResourceEvent({ kind: 'device', status: 'lent' }, { event_type: 'status', to_status: 'available' }, T).error, /record its return/);
  assert.match(O.applyResourceEvent({ kind: 'device', status: 'available' }, { event_type: 'loan_out' }, T).error, /due back/);
  assert.match(O.applyResourceEvent({ kind: 'device', status: 'out_of_service' }, { event_type: 'loan_out', due_on: '2026-10-20' }, T).error, /not available/);
  assert.match(O.applyResourceEvent({ kind: 'device', status: 'available' }, { event_type: 'calibration', next_due: '2026-10-01' }, T).error, /after the calibration/);
});

test('alerts: out of service, calibration overdue/soon, loans overdue, beds available', () => {
  const a = O.resourceAlerts([
    { kind: 'device', status: 'out_of_service' }, { kind: 'device', status: 'available', next_calibration_due: '2026-10-01' },
    { kind: 'device', status: 'available', next_calibration_due: '2026-10-25' }, { kind: 'device', status: 'lent', loan_due_back: '2026-10-14' },
    { kind: 'bed', status: 'available' }, { kind: 'bed', status: 'in_use' }, { kind: 'room', status: 'available', deleted_at: '2026-10-01' }], T);
  assert.deepEqual(a, { total: 6, out_of_service: 1, calibration_overdue: 1, calibration_soon: 1, loans_out: 1, loans_overdue: 1, beds: 2, beds_available: 1 });
});

test('measurements: whole numbers, no future, oldest pending only for snapshots and never after the date', () => {
  const flow = { kind: 'flow', active: true }, stock = { kind: 'stock', active: true };
  assert.deepEqual(O.validateMeasurement(flow, { value: '12' }, T).value, { measured_on: T, value: 12, oldest_pending_on: null });
  assert.deepEqual(O.validateMeasurement(stock, { value: 30, oldest_pending_on: '2026-08-01' }, T).value, { measured_on: T, value: 30, oldest_pending_on: '2026-08-01' });
  assert.equal(O.validateMeasurement(stock, { value: 0, oldest_pending_on: '2026-08-01' }, T).value.oldest_pending_on, null);
  assert.match(O.validateMeasurement(flow, { value: 3, measured_on: '2026-10-17' }, T).error, /today or past/);
  assert.match(O.validateMeasurement(flow, { value: 2.5 }, T).error, /whole number/);
  assert.match(O.validateMeasurement(stock, { value: 3, oldest_pending_on: '2026-10-20' }, T).error, /on or before/);
  assert.match(O.validateMeasurement({ kind: 'flow', active: false }, { value: 1 }, T).error, /inactive/);
});

test('summary: flows total in the period; stocks latest vs previous', () => {
  const types = [{ id: 'f', code: 'esp', label: 'Espirometrías', kind: 'flow', sort: 1, active: true }, { id: 's', code: 'le', label: 'Lista de espera', kind: 'stock', sort: 10, active: true }, { id: 'x', label: 'Off', kind: 'flow', sort: 2, active: false }];
  const m = [{ type_id: 'f', measured_on: '2026-10-15', value: 10 }, { type_id: 'f', measured_on: '2026-10-16', value: 12 }, { type_id: 'f', measured_on: '2026-09-01', value: 99 },
    { type_id: 's', measured_on: '2026-10-16', value: 40, oldest_pending_on: '2026-08-02' }, { type_id: 's', measured_on: '2026-10-09', value: 35 }];
  const s = O.summarizeMeasures(types, m, '2026-10-01', T);
  assert.equal(s.length, 2);
  assert.equal(s[0].total, 22); assert.equal(s[0].days_recorded, 2);
  assert.deepEqual(s[1].latest, { date: T, value: 40, oldest_pending_on: '2026-08-02', id: undefined });
  assert.deepEqual(s[1].previous, { date: '2026-10-09', value: 35 });
});

test('incidents: validation, resolving needs a note and stamps the date, reopening clears it', () => {
  assert.deepEqual(O.validateIncident({ category: 'equipment', title: 'Pletismógrafo no calibra' }).value, { category: 'equipment', title: 'Pletismógrafo no calibra' });
  assert.match(O.validateIncident({ category: 'x', title: 'abc' }).error, /category/);
  assert.match(O.validateIncident({ category: 'room', title: 'no' }).error, /few words/);
  const inc = { status: 'open', opened_on: '2026-10-10' };
  assert.match(O.incidentTransition(inc, 'resolved', { today: T }).error, /how it was resolved/);
  assert.deepEqual(O.incidentTransition(inc, 'resolved', { resolution: 'Técnico lo reparó', today: T }).patch, { status: 'resolved', resolved_on: T, resolution: 'Técnico lo reparó' });
  assert.deepEqual(O.incidentTransition({ ...inc, status: 'resolved' }, 'open', { today: T }).patch, { status: 'open', resolved_on: null, resolution: null });
  assert.deepEqual(O.incidentSummary([{ status: 'open', opened_on: '2026-10-06' }, { status: 'in_progress', opened_on: '2026-10-14', owner_id: 'a' }, { status: 'resolved', opened_on: '2026-09-01' }], T), { open: 2, oldest_open_days: 10, unowned: 1 });
});

const src = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
test('routes: reads with Units read, writes with Units write under the unit, rows must belong to the unit', () => {
  for (const r of ['resources', 'measures', 'incidents']) assert.match(src, new RegExp(`app\\.get\\('/api/ops/units/:unitId/${r}', authenticateToken, Portfolio\\.read\\('training_units', \\{ child: true \\}\\)`));
  for (const r of ["post\\('/api/ops/units/:unitId/resources'", "post\\('/api/ops/units/:unitId/resources/:resourceId/events'", "put\\('/api/ops/units/:unitId/measures'", "post\\('/api/ops/units/:unitId/incidents'", "put\\('/api/ops/units/:unitId/incidents/:incidentId'"])
    assert.match(src, new RegExp(`app\\.${r}, authenticateToken, Portfolio\\.write\\('training_units'\\)`));
  assert.match(src, /const opsOwned = async \(table, id, unitId, cols = '\*'\) => \{[^\n]*String\(data\.unit_id\) === String\(unitId\)/);
  assert.ok((src.match(/if \(permanent && !opsAdmin\(req\)\) return res\.status\(403\)/g) || []).length >= 3);   // roster, resources, incidents (+ later modules)
});

test('OR-1 keeps working before the OR-2 migration: missing tables read as empty', () => {
  assert.match(src, /async function opsSoft\(query\) \{ const \{ data, error \} = await query; if \(error\) \{ if \(error\.code === '42P01'/);
});

test('migration: 5 tables, RLS, audit triggers, no patient columns', () => {
  const sql = fs.readFileSync(path.join(__dirname, '..', 'migrations', '2026-10-16_ops_room_or2_resources_measures_incidents.sql'), 'utf8');
  for (const t of ['ops_resources', 'ops_resource_events', 'ops_measure_types', 'ops_measurements', 'ops_incidents']) {
    assert.match(sql, new RegExp(`create table if not exists public\\.${t} \\(`)); assert.match(sql, new RegExp(`alter table public\\.${t} enable row level security`));
  }
  assert.match(sql, /create trigger audit_%1\$s after insert or update or delete/);
  assert.doesNotMatch(sql.replace(/--[^\n]*/g, ''), /patient|nhc|dni|historia/i);   // comments may say "no patient data"
});
