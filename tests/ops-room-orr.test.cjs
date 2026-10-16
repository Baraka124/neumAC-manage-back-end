'use strict';
// Pneumo Ops Room OR-R: clinical breakdowns (counts only), calls from other departments, weekly / monthly reports.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const O = require('../ops-room.js');
const T = '2026-10-17';
const idx = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
const mig = fs.readFileSync(path.join(__dirname, '..', 'migrations', '2026-10-17_ops_room_orr_breakdowns_calls_reports.sql'), 'utf8');

const cond = { id: 'adm', kind: 'flow', active: true, breakdown: 'clinical_condition', label: 'Ingresos' };
const ages = { id: 'pend', kind: 'stock', active: true, breakdown: 'age_band', label: 'Pendientes' };

test('breakdown: per-category counts, value is their sum, only known categories, whole numbers', () => {
  const cats = ['epoc', 'asma', 'otra'];
  const v = O.validateMeasurement(cond, { measured_on: '2026-10-16', breakdown: { epoc: 3, asma: '2', otra: 0 } }, T, { categories: cats });
  assert.deepEqual(v.value, { measured_on: '2026-10-16', value: 5, oldest_pending_on: null, breakdown: { epoc: 3, asma: 2 } });
  assert.match(O.validateMeasurement(cond, { breakdown: { gripe: 1 } }, T, { categories: cats }).error, /Unknown category/);
  assert.match(O.validateMeasurement(cond, { breakdown: { epoc: 1.5 } }, T, { categories: cats }).error, /whole numbers/);
  assert.match(O.validateMeasurement(cond, { breakdown: { epoc: -1 } }, T, { categories: cats }).error, /whole numbers/);
  assert.match(O.validateMeasurement(cond, { value: 4 }, T, { categories: cats }).error, /counts for each category/);
  assert.match(O.validateMeasurement(cond, { breakdown: {} }, T, { categories: cats }).error, /at least one/);
  // An explicit zero day is a real record
  assert.equal(O.validateMeasurement(cond, { breakdown: { epoc: 0 } }, T, { categories: cats }).value.value, 0);
  // Snapshot with breakdown keeps the oldest pending date
  assert.equal(O.validateMeasurement(ages, { breakdown: { a80p: 2 }, oldest_pending_on: '2026-10-01' }, T, { categories: ['a80p'] }).value.oldest_pending_on, '2026-10-01');
  // Measures without breakdown keep the old shape
  assert.deepEqual(O.validateMeasurement({ kind: 'flow', active: true }, { value: 4 }, T).value, { measured_on: T, value: 4, oldest_pending_on: null });
});

test('breakdown: summaries add categories over the period; no breakdown, no extra fields', () => {
  const m = [{ id: 1, type_id: 'adm', measured_on: '2026-10-15', value: 5, breakdown: { epoc: 3, asma: 2 } }, { id: 2, type_id: 'adm', measured_on: '2026-10-16', value: 4, breakdown: { epoc: 4 } },
    { id: 3, type_id: 'adm', measured_on: '2026-09-01', value: 9, breakdown: { otra: 9 } }];
  const [s] = O.summarizeMeasures([cond], m, '2026-10-10', T);
  assert.equal(s.total, 9); assert.deepEqual(s.by_category, { epoc: 7, asma: 2 }); assert.equal(s.breakdown, 'clinical_condition');
  const [plain] = O.summarizeMeasures([{ id: 'x', kind: 'flow', active: true, label: 'x' }], [{ id: 9, type_id: 'x', measured_on: T, value: 1 }], '2026-10-10', T);
  assert.equal('by_category' in plain, false); assert.equal('breakdown' in plain.by_day[0], false);
});

test('breakdown lists are catalogues; never crossed; no identifiable data anywhere', () => {
  assert.deepEqual(O.BREAKDOWNS, ['clinical_condition', 'age_band', 'sex']);
  for (const b of O.BREAKDOWNS) assert.ok(O.CATALOGS[b]);
  assert.match(mig, /'clinical_condition','age_band','sex'/);
  assert.match(mig, /breakdown text/);
  assert.match(mig, /add column if not exists breakdown jsonb/);
  for (const banned of ['patient_name', 'nhc', 'dni', 'birth_date', 'date_of_birth']) assert.ok(!mig.toLowerCase().includes(banned), banned);
});

test('calls: channel and outcome; a call is logged already resolved by who took it', () => {
  const now = '2026-10-17T10:00:00.000Z';
  assert.match(O.validateInterconsult({ requesting_service: 'urgencias', channel: 'phone' }, now).error, /how the call ended/);
  assert.match(O.validateInterconsult({ requesting_service: 'urgencias', channel: 'fax', outcome: 'advice' }, now).error, /Channel/);
  assert.match(O.validateInterconsult({ requesting_service: 'urgencias', channel: 'phone', outcome: 'x' }, now).error, /outcome/);
  assert.match(O.validateInterconsult({ requesting_service: 'urgencias', channel: 'phone', outcome: 'advice', duration_min: 0 }, now).error, /1–600/);
  const v = O.validateInterconsult({ requesting_service: 'urgencias', channel: 'phone', outcome: 'advice', duration_min: 10, received_at: '2026-10-17T09:00:00Z' }, now).value;
  assert.equal(v.channel, 'phone');
  const row = O.callRecord(v, 'st1', now);
  assert.equal(row.status, 'closed'); assert.equal(row.answered_by, 'st1');
  assert.equal(row.answered_at, '2026-10-17T09:10:00.000Z'); assert.equal(row.closed_at, row.answered_at);
  // Formal stays as it was
  assert.equal(O.validateInterconsult({ requesting_service: 'urgencias' }, now).value.channel, 'formal');
  assert.equal(O.callRecord({ channel: 'formal', received_at: now }, 'st1', now).status, undefined);
  // End never after now
  assert.equal(O.callRecord({ channel: 'phone', received_at: '2026-10-17T09:55:00Z', duration_min: 30 }, 's', now).answered_at, now);
});

test('calls never distort interconsulta response times; they are counted on their own', () => {
  const now = '2026-10-17T12:00:00.000Z', from = '2026-10-01T00:00:00.000Z';
  const rows = [
    { priority: 'urgent', status: 'answered', received_at: '2026-10-10T08:00:00Z', answered_at: '2026-10-10T20:00:00Z', requesting_service: 'cardio' },
    { priority: 'ordinary', status: 'closed', channel: 'phone', outcome: 'advice', duration_min: 5, received_at: '2026-10-11T08:00:00Z', answered_at: '2026-10-11T08:05:00Z', requesting_service: 'urgencias', answered_by: 'Ana' },
    { priority: 'ordinary', status: 'closed', channel: 'in_person', outcome: 'seen', duration_min: 20, received_at: '2026-10-12T08:00:00Z', answered_at: '2026-10-12T08:20:00Z', requesting_service: 'urgencias', answered_by: 'Ana' },
    { priority: 'ordinary', status: 'closed', channel: 'phone', outcome: 'converted', received_at: '2026-09-12T08:00:00Z', answered_at: '2026-09-12T08:20:00Z', requesting_service: 'mi' }
  ];
  const s = O.interconsultStats(rows, now, from);
  assert.equal(s.received, 1); assert.equal(s.answered, 1); assert.equal(s.median_hours, 12);
  const c = O.callStats(rows, from, now);
  assert.equal(c.total, 2); assert.equal(c.minutes, 25);
  assert.deepEqual(c.by_service, [{ key: 'urgencias', count: 2 }]);
  assert.deepEqual(c.by_clinician, [{ key: 'Ana', count: 2 }]);
  assert.equal(c.by_outcome.length, 2);
  // Indicator: calls in the period, optionally by outcome
  const def = { kind: 'calls_total', params: {}, period: 'month' };
  assert.equal(O.indicatorValue(def, { start: '2026-10-01', end: '2026-10-31' }, { interconsults: rows }, T), 2);
  assert.equal(O.indicatorValue({ ...def, params: { outcome: 'seen' } }, { start: '2026-10-01', end: '2026-10-31' }, { interconsults: rows }, T), 1);
  assert.ok(O.IND_KINDS.calls_total);
});

test('report periods: last complete Mon–Sun week and calendar month, with the one before', () => {
  assert.deepEqual(O.reportPeriod('week', '2026-10-17'), { period: 'week', start: '2026-10-05', end: '2026-10-11', previous: { start: '2026-09-28', end: '2026-10-04' }, complete: true });
  assert.equal(O.reportPeriod('week', '2026-10-12').start, '2026-10-05');   // Monday → last week
  assert.equal(O.reportPeriod('week', '2026-10-18').start, '2026-10-05');   // Sunday → week still running is not "complete"
  const jan = O.reportPeriod('month', '2026-01-05');
  assert.deepEqual([jan.start, jan.end, jan.previous.start, jan.previous.end], ['2025-12-01', '2025-12-31', '2025-11-01', '2025-11-30']);
  const mar = O.reportPeriod('month', '2026-03-15');
  assert.equal(mar.end, '2026-02-28'); assert.equal(mar.previous.end, '2026-01-31');
  const cur = O.reportPeriod('month', T, '2026-10-01');
  assert.equal(cur.end, '2026-10-31'); assert.equal(cur.complete, false);
});

test('unit report: activity vs previous period with breakdowns, pending, incidents, indicators with the target in force', () => {
  const rp = O.reportPeriod('week', T);
  const types = [cond, ages, { id: 'off', kind: 'flow', active: false, label: 'Off' }];
  const measurements = [
    { type_id: 'adm', measured_on: '2026-10-06', value: 6, breakdown: { epoc: 4, asma: 2 } }, { type_id: 'adm', measured_on: '2026-10-07', value: 4, breakdown: { epoc: 4 } },
    { type_id: 'adm', measured_on: '2026-09-29', value: 8, breakdown: { epoc: 8 } },
    { type_id: 'pend', measured_on: '2026-10-10', value: 12, oldest_pending_on: '2026-09-30', breakdown: { a80p: 12 } }
  ];
  const incidents = [{ category: 'equipment', opened_on: '2026-10-06', resolved_on: null }, { category: 'staffing', opened_on: '2026-09-01', resolved_on: '2026-10-08' }];
  const ind = { def: { name: 'Pendientes ≤ 10', kind: 'stock_latest', params: { type_id: 'pend' }, period: 'week', direction: 'max', targets: [{ valid_from: '2026-01-01', value: 10, direction: 'max' }] }, data: { measurements } };
  const r = O.buildUnitReport(rp, { unit: { id: 'u1', unit_name: 'Broncoscopias', unit_code: 'BRO' }, types, measurements, incidents, today: T, indicators: [ind],
    labels: { clinical_condition: { epoc: 'EPOC', asma: 'Asma' }, age_band: { a80p: '≥ 80' }, incident_category: { equipment: 'Equipo' } } });
  assert.equal(r.activity.length, 1);
  const a = r.activity[0];
  assert.equal(a.total, 10); assert.equal(a.previous, 8); assert.equal(a.change_pct, 25);
  assert.deepEqual(a.breakdown, [{ code: 'epoc', label: 'EPOC', count: 8 }, { code: 'asma', label: 'Asma', count: 2 }]);
  assert.equal(r.pending[0].latest.value, 12); assert.equal(r.pending[0].latest.oldest_days, 10); assert.equal(r.pending[0].latest.breakdown[0].label, '≥ 80');
  assert.deepEqual([r.incidents.opened, r.incidents.resolved, r.incidents.open_at_end], [1, 1, 1]);
  assert.equal(r.incidents.by_category[0].label, 'Equipo');
  assert.equal(r.indicators[0].value, 12); assert.equal(r.indicators[0].target, 10); assert.equal(r.indicators[0].met, false);
  assert.equal(r.summary.indicators_not_met, 1);
  assert.equal(JSON.stringify(r).includes('full_name'), false);
});

test('department report: interconsultas + calls, unit roll-up, department indicators', () => {
  const rp = O.reportPeriod('week', T);
  const unit = O.buildUnitReport(rp, { unit: { id: 'u1', unit_name: 'Broncoscopias', unit_code: 'BRO' }, types: [cond], measurements: [{ type_id: 'adm', measured_on: '2026-10-06', value: 6 }], incidents: [], today: T });
  const ic = [
    { priority: 'urgent', status: 'answered', received_at: '2026-10-06T08:00:00Z', answered_at: '2026-10-06T18:00:00Z', requesting_service: 'cardio' },
    { priority: 'ordinary', status: 'received', received_at: '2026-09-30T08:00:00Z', requesting_service: 'mi' },
    { priority: 'ordinary', status: 'closed', channel: 'phone', outcome: 'advice', duration_min: 7, received_at: '2026-10-07T08:00:00Z', answered_at: '2026-10-07T08:07:00Z', requesting_service: 'urgencias' }
  ];
  const d = O.buildDepartmentReport(rp, { unitReports: [unit], interconsults: ic, today: T, labels: { ic_service: { cardio: 'Cardiología', urgencias: 'Urgencias' } } });
  assert.equal(d.kind, 'department');
  assert.equal(d.units[0].name, 'Broncoscopias'); assert.equal(d.units[0].headline[0].total, 6);
  assert.equal(d.interconsults.received, 1); assert.equal(d.interconsults.received_previous, 1);
  assert.equal(d.interconsults.answered, 1); assert.equal(d.interconsults.by_service[0].label, 'Cardiología');
  assert.equal(d.calls.total, 1); assert.equal(d.calls.minutes, 7); assert.equal(d.calls.by_service[0].label, 'Urgencias');
  assert.deepEqual(d.indicators, []);
});

test('routes: unit + department reports, lazy generation, guards; calls and breakdowns wired', () => {
  assert.match(idx, /app\.get\('\/api\/ops\/units\/:unitId\/reports', authenticateToken, Portfolio\.read\('training_units', \{ child: true \}\)/);
  assert.match(idx, /app\.post\('\/api\/ops\/units\/:unitId\/reports\/generate', authenticateToken, Portfolio\.write\('training_units'\)/);
  assert.match(idx, /app\.get\('\/api\/ops\/reports', authenticateToken, Portfolio\.read\('training_units'\)/);
  assert.match(idx, /app\.post\('\/api\/ops\/reports\/generate', authenticateToken, opsDeptOnlyEarly/);
  assert.match(idx, /lazy: the last complete week and month/);
  assert.match(idx, /OpsRoom\.callRecord\(/);
  assert.match(idx, /OpsRoom\.BREAKDOWNS\.includes\(breakdown\)/);
  assert.match(idx, /async function opsCompat\(/);
  // Report snapshots are unique per scope / unit / period
  assert.match(mig, /create unique index if not exists ops_reports_one/);
  assert.match(mig, /alter table public\.ops_reports enable row level security/);
});
