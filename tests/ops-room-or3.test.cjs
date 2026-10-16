'use strict';
// Pneumo Ops Room OR-2b (interconsultas) + OR-3 (¿Cumplimos? indicators).
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const O = require('../ops-room.js');
const NOW = '2026-10-16T12:00:00.000Z', T = '2026-10-16';

test('interconsulta validation: service, priority, no future reception, notes capped', () => {
  const v = O.validateInterconsult({ requesting_service: 'Cardiología', priority: 'urgent', reason_category: 'derrame' }, NOW).value;
  assert.equal(v.received_at, NOW); assert.equal(v.priority, 'urgent');
  assert.match(O.validateInterconsult({ requesting_service: 'X' }, NOW).error, /requesting service/);
  assert.match(O.validateInterconsult({ requesting_service: 'Cardiología', priority: 'asap' }, NOW).error, /urgent, preferente or ordinary/);
  assert.match(O.validateInterconsult({ requesting_service: 'Cardiología', received_at: '2026-10-17T12:00:00Z' }, NOW).error, /future/);
  assert.match(O.validateInterconsult({ requesting_service: 'Cardiología', reason_category: 'magic' }, NOW).error, /Unknown reason/);
});

test('lifecycle: received → assigned → answered → follow-up → closed → reopen', () => {
  let row = { status: 'received', received_at: '2026-10-16T08:00:00Z' };
  let r = O.interconsultAction(row, 'assign', { staffId: 'ana', nowIso: NOW }); row = { ...row, ...r.patch };
  assert.equal(row.status, 'assigned'); assert.equal(row.assigned_to, 'ana');
  r = O.interconsultAction(row, 'answer', { staffId: 'ana', nowIso: NOW }); row = { ...row, ...r.patch };
  assert.equal(row.status, 'answered'); assert.equal(row.answered_by, 'ana'); assert.equal(row.answered_at, NOW);
  row = { ...row, ...O.interconsultAction(row, 'follow_up', { nowIso: NOW }).patch }; assert.equal(row.status, 'follow_up');
  row = { ...row, ...O.interconsultAction(row, 'close', { nowIso: NOW }).patch }; assert.equal(row.status, 'closed');
  assert.match(O.interconsultAction(row, 'answer', { nowIso: NOW }).error, /reopen/);
  assert.equal(O.interconsultAction(row, 'reopen', { nowIso: NOW }).patch.status, 'answered');
});

test('lifecycle guards: answer not before reception, close needs an answer, answer without assignment self-assigns', () => {
  const row = { status: 'received', received_at: '2026-10-16T08:00:00Z' };
  assert.match(O.interconsultAction(row, 'answer', { staffId: 'a', at: '2026-10-16T07:00:00Z', nowIso: NOW }).error, /before the request/);
  assert.match(O.interconsultAction(row, 'close', { nowIso: NOW }).error, /Answer it before closing/);
  const p = O.interconsultAction(row, 'answer', { staffId: 'luis', nowIso: NOW }).patch;
  assert.equal(p.assigned_to, 'luis'); assert.equal(p.answered_by, 'luis');
});

test('stats: waiting, overdue by priority target, median and % within target, by service', () => {
  const rows = [
    { priority: 'urgent', status: 'answered', requesting_service: 'Urgencias', received_at: '2026-10-15T08:00:00Z', answered_at: '2026-10-15T14:00:00Z', answered_by: 'a' },   // 6h ✓
    { priority: 'urgent', status: 'closed', requesting_service: 'Urgencias', received_at: '2026-10-10T08:00:00Z', answered_at: '2026-10-11T20:00:00Z', answered_by: 'b' },    // 36h ✗
    { priority: 'ordinary', status: 'received', requesting_service: 'Cardiología', received_at: '2026-10-08T12:00:00Z' },                                               // 192h waiting → overdue (168)
    { priority: 'urgent', status: 'assigned', assigned_to: 'a', requesting_service: 'UCI / Reanimación', received_at: '2026-10-16T06:00:00Z' }];                    // 6h waiting
  const s = O.interconsultStats(rows, NOW, '2026-09-16T12:00:00Z');
  assert.equal(s.waiting, 2); assert.equal(s.overdue, 1); assert.equal(s.unassigned, 1);
  assert.equal(s.by_priority.urgent.answered, 2); assert.equal(s.by_priority.urgent.median_hours, 21); assert.equal(s.by_priority.urgent.within_target_pct, 50);
  assert.equal(s.within_target_pct, 50); assert.equal(s.oldest_waiting_hours, 192);
  assert.deepEqual(s.by_service[0], { key: 'Urgencias', count: 2 });
  assert.deepEqual(O.interconsultClock(rows[2], NOW), { hours: 192, target_hours: 168, over: true, answered: false });
});

test('periods: months, weeks (Monday), quarters, current one partial', () => {
  assert.deepEqual(O.periodBounds('month', T, 2), [{ start: '2026-09-01', end: '2026-09-30', partial: false }, { start: '2026-10-01', end: T, partial: true }]);
  assert.deepEqual(O.periodBounds('week', T, 1), [{ start: '2026-10-12', end: T, partial: true }]);
  assert.deepEqual(O.periodBounds('quarter', T, 2), [{ start: '2026-07-01', end: '2026-09-30', partial: false }, { start: '2026-10-01', end: T, partial: true }]);
});

test('indicators computed from records: activity, pending, oldest, incidents, calibration, interconsultas, manual', () => {
  const data = {
    measurements: [{ type_id: 'esp', measured_on: '2026-09-10', value: 100 }, { type_id: 'esp', measured_on: '2026-09-20', value: 120 }, { type_id: 'esp', measured_on: '2026-10-02', value: 50 },
      { type_id: 'le', measured_on: '2026-10-01', value: 40, oldest_pending_on: '2026-07-01' }, { type_id: 'le', measured_on: '2026-10-15', value: 35, oldest_pending_on: '2026-08-15' }],
    resources: [{ kind: 'device', calibration_interval_days: 180, next_calibration_due: '2026-12-01' }, { kind: 'device', calibration_interval_days: 180, next_calibration_due: '2026-10-01' }, { kind: 'room' }],
    incidents: [{ opened_on: '2026-09-01', resolved_on: '2026-09-05' }, { opened_on: '2026-09-28', resolved_on: null }, { opened_on: '2026-10-03', resolved_on: '2026-10-10' }],
    interconsults: [{ priority: 'urgent', received_at: '2026-10-05T08:00:00Z', answered_at: '2026-10-05T10:00:00Z' }, { priority: 'ordinary', received_at: '2026-10-01T08:00:00Z', answered_at: '2026-10-10T08:00:00Z' },
      { priority: 'urgent', received_at: '2026-10-16T08:00:00Z', answered_at: null }],
    manualValues: [{ indicator_id: 'm1', period_start: '2026-09-01', value: 92 }],
  };
  const v = (def, p) => O.indicatorValue(def, p, data, T);
  const sep = { start: '2026-09-01', end: '2026-09-30' }, oct = { start: '2026-10-01', end: T };
  assert.equal(v({ kind: 'measure_total', params: { type_id: 'esp' } }, sep), 220);
  assert.equal(v({ kind: 'stock_latest', params: { type_id: 'le' } }, oct), 35);
  assert.equal(v({ kind: 'oldest_pending_days', params: { type_id: 'le' } }, oct), 61);
  assert.equal(v({ kind: 'calibration_ok_pct' }, oct), 50);
  assert.equal(v({ kind: 'calibration_ok_pct' }, sep), null);                        // no reconstruction of the past
  assert.equal(v({ kind: 'incidents_open' }, sep), 1);
  assert.equal(v({ kind: 'incident_resolution_days' }, oct), 7);
  assert.equal(v({ kind: 'interconsult_within_target_pct' }, oct), 50);              // urgent 2h ✓, ordinary 216h ✗
  assert.equal(v({ kind: 'interconsult_median_hours', params: { priority: 'urgent' } }, oct), 2);
  assert.equal(v({ kind: 'interconsult_pending' }, oct), 1);
  assert.equal(v({ id: 'm1', kind: 'manual' }, sep), 92);
});

test('status against target: min / max, no target, no data', () => {
  const data = { measurements: [{ type_id: 'le', measured_on: '2026-10-15', value: 35 }] };
  assert.equal(O.computeIndicator({ kind: 'stock_latest', params: { type_id: 'le' }, period: 'month', direction: 'max', target: 30 }, data, T).status, 'not_met');
  assert.equal(O.computeIndicator({ kind: 'stock_latest', params: { type_id: 'le' }, period: 'month', direction: 'max', target: 40 }, data, T).status, 'met');
  assert.equal(O.computeIndicator({ kind: 'stock_latest', params: { type_id: 'le' }, period: 'month', direction: 'max', target: null }, data, T).status, 'no_target');
  assert.equal(O.computeIndicator({ kind: 'stock_latest', params: { type_id: 'x' }, period: 'month', direction: 'min', target: 1 }, data, T).status, 'no_data');
  assert.equal(O.computeIndicator({ kind: 'stock_latest', params: { type_id: 'le' }, period: 'week', direction: 'max', target: 30 }, data, T).series.length, 6);
});

test('indicator validation: unit-only kinds, measure required, direction, target', () => {
  assert.match(O.validateIndicator({ name: 'Lista', kind: 'stock_latest', direction: 'max' }, { unitScoped: true }).error, /Choose the measure/);
  assert.match(O.validateIndicator({ name: 'Lista', kind: 'stock_latest', params: { type_id: 't' }, direction: 'max' }, { unitScoped: false }).error, /belongs to a unit/);
  assert.match(O.validateIndicator({ name: 'X ok', kind: 'manual' }, { unitScoped: false }).error, /minimum or a maximum/);
  assert.match(O.validateIndicator({ name: 'X ok', kind: 'manual', direction: 'min', target: -1 }, { unitScoped: false }).error, /from 0/);
  assert.deepEqual(O.validateIndicator({ name: 'IC urgentes', kind: 'interconsult_within_target_pct', params: { priority: 'urgent' }, direction: 'min', target: 90, iso_clause: '7101 §8.2' }, { unitScoped: false }).value,
    { name: 'IC urgentes', kind: 'interconsult_within_target_pct', params: { priority: 'urgent' }, period: 'month', direction: 'min', target: 90, iso_clause: '7101 §8.2' });
});

const src = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
test('guards: interconsultas — staff log, assignee or manager acts, managers edit, admins delete permanently; department indicators admin-only', () => {
  assert.match(src, /if \(!req\.user\.medical_staff_id && !\(await opsUnitsWrite\(req\)\)\) return res\.status\(403\)/);
  assert.match(src, /if \(!manager && !mine\) return res\.status\(403\)/);
  assert.match(src, /if \(!\(await opsUnitsWrite\(req\)\)\) return res\.status\(403\)\.json\(\{ error: 'Only unit managers can edit an interconsulta\.' \}\)/);
  assert.match(src, /app\.post\('\/api\/ops\/indicators', authenticateToken, opsDeptOnly,/);
  assert.match(src, /app\.post\('\/api\/ops\/units\/:unitId\/indicators', authenticateToken, Portfolio\.write\('training_units'\)/);
  assert.match(src, /if \(row\.kind !== 'manual'\) return res\.status\(400\)/);
});

test('migration: 3 tables, RLS, audit, no patient columns', () => {
  const sql = fs.readFileSync(path.join(__dirname, '..', 'migrations', '2026-10-16_ops_room_or2b_or3_interconsults_indicators.sql'), 'utf8');
  for (const t of ['ops_interconsults', 'ops_indicators', 'ops_indicator_values']) { assert.match(sql, new RegExp(`create table if not exists public\\.${t} \\(`)); assert.match(sql, new RegExp(`alter table public\\.${t} enable row level security`)); }
  assert.doesNotMatch(sql.replace(/--[^\n]*/g, ''), /patient|nhc|dni|historia/i);
});
