'use strict';
// Interface pass: one status per unit (alert / watch / ok) from records the unit already has.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const O = require('../ops-room.js');
const T = '2026-10-17';
const unit = (caps, team = 1) => ({ capabilities: caps, roster: { current: Array(team).fill({}) } });
const quiet = { resources: {}, incidents: { open: 0, unowned: 0, oldest_open_days: null } };

test('ok when nothing needs attention', () => {
  const p = O.unitPulse({ unit: unit(['roster', 'activity']), alerts: quiet, today: T, types: [{ id: 'f', kind: 'flow', label: 'Espirometrías' }], measurements: [{ type_id: 'f', measured_on: '2026-10-16', value: 9 }] });
  assert.equal(p.level, 'ok'); assert.deepEqual(p.reasons, []);
  assert.equal(p.activity.last_recorded_on, '2026-10-16'); assert.equal(p.activity.days_since, 1);
});

test('alert: equipment down, overdue calibration or loans, objectives not met, stale incidents', () => {
  const p = O.unitPulse({ unit: unit([]), today: T, alerts: { resources: { out_of_service: 1, calibration_overdue: 2 }, incidents: { open: 1, oldest_open_days: 12, unowned: 0 } },
    indicators: [{ result: { status: 'not_met' } }, { result: { status: 'met' } }] });
  assert.equal(p.level, 'alert');
  assert.deepEqual(p.reasons.map(r => r.text), ['1 out of service', '2 calibration overdue', '1 objective not met', '1 open incident (oldest 12 d)']);
  assert.deepEqual(p.indicators, { total: 2, met: 1, not_met: 1, no_data: 0, no_target: 0 });
});

test('watch: fresh incident, no owner, calibration soon, activity not recorded, empty team', () => {
  const p = O.unitPulse({ unit: unit(['roster', 'activity'], 0), today: T, alerts: { resources: { calibration_soon: 1 }, incidents: { open: 2, oldest_open_days: 3, unowned: 1 } },
    types: [{ id: 'f', kind: 'flow', label: 'x' }], measurements: [{ type_id: 'f', measured_on: '2026-10-01', value: 1 }] });
  assert.equal(p.level, 'watch');
  assert.ok(p.reasons.every(r => r.level === 'watch'));
  assert.ok(p.reasons.some(r => r.text === 'Activity not recorded for 16 d'));
  assert.ok(p.reasons.some(r => r.text === 'Nobody in the team'));
  // A unit that does not use activity is never flagged for it
  assert.ok(!O.unitPulse({ unit: unit([]), today: T, alerts: quiet, types: [{ id: 'f', kind: 'flow' }] }).reasons.length);
});

test('pending shows each snapshot measure with its latest value and oldest age', () => {
  const p = O.unitPulse({ unit: unit([]), today: T, alerts: quiet, types: [{ id: 's', kind: 'stock', label: 'Lista de espera' }, { id: 'off', kind: 'stock', label: 'Off', active: false }],
    measurements: [{ type_id: 's', measured_on: '2026-10-10', value: 40 }, { type_id: 's', measured_on: '2026-10-16', value: 46, oldest_pending_on: '2026-08-17' }] });
  assert.deepEqual(p.pending, [{ label: 'Lista de espera', value: 46, date: '2026-10-16', oldest_days: 60 }]);
});

test('units list carries the pulse and never fails because of it', () => {
  const idx = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
  assert.match(idx, /OpsRoom\.unitPulse\(\{ unit: shaped, alerts, today/);
  assert.match(idx, /catch \(e\) \{ console\.warn\('Ops pulse skipped:'/);
});
