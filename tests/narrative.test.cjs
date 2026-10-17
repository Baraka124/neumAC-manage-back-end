'use strict';
// Report narrative + Grounded snapshot: plain words from the numbers only.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const N = require('../narrative.js');
const idx = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');

test('unit narrative: rose / fell ≥ 10 %, pending growth and old waits to watch, objectives not met, unrecorded noted', () => {
  const n = N.narrate({ kind: 'unit', activity: [{ label: 'Ingresos', total: 23, previous: 19, change_pct: 21.1, recorded: true, breakdown: [{ label: 'EPOC', count: 10 }] },
      { label: 'Altas', total: 18, previous: 20, change_pct: -10, recorded: true }, { label: 'Broncoscopias', total: 5, previous: 5, change_pct: 0, recorded: true }, { label: 'PFR', total: 0, previous: 3, change_pct: -100, recorded: false }],
    pending: [{ label: 'Lista de espera', latest: { value: 46, oldest_days: 81 }, previous_value: 40 }],
    incidents: { open_at_end: 1 }, indicators: [{ name: 'Espera ≤ 40', value: 46, target: 40, direction: 'max', met: false }] });
  assert.equal(n.headline, '1 objective not met');
  assert.deepEqual(n.rose, ['Ingresos: 23 (+21.1 % vs 19)']);
  assert.deepEqual(n.fell, ['Altas: 18 (-10 % vs 20)']);
  assert.ok(n.watch.includes('Lista de espera grew to 46 (+15 %)'));
  assert.ok(n.watch.includes('Lista de espera: oldest waiting 81 days'));
  assert.ok(n.watch.includes('Objective not met: Espera ≤ 40 (46 vs ≤ 40)'));
  assert.ok(n.notes.includes('PFR: not recorded in this period'));
  assert.ok(n.notes.includes('Ingresos: EPOC was 43 %'));
  assert.match(N.narrativeText(n), /^1 objective not met\. Rose: Ingresos/);
});
test('department narrative: interconsultas and calls vs previous, units to watch; stable when nothing moves', () => {
  const n = N.narrate({ kind: 'department', interconsults: { received: 41, received_previous: 30, within_target_pct: 72, median_hours: 26 }, calls: { total: 27, previous_total: 22, minutes: 310 },
    units: [{ name: 'PFR', indicators_not_met: 1, incidents_open: 2, activity_measures: 2, activity_recorded: 2 }, { name: 'Sueño', activity_measures: 1, activity_recorded: 0 }], indicators: [] });
  assert.ok(n.rose.includes('Interconsultas received: 41 (+36.7 %)'));
  assert.ok(n.rose.some(x => x.startsWith('Calls from other services: 27')));
  assert.ok(n.watch.includes('72 % of interconsultas answered within target (median 26 h)'));
  assert.ok(n.watch.includes('PFR: 1 objective not met') && n.watch.includes('PFR: 2 incidents open'));
  assert.ok(n.notes.includes('Sueño: no activity recorded'));
  assert.equal(N.narrate({ kind: 'department', interconsults: {}, calls: {}, units: [], indicators: [] }).headline, 'A stable period');
});
test('wiring: reports carry the narrative; Grounded snapshot is read-only, Units read', () => {
  assert.match(idx, /narrative: Narrative\.narrate\(r\.content\)/);
  assert.match(idx, /app\.get\('\/api\/ops\/grounded', authenticateToken, Portfolio\.read\('training_units'\), apiLimiter,/);
  assert.match(idx, /async function opsComputeOutlook\(weeks\)/);
});
