'use strict';
// Import capacity advice: "unit is full as per policy" + next start date + open units,
// and the batch check counting earlier rows of the same file.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const C = require('../import-capacity.js');
const D = require('../decision51.js');

const sleep = { id: 'sueno', unit_name: 'Unidad Sueño', maximum_residents: 2 };
const rot = (id, s, e, o = {}) => ({ id, training_unit_id: 'sueno', start_date: s, end_date: e, rotation_status: 'scheduled', ...o });

test('full unit: full period, next start keeping the end date, next opening, open units', () => {
  const a = C.advise({
    unit: sleep, start: '2026-11-01', end: '2026-12-31',
    rotations: [rot('a', '2026-10-01', '2026-11-30'), rot('b', '2026-11-01', '2026-11-15')],
    units: [sleep, { id: 'pfr', unit_name: 'PFR', maximum_residents: 3, unit_status: 'active' }, { id: 'ccee', unit_name: 'CCEE', maximum_residents: 1, unit_status: 'active' }, { id: 'old', unit_name: 'Old', maximum_residents: 2, unit_status: 'inactive' }],
    unitRotations: [{ id: 'x', training_unit_id: 'ccee', start_date: '2026-12-01', end_date: '2026-12-31', rotation_status: 'active' }],
  });
  assert.equal(a.capacity, 2);
  assert.deepEqual(a.full, [{ start: '2026-11-01', end: '2026-11-15', peak: 2 }]);
  assert.equal(a.next_start, '2026-11-16');
  assert.equal(a.next_opening, null);                 // not needed: a start inside the window fits
  assert.deepEqual(a.open_units.map(u => [u.unit_name, u.free]), [['PFR', 3]]);   // CCEE full in Dec, inactive unit skipped
});

test('full for the whole window → no next start, next opening after it', () => {
  const a = C.advise({ unit: { ...sleep, maximum_residents: 1 }, start: '2026-11-01', end: '2026-11-30',
    rotations: [rot('a', '2026-10-01', '2027-01-15')], units: [], unitRotations: [] });
  assert.equal(a.next_start, null);
  assert.equal(a.next_opening, '2027-01-16');
});

test('early-terminated and cancelled rotations free their place', () => {
  const a = C.advise({ unit: { ...sleep, maximum_residents: 1 }, start: '2026-11-01', end: '2026-11-30',
    rotations: [rot('a', '2026-10-01', '2026-12-31', { rotation_status: 'terminated_early', actual_end_date: '2026-10-20' }), rot('b', '2026-11-01', '2026-11-30', { rotation_status: 'cancelled' })], units: [], unitRotations: [] });
  assert.deepEqual(a.full, []);
});

test('engine capacity counts the same way (terminated early → effective end)', () => {
  const r = D.capacityProjection({ start: '2026-11-01', end: '2026-11-30', unitId: 'sueno' }, { ...sleep, maximum_residents: 1 },
    [rot('a', '2026-10-01', '2026-12-31', { rotation_status: 'terminated_early', actual_end_date: '2026-10-20' })]);
  assert.equal(r.periodsOver.length, 0);
  const full = D.capacityProjection({ start: '2026-11-01', end: '2026-11-30', unitId: 'sueno' }, { ...sleep, maximum_residents: 1 }, [rot('a', '2026-10-01', '2026-12-31', { rotation_status: 'completed' })]);
  assert.equal(full.periodsOver.length, 1);
});

const src = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
const batch = (() => { const a = src.indexOf("app.post('/api/rotations/batch'"); return src.slice(a, src.indexOf('\napp.', a + 10)); })();

test('batch check counts earlier rows of the same file and what they replace', () => {
  assert.match(batch, /buildRotationDecision\(payload,\{action:'assign',excludeId:replaced\?\.id\|\|null,extra:pending,ignore:\[\.\.\.replacedIds\]\}\)/);
  assert.match(batch, /pending\.push\(\{id:'pending-'/);
  assert.match(src, /state\.rotations=\[\.\.\.\(state\.rotations\|\|\[\]\)\.filter\(r=>!skip\.has\(String\(r\.id\)\)\),\.\.\.extra/);
});

test('capacity-blocked rows return advice; hand-entered rotations need an approved replacement', () => {
  assert.match(batch, /codes\.includes\('UNIT_CAPACITY_EXCEEDED'\)\) capacity=await importCapacityAdvice/);
  assert.match(batch, /is full as per policy \(max \$\{capacity\.capacity\} residents\)/);
  assert.match(batch, /if\(!old\.sync_source && r\.replace_confirmed!==true\) throw Error/);
});
