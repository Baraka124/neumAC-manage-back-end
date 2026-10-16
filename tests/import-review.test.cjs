'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { reviewImport } = require('../import-review.js');
const staff = [{ id: 'A', full_name: 'Adela' }, { id: 'B', full_name: 'Berta' }, { id: 'C', full_name: 'Cecilia' }, { id: 'M', full_name: 'Marta MIR' }, { id: 'E', full_name: 'Efrén' }];
const codes = f => Object.values(f.rows).flat().map(x => x.code);

test('guardias: consecutive days for the same person are flagged (also against existing shifts)', () => {
  const r = reviewImport({ kind: 'oncall', today: '2026-10-16', staff,
    proposed: [{ key: 'k1', duty_date: '2026-11-02', primary_physician_id: 'A', resident_physician_id: 'M' }],
    existing: { oncall: [{ duty_date: '2026-11-03', primary_physician_id: 'B', resident_physician_id: 'M' }], rotations: [] } });
  assert.ok(r.rows.k1.some(f => f.code === 'IMPORT_CONSECUTIVE_DUTY' && /Marta MIR \(MIR\)/.test(f.message)));
});

test('guardias: MIR on an external rotation that day is flagged', () => {
  const r = reviewImport({ kind: 'oncall', today: '2026-10-16', staff,
    proposed: [{ key: 'k1', duty_date: '2028-10-15', primary_physician_id: 'A', resident_physician_id: 'E' }],
    existing: { oncall: [], rotations: [{ resident_id: 'E', start_date: '2028-10-01', end_date: '2028-11-30', rotation_status: 'scheduled', unit: { unit_code: 'ROT-EXT', unit_name: 'Rotación Externa' } }] } });
  assert.ok(codes(r).includes('IMPORT_MIR_ON_EXTERNAL_ROTATION'));
  assert.equal(r.summary.far, 1);
});

test('guardias: workload above the month average and uncovered days are reported', () => {
  const proposed = [];
  const days = ['01','02','03','04','05','06','07','08','09','10'];
  days.forEach((d, i) => proposed.push({ key: 'k' + d, duty_date: '2026-11-' + d, primary_physician_id: i < 7 ? 'A' : (i === 7 ? 'B' : 'C'), resident_physician_id: null }));
  proposed.splice(4, 1);                                                      // 5 Nov left without a guardia
  const r = reviewImport({ kind: 'oncall', today: '2026-10-16', staff, proposed, existing: { oncall: [], rotations: [] } });
  // A has 6 of 9 shifts; B 1, C 2 → average 3 → A is above max(avg+2, avg*1.5)=5
  assert.ok(r.summary.overload.some(o => o.person === 'Adela' && o.count === 6));
  assert.deepEqual(r.summary.uncoveredDays, ['2026-11-05']);
  assert.equal(r.summary.withoutMir, 9);
});

test('rotations: rows of the same file that overlap each other are flagged', () => {
  const r = reviewImport({ kind: 'rotations', today: '2026-10-16', staff, units: [{ id: 'u1', unit_name: 'UCI' }, { id: 'u2', unit_name: 'PFR' }],
    proposed: [{ key: 'r1', resident_id: 'M', training_unit_id: 'u1', start_date: '2026-11-01', end_date: '2026-12-31' },
               { key: 'r2', resident_id: 'M', training_unit_id: 'u2', start_date: '2026-12-01', end_date: '2026-12-31' }],
    existing: { rotations: [] } });
  assert.equal(r.summary.inFileOverlaps, 1);
  assert.ok(r.rows.r1[0].code === 'IMPORT_IN_FILE_OVERLAP' && r.rows.r2[0].code === 'IMPORT_IN_FILE_OVERLAP');
});

test('rotations: months without any rotation in the next 12 months are reported per resident', () => {
  const r = reviewImport({ kind: 'rotations', today: '2026-10-16', staff, units: [],
    proposed: [{ key: 'r1', resident_id: 'M', training_unit_id: 'u1', start_date: '2026-10-01', end_date: '2027-03-31' }],
    existing: { rotations: [{ resident_id: 'M', start_date: '2027-06-01', end_date: '2027-09-30', rotation_status: 'scheduled' },
                            { resident_id: 'M', start_date: '2027-04-01', end_date: '2027-05-31', rotation_status: 'cancelled' }] } });
  assert.deepEqual(r.summary.gaps, [{ resident: 'Marta MIR', months: ['2027-04', '2027-05'] }]);   // cancelled does not count
});

test('today is required and the kind must be known', () => {
  assert.throws(() => reviewImport({ kind: 'oncall' }), /today/);
  assert.throws(() => reviewImport({ kind: 'x', today: '2026-10-16' }), /Unknown/);
});
