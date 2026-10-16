'use strict';
// The decision engine's "one rotation at a time" rule must match the DB trigger
// check_no_overlapping_rotations: every non-cancelled rotation occupies the resident up to its
// EFFECTIVE end (actual_end_date when terminated early). Otherwise a pre-check says "Ready" and
// the save is refused (seen on 2026-10-16: three October imports).
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const D = require('../decision51.js');

const base = {
  resident: { id: 'res', full_name: 'Cristina', staff_type: 'medical_resident', employment_status: 'active' },
  supervisor: { id: 'sup', full_name: 'Dra. X', staff_type: 'attending_physician', employment_status: 'active' },
  unit: { id: 'uci2', unit_name: 'UCI', unit_status: 'active', maximum_residents: 5 },
  absences: [], oncall: [], action: 'assign',
};
const terminated = { id: 'old', resident_id: 'res', training_unit_id: 'uci', start_date: '2026-09-01', end_date: '2026-10-02', actual_end_date: '2026-09-04', rotation_status: 'terminated_early', training_unit: { unit_name: 'UCI' } };
const review = (start, end, rotations) => D.reviewRotation({ ...base, rotations, proposal: { residentId: 'res', unitId: 'uci2', supervisorId: 'sup', start, end, category: 'clinical_rotation' } });
const concurrent = d => (d.findings || []).filter(f => f.code === 'ROTATION_CONCURRENT_PRIMARY');

test('days actually served in an early-terminated rotation block a new rotation (as the DB does)', () => {
  const f = concurrent(review('2026-09-01', '2026-11-30', [terminated]));
  assert.equal(f.length, 1);
  assert.equal(f[0].evidence.end, '2026-09-04');
});

test('starting the day after the effective end is clear — the planned end no longer counts', () => {
  assert.equal(concurrent(review('2026-09-05', '2026-11-30', [terminated])).length, 0);
  assert.equal(concurrent(review('2026-10-01', '2026-11-30', [terminated])).length, 0);
});

test('completed rotations count; cancelled never do', () => {
  assert.equal(concurrent(review('2026-09-01', '2026-09-30', [{ ...terminated, rotation_status: 'completed', actual_end_date: null }])).length, 1);
  assert.equal(concurrent(review('2026-09-01', '2026-09-30', [{ ...terminated, rotation_status: 'cancelled' }])).length, 0);
});

test('the decision loader no longer drops terminated/completed rotations', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
  const a = src.indexOf('const loadRotationDecisionState'), b = src.indexOf('};', a);
  assert.match(src.slice(a, b), /\.is\('deleted_at', null\)\.neq\('rotation_status','cancelled'\)/);
});
