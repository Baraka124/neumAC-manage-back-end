'use strict';
// Pneumo Ops Room OR-1: unit profile + roster ("¿Quién está?").
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const O = require('../ops-room.js');
const T = '2026-10-16';
const att = { id: 'a', staff_type: 'attending_physician', employment_status: 'active' };

test('roster accepts non-resident active staff with a valid role and dates', () => {
  assert.deepEqual(O.validateRosterEntry({ staff: att, role: 'coordinator' }, T).value, { role: 'coordinator', assigned_from: T, assigned_until: null });
  assert.equal(O.validateRosterEntry({ staff: att }, T).value.role, 'primary');
  assert.equal(O.validateRosterEntry({ staff: att, assigned_from: '2026-11-01', assigned_until: '2027-01-31' }, T).value.assigned_until, '2027-01-31');
});

test('residents are refused (they come from Rotations); inactive, bad role and bad dates too', () => {
  assert.match(O.validateRosterEntry({ staff: { ...att, staff_type: 'medical_resident' } }, T).error, /Residents come from Rotations/);
  assert.match(O.validateRosterEntry({ staff: { ...att, employment_status: 'inactive' } }, T).error, /Only active staff/);
  assert.match(O.validateRosterEntry({ staff: att, role: 'boss' }, T).error, /Role must be/);
  assert.match(O.validateRosterEntry({ staff: att, assigned_from: '2026-11-01', assigned_until: '2026-10-01' }, T).error, /on or after/);
  assert.match(O.validateRosterEntry({ staff: null }, T).error, /not found/);
});

test('removal: not started → deleted; started → ended today; ended → nothing; permanent → deleted', () => {
  assert.deepEqual(O.removalPlan({ assigned_from: '2026-11-01' }, T), { action: 'delete' });
  assert.deepEqual(O.removalPlan({ assigned_from: '2026-09-01' }, T), { action: 'end', assigned_until: T });
  assert.equal(O.removalPlan({ assigned_from: '2026-01-01', assigned_until: '2026-03-01' }, T).action, 'none');
  assert.deepEqual(O.removalPlan({ assigned_from: '2026-01-01', assigned_until: '2026-03-01' }, T, true), { action: 'delete' });
});

test('unit shape: roster split current/upcoming/ended, coordinators, residents this week (effective dates)', () => {
  const unit = { id: 'pfr', unit_code: 'PFR', unit_name: 'PFR', ops_capabilities: ['roster', 'calibration'] };
  const roster = [
    { id: 1, unit_id: 'pfr', role: 'primary', assigned_from: '2026-01-01', staff: { id: 'b', full_name: 'Beatriz' } },
    { id: 2, unit_id: 'pfr', role: 'coordinator', assigned_from: '2026-01-01', staff: { id: 'a', full_name: 'Ana' } },
    { id: 3, unit_id: 'pfr', role: 'secondary', assigned_from: '2026-11-01', staff: { id: 'c', full_name: 'Carlos' } },
    { id: 4, unit_id: 'pfr', role: 'primary', assigned_from: '2025-01-01', assigned_until: '2025-12-31', staff: { id: 'd', full_name: 'Diego' } },
    { id: 5, unit_id: 'other', role: 'primary', assigned_from: '2026-01-01', staff: { id: 'e', full_name: 'Eva' } }];
  const rot = [
    { id: 'r1', resident_id: 'x', training_unit_id: 'pfr', start_date: '2026-10-01', end_date: '2026-10-31', rotation_status: 'active', resident: { full_name: 'Laura' } },
    { id: 'r2', resident_id: 'y', training_unit_id: 'pfr', start_date: '2026-10-01', end_date: '2026-12-31', actual_end_date: '2026-10-10', rotation_status: 'terminated_early', resident: { full_name: 'Iria' } },
    { id: 'r3', resident_id: 'z', training_unit_id: 'pfr', start_date: '2026-10-20', end_date: '2026-11-30', rotation_status: 'scheduled', resident: { full_name: 'Cristina' } },
    { id: 'r4', resident_id: 'w', training_unit_id: 'pfr', start_date: '2026-10-01', end_date: '2026-10-31', rotation_status: 'cancelled', resident: { full_name: 'X' } }];
  const u = O.shapeUnit(unit, roster, rot, T);
  assert.deepEqual(u.roster.current.map(r => r.staff.full_name), ['Ana', 'Beatriz']);          // coordinator first
  assert.deepEqual(u.roster.upcoming.map(r => r.staff.full_name), ['Carlos']);
  assert.deepEqual(u.roster.ended.map(r => r.staff.full_name), ['Diego']);
  assert.deepEqual(u.coordinators, ['Ana']);
  assert.deepEqual(u.residents_this_week.map(r => r.full_name), ['Cristina', 'Laura']);       // Iria ended early; cancelled never
});

test('capability catalogue is closed', () => {
  assert.deepEqual(O.validateCapabilities(['roster', 'roster', 'beds']).value, ['roster', 'beds']);
  assert.match(O.validateCapabilities(['roster', 'teleport']).error, /Unknown capability/);
});

const src = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
test('routes are guarded: read for views, Units write for roster, admin for profile and permanent delete', () => {
  assert.match(src, /app\.get\('\/api\/ops\/units', authenticateToken, Portfolio\.read\('training_units'\)/);
  assert.match(src, /app\.post\('\/api\/ops\/units\/:unitId\/staff', authenticateToken, Portfolio\.write\('training_units'\)/);
  assert.match(src, /app\.put\('\/api\/ops\/units\/:unitId\/staff\/:entryId', authenticateToken, Portfolio\.write\('training_units'\)/);
  assert.match(src, /app\.delete\('\/api\/ops\/units\/:unitId\/staff\/:entryId', authenticateToken, Portfolio\.write\('training_units'\)/);
  assert.match(src, /if \(!opsAdmin\(req\)\) return res\.status\(403\)[^\n]*Ops Room profile/);
  assert.match(src, /if \(permanent && !opsAdmin\(req\)\) return res\.status\(403\)/);
  assert.match(src, /String\(row\.unit_id\) !== String\(req\.params\.unitId\)/);           // entry must belong to the unit in the URL
});

test('migration is recorded in the repo', () => {
  const sql = fs.readFileSync(path.join(__dirname, '..', 'migrations', '2026-10-16_ops_room_or1_unit_profile_and_roster.sql'), 'utf8');
  assert.match(sql, /add column if not exists ops_enabled/);
  assert.match(sql, /create unique index if not exists unit_staff_one_active on public\.unit_staff \(unit_id, staff_id\) where assigned_until is null/);
  assert.match(sql, /create trigger audit_unit_staff/);
});
