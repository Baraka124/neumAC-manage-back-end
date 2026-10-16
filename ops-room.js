'use strict';
/* Pneumo Ops Room — pure rules (no DB, no clock: callers pass `today`).
   OR-1: unit operational profile + unit roster ("¿Quién está?").
   Roster = unit_staff (attending physicians and other non-resident staff, by unit, with role and dates).
   Residents are NOT in the roster: they come from Rotations and are linked, never copied. */

const CAPABILITIES = Object.freeze(['roster', 'resources', 'beds', 'calibration', 'loans', 'activity', 'pending', 'incidents', 'indicators']);
const ROLES = Object.freeze({ coordinator: 'Coordinador/a', primary: 'Adjunto/a de la unidad', secondary: 'Colaborador/a' });
const RESIDENT = /resident|fellow|mir/i;
const iso = d => String(d || '').slice(0, 10);
const isIso = d => /^\d{4}-\d{2}-\d{2}$/.test(String(d || '')) && !isNaN(Date.parse(d + 'T12:00:00Z'));
const addDays = (d, n) => { const x = new Date(iso(d) + 'T12:00:00Z'); x.setUTCDate(x.getUTCDate() + n); return x.toISOString().slice(0, 10); };

function validateCapabilities(list) {
  if (!Array.isArray(list)) return { error: 'capabilities must be a list' };
  const bad = list.filter(c => !CAPABILITIES.includes(c));
  if (bad.length) return { error: 'Unknown capability: ' + bad.join(', ') };
  return { value: [...new Set(list)] };
}

// staff: {id, staff_type, employment_status, deleted_at}
function validateRosterEntry({ staff, role, assigned_from, assigned_until }, today) {
  if (!staff || staff.deleted_at) return { error: 'Staff member not found.' };
  if (RESIDENT.test(String(staff.staff_type || ''))) return { error: 'Residents come from Rotations — assign them a rotation in this unit instead.' };
  if ((staff.employment_status || 'active') !== 'active') return { error: 'Only active staff can be added to a unit.' };
  const r = role || 'primary';
  if (!ROLES[r]) return { error: 'Role must be one of: ' + Object.keys(ROLES).join(', ') };
  const from = assigned_from ? iso(assigned_from) : today;
  if (!isIso(from)) return { error: 'Invalid start date.' };
  const until = assigned_until ? iso(assigned_until) : null;
  if (until && !isIso(until)) return { error: 'Invalid end date.' };
  if (until && until < from) return { error: 'The end date must be on or after the start date.' };
  return { value: { role: r, assigned_from: from, assigned_until: until } };
}

// Roster row state relative to today.
function rosterState(row, today) {
  const from = iso(row.assigned_from) || null, until = iso(row.assigned_until) || null;
  if (until && until < today) return 'ended';
  if (from && from > today) return 'upcoming';
  return 'current';
}

// How a membership is removed: one that has not started yet is deleted (it never happened);
// one that started is ended today (history kept). `permanent` always deletes (admins only).
function removalPlan(row, today, permanent) {
  if (permanent) return { action: 'delete' };
  const from = iso(row.assigned_from) || null;
  if (from && from > today) return { action: 'delete' };
  if (rosterState(row, today) === 'ended') return { action: 'none', message: 'This membership has already ended.' };
  return { action: 'end', assigned_until: today };
}

// Residents rotating in a unit in the window [today, today+6] (effective dates; cancelled never count).
function residentsThisWeek(rotations, unitId, today) {
  const end = addDays(today, 6);
  return (rotations || []).filter(r => String(r.training_unit_id) === String(unitId) && !r.deleted_at && r.rotation_status !== 'cancelled'
    && iso(r.actual_start_date || r.start_date) <= end && iso(r.actual_end_date || r.end_date) >= today)
    .map(r => ({ rotation_id: r.id, resident_id: r.resident_id, full_name: r.resident?.full_name || null,
      start_date: iso(r.actual_start_date || r.start_date), end_date: iso(r.actual_end_date || r.end_date), status: r.rotation_status }))
    .sort((a, b) => String(a.full_name).localeCompare(String(b.full_name), 'es'));
}

const ROLE_ORDER = { coordinator: 0, primary: 1, secondary: 2 };
function shapeUnit(unit, roster, rotations, today) {
  const rows = (roster || []).filter(r => String(r.unit_id) === String(unit.id)).map(r => ({
    id: r.id, role: r.role, role_label: ROLES[r.role] || r.role, assigned_from: iso(r.assigned_from) || null, assigned_until: iso(r.assigned_until) || null,
    state: rosterState(r, today), staff: r.staff ? { id: r.staff.id, full_name: r.staff.full_name, staff_type: r.staff.staff_type } : null,
  })).sort((a, b) => (ROLE_ORDER[a.role] ?? 9) - (ROLE_ORDER[b.role] ?? 9) || String(a.staff?.full_name).localeCompare(String(b.staff?.full_name), 'es'));
  const current = rows.filter(r => r.state === 'current');
  return {
    id: unit.id, unit_code: unit.unit_code, unit_name: unit.unit_name, unit_type: unit.unit_type,
    location: [unit.location_building, unit.location_floor].filter(Boolean).join(' · ') || null,
    maximum_residents: unit.maximum_residents, capabilities: unit.ops_capabilities || [],
    roster: { current, upcoming: rows.filter(r => r.state === 'upcoming'), ended: rows.filter(r => r.state === 'ended') },
    coordinators: current.filter(r => r.role === 'coordinator').map(r => r.staff?.full_name).filter(Boolean),
    residents_this_week: residentsThisWeek(rotations, unit.id, today),
  };
}

module.exports = { CAPABILITIES, ROLES, validateCapabilities, validateRosterEntry, rosterState, removalPlan, residentsThisWeek, shapeUnit, addDays };
