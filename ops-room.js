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

/* ── OR-2: resources (+ history), measures (activity flows / pending stocks), incidents ── */
const RESOURCE_KINDS = Object.freeze({ room: 'Room', bed: 'Bed', device: 'Device' });
const RESOURCE_STATUS = Object.freeze({ available: 'Available', in_use: 'In use', out_of_service: 'Out of service', maintenance: 'Maintenance', lent: 'Lent out' });
const INCIDENT_CATEGORIES = Object.freeze({ equipment: 'Equipment', room: 'Room / space', cancellation: 'Cancellation', staffing: 'Staffing', supplies: 'Supplies', other: 'Other' });
const INCIDENT_STATUS = Object.freeze({ open: 'Open', in_progress: 'In progress', resolved: 'Resolved' });
const str = (v, max) => { if (v === undefined || v === null) return null; const s = String(v).trim(); return s ? s.slice(0, max) : null; };
const daysBetween = (a, b) => Math.round((Date.parse(iso(b) + 'T12:00:00Z') - Date.parse(iso(a) + 'T12:00:00Z')) / 86400000);

// Create / edit a resource. Calibration interval drives next_calibration_due when a calibration is recorded.
function validateResource(body, { partial = false } = {}) {
  const out = {};
  if (!partial || body.kind !== undefined) { if (!RESOURCE_KINDS[body.kind]) return { error: 'Kind must be room, bed or device.' }; out.kind = body.kind; }
  if (!partial || body.name !== undefined) { const n = str(body.name, 120); if (!n) return { error: 'A name is required.' }; out.name = n; }
  for (const [k, max] of [['identifier', 80], ['location', 120], ['notes', 500]]) if (body[k] !== undefined) out[k] = str(body[k], max);
  if (body.calibration_interval_days !== undefined) {
    const d = body.calibration_interval_days === null || body.calibration_interval_days === '' ? null : Number(body.calibration_interval_days);
    if (d !== null && (!Number.isInteger(d) || d < 1 || d > 3650)) return { error: 'Calibration interval must be 1–3650 days.' };
    out.calibration_interval_days = d;
  }
  if (body.next_calibration_due !== undefined) { if (body.next_calibration_due && !isIso(body.next_calibration_due)) return { error: 'Invalid calibration date.' }; out.next_calibration_due = body.next_calibration_due || null; }
  return { value: out };
}

// Apply an event to a resource → { patch (resource columns), event (history row) } or { error }.
function applyResourceEvent(resource, ev, today) {
  const type = ev.event_type, on = ev.event_on ? iso(ev.event_on) : today, note = str(ev.note, 500);
  if (!isIso(on)) return { error: 'Invalid date.' };
  if (on > today) return { error: 'Events are recorded on or before today.' };
  const base = { event_type: type, event_on: on, note, from_status: resource.status, to_status: resource.status };
  switch (type) {
    case 'status': {
      if (!RESOURCE_STATUS[ev.to_status] || ev.to_status === 'lent') return { error: 'Choose available, in use, out of service or maintenance (use "Lend" for loans).' };
      if (resource.status === 'lent') return { error: 'This device is lent out — record its return first.' };
      return { patch: { status: ev.to_status }, event: { ...base, to_status: ev.to_status } };
    }
    case 'calibration': {
      const next = ev.next_due ? iso(ev.next_due) : (resource.calibration_interval_days ? addDays(on, resource.calibration_interval_days) : null);
      if (next && (!isIso(next) || next <= on)) return { error: 'The next calibration must be after the calibration date.' };
      return { patch: { last_calibrated_on: on, next_calibration_due: next }, event: { ...base, due_on: next } };
    }
    case 'maintenance': return { patch: {}, event: base };
    case 'loan_out': {
      if (resource.kind !== 'device') return { error: 'Only devices can be lent.' };
      if (resource.status === 'lent') return { error: 'This device is already lent out.' };
      if (['out_of_service', 'maintenance'].includes(resource.status)) return { error: 'This device is not available to lend.' };
      const due = ev.due_on ? iso(ev.due_on) : null;
      if (!due || !isIso(due) || due < on) return { error: 'Set the date it is due back (on or after today).' };
      return { patch: { status: 'lent', loan_due_back: due }, event: { ...base, to_status: 'lent', due_on: due } };
    }
    case 'loan_return': {
      if (resource.status !== 'lent') return { error: 'This device is not lent out.' };
      return { patch: { status: 'available', loan_due_back: null }, event: { ...base, to_status: 'available' } };
    }
    case 'note': if (!note) return { error: 'Write the note.' }; return { patch: {}, event: base };
    default: return { error: 'Unknown event.' };
  }
}

// Alerts a unit card / resource list needs (computed, never stored).
function resourceAlerts(resources, today, soonDays = 14) {
  const soon = addDays(today, soonDays), live = (resources || []).filter(r => !r.deleted_at);
  return {
    total: live.length,
    out_of_service: live.filter(r => ['out_of_service', 'maintenance'].includes(r.status)).length,
    calibration_overdue: live.filter(r => r.next_calibration_due && iso(r.next_calibration_due) < today).length,
    calibration_soon: live.filter(r => r.next_calibration_due && iso(r.next_calibration_due) >= today && iso(r.next_calibration_due) <= soon).length,
    loans_out: live.filter(r => r.status === 'lent').length,
    loans_overdue: live.filter(r => r.status === 'lent' && r.loan_due_back && iso(r.loan_due_back) < today).length,
    beds: live.filter(r => r.kind === 'bed').length,
    beds_available: live.filter(r => r.kind === 'bed' && r.status === 'available').length,
  };
}

// One measurement: flows count what happened on a day (≤ today); stocks are a snapshot (oldest pending date optional).
function validateMeasurement(type, body, today) {
  if (!type || !type.active) return { error: 'Unknown or inactive measure.' };
  const on = body.measured_on ? iso(body.measured_on) : today;
  if (!isIso(on)) return { error: 'Invalid date.' };
  if (on > today) return { error: 'You can only record today or past days.' };
  const v = Number(body.value);
  if (!Number.isInteger(v) || v < 0 || v > 100000) return { error: 'The value must be a whole number from 0.' };
  let oldest = null;
  if (type.kind === 'stock' && body.oldest_pending_on) {
    oldest = iso(body.oldest_pending_on);
    if (!isIso(oldest) || oldest > on) return { error: 'The oldest pending date must be on or before the snapshot date.' };
    if (v === 0) oldest = null;
  }
  return { value: { measured_on: on, value: v, oldest_pending_on: oldest } };
}

// Period summary: flows → total per type over [from, to]; stocks → latest snapshot + previous for trend.
function summarizeMeasures(types, measurements, from, to) {
  const out = [];
  for (const t of (types || []).filter(x => x.active).sort((a, b) => a.sort - b.sort || String(a.label).localeCompare(String(b.label), 'es'))) {
    const rows = (measurements || []).filter(m => String(m.type_id) === String(t.id)).sort((a, b) => (iso(a.measured_on) < iso(b.measured_on) ? 1 : -1));
    if (t.kind === 'flow') {
      const inRange = rows.filter(m => iso(m.measured_on) >= from && iso(m.measured_on) <= to);
      out.push({ type_id: t.id, code: t.code, label: t.label, kind: 'flow', total: inRange.reduce((s, m) => s + m.value, 0), days_recorded: inRange.length,
        by_day: inRange.map(m => ({ date: iso(m.measured_on), value: m.value, id: m.id })) });
    } else {
      const [latest, prev] = rows;
      out.push({ type_id: t.id, code: t.code, label: t.label, kind: 'stock',
        latest: latest ? { date: iso(latest.measured_on), value: latest.value, oldest_pending_on: iso(latest.oldest_pending_on) || null, id: latest.id } : null,
        previous: prev ? { date: iso(prev.measured_on), value: prev.value } : null,
        history: rows.slice(0, 12).map(m => ({ date: iso(m.measured_on), value: m.value })) });
    }
  }
  return out;
}

function validateIncident(body, { partial = false } = {}) {
  const out = {};
  if (!partial || body.category !== undefined) { if (!INCIDENT_CATEGORIES[body.category]) return { error: 'Choose a category.' }; out.category = body.category; }
  if (!partial || body.title !== undefined) { const t = str(body.title, 140); if (!t || t.length < 3) return { error: 'Describe the incident in a few words.' }; out.title = t; }
  if (body.details !== undefined) out.details = str(body.details, 500);
  if (body.resource_id !== undefined) out.resource_id = body.resource_id || null;
  if (body.owner_id !== undefined) out.owner_id = body.owner_id || null;
  if (body.opened_on !== undefined) { if (!isIso(body.opened_on)) return { error: 'Invalid date.' }; out.opened_on = iso(body.opened_on); }
  return { value: out };
}

// Status transitions: resolving needs a resolution note and stamps the date; reopening clears it.
function incidentTransition(incident, to, { resolution, today }) {
  if (!INCIDENT_STATUS[to]) return { error: 'Unknown status.' };
  if (to === incident.status) return { patch: {} };
  if (to === 'resolved') {
    const r = str(resolution, 500); if (!r) return { error: 'Say how it was resolved.' };
    const on = today < iso(incident.opened_on) ? iso(incident.opened_on) : today;
    return { patch: { status: 'resolved', resolved_on: on, resolution: r } };
  }
  return { patch: { status: to, resolved_on: null, resolution: null } };
}

function incidentSummary(incidents, today) {
  const open = (incidents || []).filter(i => !i.deleted_at && i.status !== 'resolved');
  return { open: open.length, oldest_open_days: open.length ? Math.max(...open.map(i => daysBetween(i.opened_on, today))) : null, unowned: open.filter(i => !i.owner_id).length };
}

Object.assign(module.exports, { RESOURCE_KINDS, RESOURCE_STATUS, INCIDENT_CATEGORIES, INCIDENT_STATUS, validateResource, applyResourceEvent, resourceAlerts,
  validateMeasurement, summarizeMeasures, validateIncident, incidentTransition, incidentSummary, daysBetween });
