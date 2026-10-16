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
function validateRosterEntry({ staff, role, assigned_from, assigned_until }, today, roles = Object.keys(ROLES)) {
  if (!staff || staff.deleted_at) return { error: 'Staff member not found.' };
  if (RESIDENT.test(String(staff.staff_type || ''))) return { error: 'Residents come from Rotations — assign them a rotation in this unit instead.' };
  if ((staff.employment_status || 'active') !== 'active') return { error: 'Only active staff can be added to a unit.' };
  const r = role || 'primary';
  if (!roles.includes(r)) return { error: 'Choose one of the roles defined for units.' };
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
function shapeUnit(unit, roster, rotations, today, roleLabels = ROLES) {
  const rows = (roster || []).filter(r => String(r.unit_id) === String(unit.id)).map(r => ({
    id: r.id, role: r.role, role_label: roleLabels[r.role] || r.role, assigned_from: iso(r.assigned_from) || null, assigned_until: iso(r.assigned_until) || null,
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
// With a breakdown (OR-R), `body.breakdown` = { code: count } over the measure's list and the value is their sum.
function validateMeasurement(type, body, today, { categories = null } = {}) {
  if (!type || !type.active) return { error: 'Unknown or inactive measure.' };
  const on = body.measured_on ? iso(body.measured_on) : today;
  if (!isIso(on)) return { error: 'Invalid date.' };
  if (on > today) return { error: 'You can only record today or past days.' };
  if (type.breakdown) {
    const b = body.breakdown && typeof body.breakdown === 'object' ? body.breakdown : null;
    if (!b) return { error: 'Enter the counts for each category.' };
    const out = {};
    for (const [code, raw] of Object.entries(b)) {
      if (raw === '' || raw === null || raw === undefined) continue;
      if (categories && !categories.includes(code)) return { error: 'Unknown category: ' + code };
      const n = Number(raw); if (!Number.isInteger(n) || n < 0 || n > 100000) return { error: 'Counts must be whole numbers from 0.' };
      if (n > 0) out[code] = n;
    }
    const total = Object.values(out).reduce((a, n) => a + n, 0);
    if (!Object.keys(b).some(k => b[k] !== '' && b[k] !== null && b[k] !== undefined)) return { error: 'Enter at least one count (0 is fine).' };
    let oldest = null;
    if (type.kind === 'stock' && body.oldest_pending_on && total > 0) { oldest = iso(body.oldest_pending_on); if (!isIso(oldest) || oldest > on) return { error: 'The oldest pending date must be on or before the snapshot date.' }; }
    return { value: { measured_on: on, value: total, oldest_pending_on: oldest, breakdown: out } };
  }
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
const sumBreakdowns = rows => rows.reduce((acc, m) => { for (const [k, n] of Object.entries(m.breakdown || {})) acc[k] = (acc[k] || 0) + Number(n || 0); return acc; }, {});

// Period summary: flows → total per type over [from, to]; stocks → latest snapshot + previous for trend.
function summarizeMeasures(types, measurements, from, to) {
  const out = [];
  for (const t of (types || []).filter(x => x.active).sort((a, b) => a.sort - b.sort || String(a.label).localeCompare(String(b.label), 'es'))) {
    const rows = (measurements || []).filter(m => String(m.type_id) === String(t.id)).sort((a, b) => (iso(a.measured_on) < iso(b.measured_on) ? 1 : -1));
    if (t.kind === 'flow') {
      const inRange = rows.filter(m => iso(m.measured_on) >= from && iso(m.measured_on) <= to);
      out.push({ type_id: t.id, code: t.code, label: t.label, kind: 'flow', total: inRange.reduce((s, m) => s + m.value, 0), days_recorded: inRange.length,
        ...(t.breakdown ? { breakdown: t.breakdown, by_category: sumBreakdowns(inRange) } : {}),
        by_day: inRange.map(m => ({ date: iso(m.measured_on), value: m.value, id: m.id, ...(m.breakdown ? { breakdown: m.breakdown } : {}) })) });
    } else {
      const [latest, prev] = rows;
      out.push({ type_id: t.id, code: t.code, label: t.label, kind: 'stock', ...(t.breakdown ? { breakdown: t.breakdown } : {}),
        latest: latest ? { date: iso(latest.measured_on), value: latest.value, oldest_pending_on: iso(latest.oldest_pending_on) || null, id: latest.id, ...(latest.breakdown ? { breakdown: latest.breakdown } : {}) } : null,
        previous: prev ? { date: iso(prev.measured_on), value: prev.value } : null,
        history: rows.slice(0, 12).map(m => ({ date: iso(m.measured_on), value: m.value })) });
    }
  }
  return out;
}

function validateIncident(body, { partial = false, categories = Object.keys(INCIDENT_CATEGORIES) } = {}) {
  const out = {};
  if (!partial || body.category !== undefined) { if (!categories.includes(body.category)) return { error: 'Choose a category.' }; out.category = body.category; }
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

/* ── OR-2b: Interconsultas (department-wide service; one record per request, no patient data) ── */
const IC_PRIORITY = Object.freeze({ urgent: 'Urgente', preferente: 'Preferente', ordinary: 'Ordinaria' });
// Response-time targets in hours. PROVISIONAL until the department confirms them (see OPS_ROOMS.md §3b).
const IC_TARGET_HOURS = Object.freeze({ urgent: 24, preferente: 72, ordinary: 168 });
const IC_STATUS = Object.freeze({ received: 'Recibida', assigned: 'Asignada', answered: 'Respondida', follow_up: 'En seguimiento', closed: 'Cerrada' });
const IC_SERVICES = Object.freeze(['Urgencias', 'Medicina Interna', 'Cardiología', 'Cirugía General', 'Cirugía Torácica', 'UCI / Reanimación', 'Oncología',
  'Hematología', 'Nefrología', 'Neurología', 'Digestivo', 'Traumatología', 'Ginecología y Obstetricia', 'Geriatría', 'Infecciosas', 'Reumatología',
  'Endocrinología', 'Urología', 'ORL', 'Psiquiatría', 'Pediatría', 'Otro servicio']);
const IC_REASONS = Object.freeze({ disnea: 'Disnea', insuf_resp: 'Insuficiencia respiratoria', derrame: 'Derrame pleural', nodulo: 'Nódulo / masa pulmonar',
  epoc_asma: 'EPOC / asma', infeccion: 'Infección respiratoria', preop: 'Valoración preoperatoria', vmni: 'Ventilación no invasiva',
  hemoptisis: 'Hemoptisis', tep: 'TEP / circulación pulmonar', intersticial: 'Enfermedad intersticial', sueno: 'Trastorno respiratorio del sueño', otro: 'Otro motivo' });
const isoTs = v => { if (!v) return null; const t = Date.parse(v); return isNaN(t) ? null : new Date(t).toISOString(); };
const hoursBetween = (a, b) => (Date.parse(b) - Date.parse(a)) / 3600000;
const median = xs => { const s = xs.filter(x => Number.isFinite(x)).sort((a, b) => a - b); if (!s.length) return null; const m = Math.floor(s.length / 2); return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
const round1 = x => x === null || x === undefined ? null : Math.round(x * 10) / 10;

function validateInterconsult(body, nowIso, { partial = false, services = null, reasons = Object.keys(IC_REASONS) } = {}) {
  const out = {};
  if (!partial || body.requesting_service !== undefined) {
    const s = str(body.requesting_service, 80); if (!s || s.length < 2) return { error: 'Choose the requesting service.' };
    if (services && !services.includes(s)) return { error: 'Choose a service from the list (it can be added in Configuración).' };
    out.requesting_service = s;
  }
  if (!partial || body.priority !== undefined) { const p = body.priority || 'ordinary'; if (!IC_PRIORITY[p]) return { error: 'Priority must be urgent, preferente or ordinary.' }; out.priority = p; }
  if (body.reason_category !== undefined) { if (body.reason_category && !reasons.includes(body.reason_category)) return { error: 'Unknown reason.' }; out.reason_category = body.reason_category || null; }
  if (!partial || body.received_at !== undefined) {
    const r = body.received_at ? isoTs(body.received_at) : nowIso;
    if (!r) return { error: 'Invalid reception time.' };
    if (Date.parse(r) > Date.parse(nowIso) + 5 * 60000) return { error: 'The reception time cannot be in the future.' };
    out.received_at = r;
  }
  if (body.unit_id !== undefined) out.unit_id = body.unit_id || null;
  if (body.notes !== undefined) out.notes = str(body.notes, 300);
  // OR-R: calls / in-person requests from other departments share this record.
  if (!partial || body.channel !== undefined) { const c = body.channel || 'formal'; if (!IC_CHANNEL[c]) return { error: 'Channel must be formal, phone or in person.' }; out.channel = c; }
  if (body.outcome !== undefined) { if (body.outcome && !IC_OUTCOME[body.outcome]) return { error: 'Unknown outcome.' }; out.outcome = body.outcome || null; }
  if (body.duration_min !== undefined) { if (body.duration_min === null || body.duration_min === '') out.duration_min = null; else { const d = Number(body.duration_min); if (!Number.isInteger(d) || d < 1 || d > 600) return { error: 'Duration must be 1–600 minutes.' }; out.duration_min = d; } }
  if (out.channel && out.channel !== 'formal' && !partial && !out.outcome) return { error: 'Say how the call ended (advice, patient seen, or formal interconsulta).' };
  return { value: out };
}
const IC_CHANNEL = Object.freeze({ formal: 'Interconsulta formal', phone: 'Llamada', in_person: 'En persona' });
const IC_OUTCOME = Object.freeze({ advice: 'Consejo / orientación', seen: 'Paciente valorado', converted: 'Pasó a interconsulta formal' });
// A call is logged once it is over: answered and closed at reception (+ duration), by the person logging it.
function callRecord(v, staffId, nowIso) {
  if (!v.channel || v.channel === 'formal') return v;
  const end = new Date(Date.parse(v.received_at) + (v.duration_min || 0) * 60000).toISOString();
  const at = Date.parse(end) > Date.parse(nowIso) ? nowIso : end;
  return { ...v, status: 'closed', assigned_to: staffId || null, assigned_at: v.received_at, answered_at: at, answered_by: staffId || null, closed_at: at };
}
function callStats(rows, fromIso, toIso) {
  const calls = (rows || []).filter(r => !r.deleted_at && r.channel && r.channel !== 'formal' && Date.parse(r.received_at) >= Date.parse(fromIso) && Date.parse(r.received_at) <= Date.parse(toIso));
  const count = key => Object.entries(calls.reduce((m, r) => { const k = r[key] || '—'; m[k] = (m[k] || 0) + 1; return m; }, {})).map(([k, n]) => ({ key: k, count: n })).sort((a, b) => b.count - a.count);
  return { total: calls.length, minutes: calls.reduce((a, r) => a + (r.duration_min || 0), 0), by_channel: count('channel'), by_outcome: count('outcome'), by_service: count('requesting_service').slice(0, 8), by_clinician: count('answered_by') };
}

// Lifecycle: received → assigned → answered → (follow_up) → closed. Reopen goes back one honest step.
function interconsultAction(row, action, { staffId = null, at = null, nowIso }) {
  const when = at ? isoTs(at) : nowIso;
  if (!when) return { error: 'Invalid time.' };
  if (Date.parse(when) > Date.parse(nowIso) + 5 * 60000) return { error: 'The time cannot be in the future.' };
  if (row.status === 'closed' && action !== 'reopen') return { error: 'This interconsult is closed — reopen it first.' };
  switch (action) {
    case 'assign':
      if (!staffId) return { error: 'Choose who takes it.' };
      if (!['received', 'assigned'].includes(row.status)) return { error: 'Only unanswered interconsults can be (re)assigned.' };
      return { patch: { status: 'assigned', assigned_to: staffId, assigned_at: Date.parse(when) < Date.parse(row.received_at) ? row.received_at : when } };
    case 'answer':
      if (!['received', 'assigned'].includes(row.status)) return { error: 'Already answered.' };
      if (Date.parse(when) < Date.parse(row.received_at)) return { error: 'The answer cannot be before the request was received.' };
      return { patch: { status: 'answered', answered_at: when, answered_by: staffId || row.assigned_to || null, assigned_to: row.assigned_to || staffId || null, assigned_at: row.assigned_at || when } };
    case 'follow_up':
      if (row.status !== 'answered') return { error: 'Only an answered interconsult can move to follow-up.' };
      return { patch: { status: 'follow_up' } };
    case 'close':
      if (!['answered', 'follow_up'].includes(row.status)) return { error: 'Answer it before closing.' };
      return { patch: { status: 'closed', closed_at: when } };
    case 'reopen':
      if (row.status !== 'closed') return { error: 'It is not closed.' };
      return { patch: { status: row.answered_at ? 'answered' : (row.assigned_to ? 'assigned' : 'received'), closed_at: null } };
    default: return { error: 'Unknown action.' };
  }
}

// Board + stats. `fromIso` bounds the "recent" window (received/answered inside it).
// `targets`: { priority: hours } or a function (priority, isoDate) → hours (the target in force that day).
const icTargetFn = targets => typeof targets === 'function' ? targets : (p => (targets || IC_TARGET_HOURS)[p]);
function interconsultStats(rows, nowIso, fromIso, targets = IC_TARGET_HOURS) {
  const tf = icTargetFn(targets), tRow = r => tf(r.priority, String(r.received_at).slice(0, 10));
  // Response-time metrics are about formal interconsultas only; calls are counted in callStats (OR-R).
  const live = (rows || []).filter(r => !r.deleted_at && (!r.channel || r.channel === 'formal'));
  const waiting = live.filter(r => ['received', 'assigned'].includes(r.status));
  const ageH = r => hoursBetween(r.received_at, nowIso);
  const overdue = waiting.filter(r => ageH(r) > (tRow(r) || Infinity));
  const answered = live.filter(r => r.answered_at && Date.parse(r.answered_at) >= Date.parse(fromIso) && Date.parse(r.answered_at) <= Date.parse(nowIso));
  const resp = r => hoursBetween(r.received_at, r.answered_at);
  const byPriority = {};
  for (const p of Object.keys(IC_PRIORITY)) {
    const a = answered.filter(r => r.priority === p);
    byPriority[p] = { answered: a.length, median_hours: round1(median(a.map(resp))), within_target_pct: a.length ? round1(100 * a.filter(r => resp(r) <= (tRow(r) || Infinity)).length / a.length) : null, target_hours: tf(p, nowIso.slice(0, 10)) };
  }
  const received = live.filter(r => Date.parse(r.received_at) >= Date.parse(fromIso));
  const count = (list, key) => Object.entries(list.reduce((m, r) => { const k = r[key] || '—'; m[k] = (m[k] || 0) + 1; return m; }, {})).map(([k, n]) => ({ key: k, count: n })).sort((a, b) => b.count - a.count);
  return {
    waiting: waiting.length, overdue: overdue.length, unassigned: waiting.filter(r => !r.assigned_to).length,
    follow_up: live.filter(r => r.status === 'follow_up').length,
    oldest_waiting_hours: waiting.length ? round1(Math.max(...waiting.map(ageH))) : null,
    received: received.length, answered: answered.length,
    median_hours: round1(median(answered.map(resp))),
    within_target_pct: answered.length ? round1(100 * answered.filter(r => resp(r) <= (tRow(r) || Infinity)).length / answered.length) : null,
    by_priority: byPriority, by_service: count(received, 'requesting_service').slice(0, 8), by_clinician: count(answered.filter(r => r.answered_by), 'answered_by'),
  };
}
function interconsultClock(row, nowIso, targets = IC_TARGET_HOURS) {
  const end = row.answered_at || nowIso, h = hoursBetween(row.received_at, end), t = icTargetFn(targets)(row.priority, String(row.received_at).slice(0, 10));
  return { hours: round1(h), target_hours: t, over: h > t, answered: !!row.answered_at };
}

/* ── OR-3: ¿Cumplimos? — indicators computed from Ops Room records ── */
const IND_KINDS = Object.freeze({
  measure_total: { label: 'Activity total in the period', scope: 'unit', needs: ['type_id'], unit_label: '' },
  stock_latest: { label: 'Pending work (latest snapshot in the period)', scope: 'unit', needs: ['type_id'], unit_label: '' },
  oldest_pending_days: { label: 'Oldest pending item (days)', scope: 'unit', needs: ['type_id'], unit_label: 'days' },
  calibration_ok_pct: { label: 'Devices with calibration up to date (%) — current only', scope: 'unit', needs: [], unit_label: '%' },
  incidents_open: { label: 'Open incidents at the end of the period', scope: 'unit', needs: [], unit_label: '' },
  incident_resolution_days: { label: 'Median days to resolve incidents', scope: 'unit', needs: [], unit_label: 'days' },
  interconsult_within_target_pct: { label: 'Interconsultas answered within target (%)', scope: 'any', needs: [], unit_label: '%' },
  interconsult_median_hours: { label: 'Median interconsulta response (hours)', scope: 'any', needs: [], unit_label: 'h' },
  interconsult_pending: { label: 'Interconsultas waiting at the end of the period', scope: 'any', needs: [], unit_label: '' },
  calls_total: { label: 'Calls / in-person requests from other departments in the period', scope: 'any', needs: [], unit_label: '' },
  manual: { label: 'Entered by hand each period', scope: 'any', needs: [], unit_label: '' },
});

function validateIndicator(body, { unitScoped, partial = false } = {}) {
  const out = {};
  if (!partial || body.name !== undefined) { const n = str(body.name, 120); if (!n || n.length < 3) return { error: 'Give the indicator a name.' }; out.name = n; }
  if (!partial || body.kind !== undefined) {
    const k = IND_KINDS[body.kind]; if (!k) return { error: 'Unknown indicator type.' };
    if (k.scope === 'unit' && !unitScoped) return { error: 'This indicator type belongs to a unit.' };
    out.kind = body.kind;
  }
  if (body.params !== undefined || !partial) {
    const p = body.params && typeof body.params === 'object' ? body.params : {};
    const clean = {};
    if (p.type_id) clean.type_id = String(p.type_id);
    if (p.priority) { if (!IC_PRIORITY[p.priority]) return { error: 'Unknown priority.' }; clean.priority = p.priority; }
    if (p.outcome) { if (!IC_OUTCOME[p.outcome]) return { error: 'Unknown call outcome.' }; clean.outcome = p.outcome; }
    const kind = out.kind || body.kind;
    if (kind && (IND_KINDS[kind]?.needs || []).includes('type_id') && !clean.type_id) return { error: 'Choose the measure this indicator uses.' };
    out.params = clean;
  }
  if (!partial || body.period !== undefined) { const p = body.period || 'month'; if (!['week', 'month', 'quarter'].includes(p)) return { error: 'Period must be week, month or quarter.' }; out.period = p; }
  if (!partial || body.direction !== undefined) { if (!['min', 'max'].includes(body.direction)) return { error: 'Say whether the target is a minimum or a maximum.' }; out.direction = body.direction; }
  if (body.target !== undefined) { if (body.target === null || body.target === '') out.target = null; else { const t = Number(body.target); if (!Number.isFinite(t) || t < 0) return { error: 'The target must be a number from 0.' }; out.target = t; } }
  for (const [k, max] of [['iso_clause', 40], ['notes', 300], ['unit_label', 20]]) if (body[k] !== undefined) out[k] = str(body[k], max);
  if (body.owner_id !== undefined) out.owner_id = body.owner_id || null;
  if (body.active !== undefined) out.active = body.active === true;
  return { value: out };
}

// Last n periods ending with the current (partial) one. Weeks start on Monday.
function periodBounds(period, today, n = 6) {
  const d = new Date(iso(today) + 'T12:00:00Z'), out = [];
  const fmt = x => x.toISOString().slice(0, 10);
  let start;
  if (period === 'week') { start = new Date(d); start.setUTCDate(d.getUTCDate() - ((d.getUTCDay() + 6) % 7)); }
  else if (period === 'quarter') start = new Date(Date.UTC(d.getUTCFullYear(), Math.floor(d.getUTCMonth() / 3) * 3, 1, 12));
  else start = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1, 12));
  for (let i = 0; i < n; i++) {
    const s = new Date(start), e = new Date(start);
    if (period === 'week') { s.setUTCDate(start.getUTCDate() - 7 * i); e.setTime(s.getTime()); e.setUTCDate(s.getUTCDate() + 6); }
    else { const m = period === 'quarter' ? 3 : 1; s.setUTCMonth(start.getUTCMonth() - m * i); e.setTime(s.getTime()); e.setUTCMonth(s.getUTCMonth() + m); e.setUTCDate(0); }
    const end = fmt(e) > iso(today) ? iso(today) : fmt(e);
    out.unshift({ start: fmt(s), end, partial: fmt(e) > iso(today) });
  }
  return out;
}

function indicatorValue(def, p, data, today) {
  const inP = d => d && iso(d) >= p.start && iso(d) <= p.end;
  const tid = def.params?.type_id;
  switch (def.kind) {
    case 'measure_total': { const rows = (data.measurements || []).filter(m => String(m.type_id) === String(tid) && inP(m.measured_on)); return rows.length ? rows.reduce((s, m) => s + m.value, 0) : null; }
    case 'stock_latest': case 'oldest_pending_days': {
      const rows = (data.measurements || []).filter(m => String(m.type_id) === String(tid) && inP(m.measured_on)).sort((a, b) => (iso(a.measured_on) < iso(b.measured_on) ? 1 : -1));
      if (!rows.length) return null;
      if (def.kind === 'stock_latest') return rows[0].value;
      return rows[0].oldest_pending_on ? daysBetween(rows[0].oldest_pending_on, rows[0].measured_on) : (rows[0].value === 0 ? 0 : null);
    }
    case 'calibration_ok_pct': {
      if (p.end !== iso(today)) return null;                         // no reconstruction of past calibration states
      const devs = (data.resources || []).filter(r => !r.deleted_at && r.kind === 'device' && (r.calibration_interval_days || r.next_calibration_due));
      return devs.length ? round1(100 * devs.filter(r => r.next_calibration_due && iso(r.next_calibration_due) >= iso(today)).length / devs.length) : null;
    }
    case 'incidents_open': return (data.incidents || []).filter(i => !i.deleted_at && iso(i.opened_on) <= p.end && (!i.resolved_on || iso(i.resolved_on) > p.end)).length;
    case 'incident_resolution_days': return median((data.incidents || []).filter(i => !i.deleted_at && i.resolved_on && inP(i.resolved_on)).map(i => daysBetween(i.opened_on, i.resolved_on)));
    case 'interconsult_within_target_pct': case 'interconsult_median_hours': {
      const pr = def.params?.priority, rows = (data.interconsults || []).filter(r => !r.deleted_at && (!r.channel || r.channel === 'formal') && r.answered_at && inP(r.answered_at.slice(0, 10)) && (!pr || r.priority === pr) && (!def.unit_id || String(r.unit_id) === String(def.unit_id)));
      if (!rows.length) return null;
      const h = r => hoursBetween(r.received_at, r.answered_at);
      const tf = icTargetFn(data.icTargets || IC_TARGET_HOURS);
      return def.kind === 'interconsult_median_hours' ? round1(median(rows.map(h))) : round1(100 * rows.filter(r => h(r) <= (tf(r.priority, String(r.received_at).slice(0, 10)) || Infinity)).length / rows.length);
    }
    case 'interconsult_pending': {
      const endTs = Date.parse(p.end + 'T23:59:59Z'), pr = def.params?.priority;
      return (data.interconsults || []).filter(r => !r.deleted_at && (!r.channel || r.channel === 'formal') && (!pr || r.priority === pr) && (!def.unit_id || String(r.unit_id) === String(def.unit_id))
        && Date.parse(r.received_at) <= endTs && (!r.answered_at || Date.parse(r.answered_at) > endTs)).length;
    }
    case 'calls_total': return (data.interconsults || []).filter(r => !r.deleted_at && r.channel && r.channel !== 'formal' && inP(String(r.received_at).slice(0, 10)) && (!def.params?.outcome || r.outcome === def.params.outcome)).length;
    case 'manual': { const v = (data.manualValues || []).find(x => String(x.indicator_id) === String(def.id) && iso(x.period_start) === p.start); return v ? Number(v.value) : null; }
    default: return null;
  }
}

// Target in force on a date: the history entry with the latest valid_from on or before it (null if none).
function targetAt(history, date) {
  let best = null;
  for (const h of history || []) if (iso(h.valid_from) <= iso(date) && (!best || iso(h.valid_from) > iso(best.valid_from))) best = h;
  return best;
}
// Series for the last n periods + status. With `def.targets` (history), each period is judged with the target in
// force on its last day; without it, the single `def.target` applies to every period (pre-OR-C behaviour).
function computeIndicator(def, data, today, n = 6) {
  const periods = periodBounds(def.period || 'month', today, n);
  const tgt = p => { if (Array.isArray(def.targets)) { const h = targetAt(def.targets, p.end); return h && h.value !== null && h.value !== undefined ? { value: Number(h.value), direction: h.direction || def.direction } : null; }
    return def.target === null || def.target === undefined ? null : { value: Number(def.target), direction: def.direction }; };
  const series = periods.map(p => { const v = indicatorValue(def, p, data, today), t = tgt(p); return { ...p, value: v === undefined ? null : v, target: t ? t.value : null,
    met: v === null || v === undefined || !t ? null : (t.direction === 'min' ? v >= t.value : v <= t.value) }; });
  const current = series[series.length - 1], last = [...series].reverse().find(s => s.value !== null) || null, now = tgt({ end: iso(today) });
  return { series, current, last_value: last, target_now: now, status: !now && !(last && last.target !== null) ? 'no_target' : (last ? (last.met === null ? 'no_target' : (last.met ? 'met' : 'not_met')) : 'no_data') };
}

/* ── OR-C: catalogues as data ── */
const CATALOGS = Object.freeze({ ic_service: 'Interconsulta services', ic_reason: 'Interconsulta reasons', ic_priority: 'Interconsulta priorities',
  incident_category: 'Incident categories', roster_role: 'Roles in a unit', device_type: 'Device types',
  clinical_condition: 'Clinical conditions (breakdowns)', age_band: 'Age bands (breakdowns)', sex: 'Sex (breakdowns)' });
const BREAKDOWNS = Object.freeze(['clinical_condition', 'age_band', 'sex']);
const FIXED_CODES = Object.freeze({ ic_priority: ['urgent', 'preferente', 'ordinary'] });   // logic depends on these: no additions
const slugCode = s => String(s || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '').slice(0, 40);
// Built-in lists, used until the OR-C migration has run (and as the seed it mirrors).
function catalogFallback() {
  const mk = (catalog, obj, locked = []) => Object.entries(obj).map(([code, label], i) => ({ catalog, code, label, sort: i + 1, active: true, locked: locked.includes(code), meta: {} }));
  return { ic_service: IC_SERVICES.map((label, i) => ({ catalog: 'ic_service', code: slugCode(label), label, sort: i + 1, active: true, locked: label === 'Otro servicio', meta: {} })),
    ic_reason: mk('ic_reason', IC_REASONS, ['otro']), ic_priority: mk('ic_priority', IC_PRIORITY, FIXED_CODES.ic_priority),
    incident_category: mk('incident_category', INCIDENT_CATEGORIES, ['other']), roster_role: mk('roster_role', ROLES, ['coordinator']), device_type: [],
    clinical_condition: [], age_band: [], sex: [] };
}
// rows (from ops_catalog_items) → { catalog: [items sorted] } with fallback for catalogues not in the database yet.
function catalogFrom(rows) {
  const out = catalogFallback(), seen = new Set();
  for (const r of rows || []) { if (!CATALOGS[r.catalog]) continue; if (!seen.has(r.catalog)) { out[r.catalog] = []; seen.add(r.catalog); } out[r.catalog].push(r); }
  for (const k of Object.keys(out)) out[k].sort((a, b) => a.sort - b.sort || String(a.label).localeCompare(String(b.label), 'es'));
  return out;
}
const activeCodes = (cat, name) => (cat[name] || []).filter(i => i.active).map(i => i.code);
const labelsOf = (cat, name) => Object.fromEntries((cat[name] || []).map(i => [i.code, i.label]));

function validateCatalogItem(catalog, body, { existing = null } = {}) {
  if (!CATALOGS[catalog]) return { error: 'Unknown list.' };
  const out = {};
  if (!existing) {
    if (FIXED_CODES[catalog]) return { error: 'This list is fixed: rename its items or change their targets instead.' };
    const label = str(body.label, 80); if (!label) return { error: 'A name is required.' };
    const code = slugCode(body.code || label); if (code.length < 2) return { error: 'The name needs at least two letters or digits.' };
    Object.assign(out, { code, label, sort: Number.isFinite(Number(body.sort)) ? Number(body.sort) : 100 });
  } else {
    if (body.label !== undefined) { const l = str(body.label, 80); if (!l) return { error: 'A name is required.' }; out.label = l; }
    if (body.sort !== undefined) { const n = Number(body.sort); if (!Number.isFinite(n)) return { error: 'Order must be a number.' }; out.sort = n; }
    if (body.active !== undefined) { if (existing.locked && body.active === false) return { error: 'This item is used by the system and cannot be switched off.' }; out.active = body.active === true; }
  }
  if (body.meta !== undefined) {
    const m = body.meta && typeof body.meta === 'object' ? body.meta : {}, meta = {};
    if (catalog === 'device_type' && m.calibration_days !== undefined && m.calibration_days !== null && m.calibration_days !== '') {
      const d = Number(m.calibration_days); if (!Number.isInteger(d) || d < 1 || d > 3650) return { error: 'Calibration interval must be 1–3650 days.' }; meta.calibration_days = d;
    }
    out.meta = meta;
  }
  return { value: out };
}

// A new target entry (indicator or interconsulta priority). valid_from defaults to today.
function validateTargetEntry(body, today) {
  const from = body.valid_from ? iso(body.valid_from) : iso(today);
  if (!isIso(from)) return { error: 'Invalid “valid from” date.' };
  if (from > addDays(today, 366)) return { error: '“Valid from” can be at most a year ahead.' };
  let value = null;
  if (body.value !== null && body.value !== undefined && body.value !== '') { value = Number(body.value); if (!Number.isFinite(value) || value < 0) return { error: 'The target must be a number from 0.' }; }
  if (body.direction !== undefined && body.direction !== null && !['min', 'max'].includes(body.direction)) return { error: 'Direction must be min or max.' };
  return { value: { value, direction: body.direction || null, valid_from: from, note: str(body.note, 300) } };
}

/* ── OR-R: weekly / monthly reports (fixed snapshots; counts only) ── */
// Last complete week (Mon–Sun) and month before `today`, and the period before each (for comparison).
function reportPeriod(period, today, start = null) {
  const fmt = x => x.toISOString().slice(0, 10), d = new Date(iso(today) + 'T12:00:00Z');
  let s;
  if (start) s = new Date(iso(start) + 'T12:00:00Z');
  else if (period === 'week') { s = new Date(d); s.setUTCDate(d.getUTCDate() - ((d.getUTCDay() + 6) % 7) - 7); }
  else s = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() - 1, 1, 12));
  const e = new Date(s), ps = new Date(s), pe = new Date(s);
  if (period === 'week') { e.setUTCDate(s.getUTCDate() + 6); ps.setUTCDate(s.getUTCDate() - 7); pe.setUTCDate(s.getUTCDate() - 1); }
  else { e.setUTCMonth(s.getUTCMonth() + 1); e.setUTCDate(0); ps.setUTCMonth(s.getUTCMonth() - 1); pe.setUTCDate(0); }
  return { period, start: fmt(s), end: fmt(e), previous: { start: fmt(ps), end: fmt(pe) }, complete: fmt(e) < iso(today) };
}
const pct = (a, b) => (b ? Math.round(((a - b) / b) * 1000) / 10 : null);
const labelled = (obj, labels) => Object.entries(obj || {}).map(([code, count]) => ({ code, label: (labels || {})[code] || code, count })).sort((a, b) => b.count - a.count);

// data: { unit, types, measurements, incidents, resources, roster:{count, coordinators}, indicators:[{def, data}], labels:{incident_category, clinical_condition, age_band, sex}, today }
function buildUnitReport(rp, data) {
  const inR = (d, r) => d && iso(d) >= r.start && iso(d) <= r.end;
  const meas = data.measurements || [];
  const activity = (data.types || []).filter(t => t.active !== false && t.kind === 'flow').map(t => {
    const cur = meas.filter(m => String(m.type_id) === String(t.id) && inR(m.measured_on, rp)), prev = meas.filter(m => String(m.type_id) === String(t.id) && inR(m.measured_on, rp.previous));
    const total = cur.reduce((a, m) => a + m.value, 0), ptotal = prev.reduce((a, m) => a + m.value, 0);
    return { label: t.label, total, previous: ptotal, change_pct: pct(total, ptotal), days_recorded: cur.length, recorded: cur.length > 0,
      breakdown: t.breakdown ? labelled(sumBreakdowns(cur), data.labels?.[t.breakdown]) : null, breakdown_kind: t.breakdown || null };
  });
  const pending = (data.types || []).filter(t => t.active !== false && t.kind === 'stock').map(t => {
    const latestIn = r => meas.filter(m => String(m.type_id) === String(t.id) && inR(m.measured_on, r)).sort((a, b) => (iso(a.measured_on) < iso(b.measured_on) ? 1 : -1))[0] || null;
    const l = latestIn(rp), p = latestIn(rp.previous);
    return { label: t.label, latest: l ? { date: iso(l.measured_on), value: l.value, oldest_days: l.oldest_pending_on ? daysBetween(l.oldest_pending_on, l.measured_on) : null,
      breakdown: t.breakdown ? labelled(l.breakdown, data.labels?.[t.breakdown]) : null } : null, previous_value: p ? p.value : null };
  });
  const inc = (data.incidents || []).filter(i => !i.deleted_at);
  const opened = inc.filter(i => inR(i.opened_on, rp)), resolved = inc.filter(i => i.resolved_on && inR(i.resolved_on, rp));
  const openAtEnd = inc.filter(i => iso(i.opened_on) <= rp.end && (!i.resolved_on || iso(i.resolved_on) > rp.end));
  const byCat = labelled(opened.reduce((m, i) => { m[i.category] = (m[i.category] || 0) + 1; return m; }, {}), data.labels?.incident_category);
  const indicators = (data.indicators || []).map(({ def, data: d }) => {
    const v = indicatorValue(def, rp, d, data.today), t = Array.isArray(def.targets) ? targetAt(def.targets, rp.end) : (def.target !== null && def.target !== undefined ? { value: def.target, direction: def.direction } : null);
    const tv = t && t.value !== null && t.value !== undefined ? Number(t.value) : null, dir = (t && t.direction) || def.direction;
    return { name: def.name, kind: def.kind, value: v === undefined ? null : v, target: tv, direction: dir, met: v === null || v === undefined || tv === null ? null : (dir === 'min' ? v >= tv : v <= tv), iso_clause: def.iso_clause || null };
  });
  return { kind: 'unit', unit: { id: data.unit.id, name: data.unit.unit_name, code: data.unit.unit_code }, period: rp.period, start: rp.start, end: rp.end, previous: rp.previous,
    team: data.roster || null, activity, pending,
    incidents: { opened: opened.length, resolved: resolved.length, open_at_end: openAtEnd.length, by_category: byCat },
    resources_now: data.resources ? resourceAlerts(data.resources, data.today) : null,
    indicators, summary: { indicators_met: indicators.filter(i => i.met === true).length, indicators_not_met: indicators.filter(i => i.met === false).length,
      activity_recorded: activity.filter(a => a.recorded).length, activity_measures: activity.length } };
}

// data: { unitReports:[content], interconsults, icTargets, labels:{ic_service}, indicators:[{def,data}], today }
function buildDepartmentReport(rp, data) {
  const fromIso = rp.start + 'T00:00:00.000Z', toIso = rp.end + 'T23:59:59.999Z', pFrom = rp.previous.start + 'T00:00:00.000Z', pTo = rp.previous.end + 'T23:59:59.999Z';
  const ic = data.interconsults || [];
  const inWin = (r, a, b) => Date.parse(r.received_at) >= Date.parse(a) && Date.parse(r.received_at) <= Date.parse(b);
  const statsFor = (a, b) => interconsultStats(ic.filter(r => inWin(r, a, b) || (r.answered_at && Date.parse(r.answered_at) >= Date.parse(a) && Date.parse(r.answered_at) <= Date.parse(b))), b, a, data.icTargets || IC_TARGET_HOURS);
  const cur = statsFor(fromIso, toIso), prev = statsFor(pFrom, pTo);
  const calls = callStats(ic, fromIso, toIso), pcalls = callStats(ic, pFrom, pTo);
  const svc = data.labels?.ic_service || {};
  const ind = buildUnitReport(rp, { unit: { id: null, unit_name: 'Departamento', unit_code: '' }, types: [], measurements: [], incidents: [], indicators: data.indicators || [], today: data.today, labels: {} }).indicators;
  return { kind: 'department', period: rp.period, start: rp.start, end: rp.end, previous: rp.previous,
    units: (data.unitReports || []).map(u => ({ id: u.unit.id, name: u.unit.name, code: u.unit.code, incidents_open: u.incidents.open_at_end, incidents_opened: u.incidents.opened,
      indicators_met: u.summary.indicators_met, indicators_not_met: u.summary.indicators_not_met, activity_recorded: u.summary.activity_recorded, activity_measures: u.summary.activity_measures,
      headline: u.activity.filter(a => a.recorded).slice(0, 3).map(a => ({ label: a.label, total: a.total, change_pct: a.change_pct })) })),
    interconsults: { received: cur.received, answered: cur.answered, median_hours: cur.median_hours, within_target_pct: cur.within_target_pct, by_priority: cur.by_priority,
      received_previous: prev.received, by_service: cur.by_service.map(s => ({ ...s, label: svc[s.key] || s.key })) },
    calls: { ...calls, previous_total: pcalls.total, by_service: calls.by_service.map(s => ({ ...s, label: svc[s.key] || s.key })) },
    indicators: ind };
}

Object.assign(module.exports, { IC_CHANNEL, IC_OUTCOME, callRecord, callStats, BREAKDOWNS, sumBreakdowns, reportPeriod, buildUnitReport, buildDepartmentReport, targetAt, CATALOGS, FIXED_CODES, slugCode, catalogFallback, catalogFrom, activeCodes, labelsOf, validateCatalogItem, validateTargetEntry, icTargetFn,
  IC_PRIORITY, IC_TARGET_HOURS, IC_STATUS, IC_SERVICES, IC_REASONS, validateInterconsult, interconsultAction, interconsultStats, interconsultClock,
  IND_KINDS, validateIndicator, periodBounds, indicatorValue, computeIndicator, median, hoursBetween });
