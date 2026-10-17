'use strict';
/* Communication CM-1 — pure rules (no database). Posts (what comes in and what the team needs to know),
   follow-ups, agenda (sessions, seminars, meetings) and the daily brief (Parte del día).
   NO PATIENT DATA: free text is capped and the screens say so; absence reasons are never shown in a brief. */

const iso = d => (d ? String(d).slice(0, 10) : null);
const isIso = d => /^\d{4}-\d{2}-\d{2}$/.test(String(d || '')) && !Number.isNaN(Date.parse(d + 'T12:00:00Z'));
const isoTs = v => { if (!v) return null; const t = Date.parse(v); return Number.isNaN(t) ? null : new Date(t).toISOString(); };
const str = (v, max) => { if (v === undefined || v === null) return null; const s = String(v).trim(); return s ? s.slice(0, max) : null; };
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const isUuid = v => UUID.test(String(v || ''));
const httpsUrl = v => { const s = str(v, 300); return s && /^https:\/\/[^\s]+$/i.test(s) ? s : null; };

// Post types people write. 'parte' (daily brief) and 'meeting' (agenda) posts are created by the system.
const POST_TYPES = Object.freeze({
  announcement: { label: 'Aviso', priority: 'normal' },
  entrada: { label: 'Entrada', priority: 'normal' },          // came in from another service / person, briefed to the team
  broadcast: { label: 'Urgente', priority: 'urgent' },
  protocol: { label: 'Protocolo', priority: 'high' },
  kudos: { label: 'Reconocimiento', priority: 'low' },
});
const SYSTEM_TYPES = Object.freeze({ parte: { label: 'Parte del día', priority: 'normal' }, meeting: { label: 'Agenda', priority: 'normal' } });
const PRIORITIES = ['urgent', 'high', 'normal', 'low'];
const COMMS_FALLBACK = Object.freeze({
  comm_category: [['information', 'Información', true], ['admission_request', 'Petición de ingreso / cama'], ['interconsulta', 'Interconsulta', true],
    ['instruction', 'Indicación de Dirección / Jefatura'], ['organisation', 'Organización del servicio'], ['protocol', 'Protocolo'],
    ['training', 'Formación / sesión'], ['recognition', 'Reconocimiento'], ['other', 'Otra', true]],
  meeting_kind: [['sesion_clinica', 'Sesión clínica'], ['seminario', 'Seminario'], ['reunion_servicio', 'Reunión de servicio'], ['comite', 'Comité'], ['formacion', 'Formación'], ['otra', 'Otra', true]],
});

/* ── Audience: who a post or meeting concerns (everyone can still read it — communication is general) ── */
function validateAudience(a) {
  if (a === undefined) return { value: undefined };
  if (a === null || a === 'all' || (a && a.all === true)) return { value: null };
  if (typeof a !== 'object') return { error: 'Invalid audience.' };
  const out = {};
  for (const [k, max] of [['units', 50], ['staff', 200]]) {
    if (a[k] === undefined) continue;
    if (!Array.isArray(a[k]) || a[k].length > max || !a[k].every(isUuid)) return { error: 'Invalid audience: ' + k + '.' };
    if (a[k].length) out[k] = [...new Set(a[k].map(String))];
  }
  if (a.roles !== undefined) {
    if (!Array.isArray(a.roles) || a.roles.length > 20 || !a.roles.every(r => /^[a-z0-9_]{2,40}$/.test(String(r)))) return { error: 'Invalid audience: roles.' };
    if (a.roles.length) out.roles = [...new Set(a.roles)];
  }
  if (a.oncall_today === true) out.oncall_today = true;
  return { value: Object.keys(out).length ? out : null };
}
// me = { staff_id, unit_ids:[], roles:[] }, oncallIds = staff on call on the post's date
function audienceIncludes(aud, me, oncallIds = []) {
  if (!aud) return true;
  const id = me && me.staff_id ? String(me.staff_id) : null;
  if (id && (aud.staff || []).includes(id)) return true;
  if ((aud.units || []).some(u => (me?.unit_ids || []).map(String).includes(String(u)))) return true;
  if ((aud.roles || []).some(r => (me?.roles || []).includes(r))) return true;
  if (aud.oncall_today && id && oncallIds.map(String).includes(id)) return true;
  return false;
}

/* ── Posts ── */
function validatePost(body, { today, categories = null, partial = false } = {}) {
  const out = {};
  if (!partial || body.type !== undefined) {
    const t = body.type || 'announcement';
    if (!POST_TYPES[t]) return { error: 'Choose aviso, entrada, urgente, protocolo or reconocimiento.' };
    out.type = t;
  }
  if (!partial || body.content !== undefined) {
    const c = str(body.content, 4000); if (!c || c.length < 2) return { error: 'Write the message.' };
    out.content = c;
    out.title = str(body.title, 100) || c.split('\n')[0].slice(0, 100);
  } else if (body.title !== undefined) out.title = str(body.title, 100);
  if (body.priority_level !== undefined || !partial) {
    const p = body.priority_level || (out.type ? POST_TYPES[out.type].priority : 'normal');
    if (!PRIORITIES.includes(p)) return { error: 'Unknown priority.' };
    out.priority_level = p;
  }
  if (body.source_service !== undefined) { const s = str(body.source_service, 80); if (s && s.length < 2) return { error: 'Source too short.' }; out.source_service = s; }
  if (body.source_detail !== undefined) out.source_detail = str(body.source_detail, 120);
  if (out.type === 'entrada' && !partial && !out.source_service) return { error: 'Say where it came from (service or person).' };
  if (body.category !== undefined) {
    if (body.category && categories && !categories.includes(body.category)) return { error: 'Choose a category from the list.' };
    out.category = body.category || null;
  }
  if (body.audience !== undefined) { const a = validateAudience(body.audience); if (a.error) return a; out.audience = a.value; }
  if (body.publish_end_date !== undefined) {
    if (body.publish_end_date === null || body.publish_end_date === '') out.publish_end_date = null;
    else { const e = iso(body.publish_end_date); if (!isIso(e)) return { error: 'Invalid end date.' }; if (today && e < today) return { error: 'The end date cannot be in the past.' }; out.publish_end_date = e; }
  }
  return { value: out };
}

/* ── Follow-ups ── */
function validateAction(body, { partial = false } = {}) {
  const out = {};
  if (!partial || body.text !== undefined) { const t = str(body.text, 300); if (!t || t.length < 2) return { error: 'Say what needs to be done.' }; out.text = t; }
  if (body.owner_id !== undefined) { if (body.owner_id && !isUuid(body.owner_id)) return { error: 'Invalid owner.' }; out.owner_id = body.owner_id || null; }
  if (body.due_on !== undefined) { if (body.due_on === null || body.due_on === '') out.due_on = null; else { const d = iso(body.due_on); if (!isIso(d)) return { error: 'Invalid due date.' }; out.due_on = d; } }
  return { value: out };
}
function actionTransition(row, to, { userId, nowIso }) {
  if (!['open', 'done', 'cancelled'].includes(to)) return { error: 'Unknown status.' };
  if (row.status === to) return { error: 'It is already ' + to + '.' };
  if (to === 'done') return { patch: { status: 'done', done_at: nowIso, done_by: userId || null } };
  if (to === 'cancelled') return { patch: { status: 'cancelled', done_at: nowIso, done_by: userId || null } };
  return { patch: { status: 'open', done_at: null, done_by: null } };
}
function actionState(a, today) {
  if (a.status !== 'open') return a.status;
  if (a.due_on && iso(a.due_on) < today) return 'overdue';
  if (a.due_on && iso(a.due_on) === today) return 'due_today';
  return 'open';
}

/* ── Agenda ── */
function validateMeeting(body, { kinds = null, partial = false } = {}) {
  const out = {};
  if (!partial || body.title !== undefined) { const t = str(body.title, 160); if (!t || t.length < 2) return { error: 'A title is required.' }; out.title = t; }
  if (!partial || body.kind !== undefined) { const k = body.kind || 'otra'; if (kinds && !kinds.includes(k)) return { error: 'Choose a kind from the list.' }; out.kind = k; }
  if (!partial || body.starts_at !== undefined) { const s = isoTs(body.starts_at); if (!s) return { error: 'Choose when it starts.' }; out.starts_at = s; }
  if (body.ends_at !== undefined) { if (!body.ends_at) out.ends_at = null; else { const e = isoTs(body.ends_at); if (!e) return { error: 'Invalid end time.' }; out.ends_at = e; } }
  if (out.ends_at && out.starts_at && Date.parse(out.ends_at) < Date.parse(out.starts_at)) return { error: 'It cannot end before it starts.' };
  if (body.location !== undefined) out.location = str(body.location, 120);
  if (body.online_url !== undefined) { if (body.online_url && !httpsUrl(body.online_url)) return { error: 'The online link must start with https://' }; out.online_url = body.online_url ? httpsUrl(body.online_url) : null; }
  if (body.organizer_id !== undefined) { if (body.organizer_id && !isUuid(body.organizer_id)) return { error: 'Invalid organiser.' }; out.organizer_id = body.organizer_id || null; }
  if (body.audience !== undefined) { const a = validateAudience(body.audience); if (a.error) return a; out.audience = a.value; }
  if (body.status !== undefined) { if (!['planned', 'held', 'cancelled'].includes(body.status)) return { error: 'Unknown status.' }; out.status = body.status; }
  if (body.minutes !== undefined) out.minutes = str(body.minutes, 8000);
  if (body.visibility !== undefined) { if (!['internal', 'public'].includes(body.visibility)) return { error: 'Visibility is internal or public.' }; out.visibility = body.visibility; }
  if (body.description !== undefined) out.description = str(body.description, 2000);
  if (body.banner_alt !== undefined) out.banner_alt = str(body.banner_alt, 160);
  if (body.materials !== undefined) {
    if (body.materials === null) out.materials = null;
    else {
      if (!Array.isArray(body.materials) || body.materials.length > 10) return { error: 'Up to 10 materials.' };
      const m = [];
      for (const x of body.materials) { const url = httpsUrl(x && x.url); if (!url) return { error: 'Material links must start with https://' }; m.push({ label: str(x.label, 80) || url, url }); }
      out.materials = m.length ? m : null;
    }
  }
  let items;
  if (body.items !== undefined) {
    if (!Array.isArray(body.items) || body.items.length > 30) return { error: 'Up to 30 agenda items.' };
    items = [];
    for (const [i, x] of body.items.entries()) {
      const topic = str(x && x.topic, 200); if (!topic || topic.length < 2) return { error: `Agenda item ${i + 1}: a topic is required.` };
      if (x.presenter_id && !isUuid(x.presenter_id)) return { error: `Agenda item ${i + 1}: invalid presenter.` };
      const d = x.duration_min === undefined || x.duration_min === null || x.duration_min === '' ? null : Number(x.duration_min);
      if (d !== null && (!Number.isInteger(d) || d < 1 || d > 480)) return { error: `Agenda item ${i + 1}: minutes must be 1–480.` };
      items.push({ sort: i, topic, presenter_id: x.presenter_id || null, presenter_name: x.presenter_id ? null : str(x.presenter_name, 120), duration_min: d, notes: str(x.notes, 1000) });
    }
  }
  return { value: out, items };
}
function meetingSchedule(starts_at, items) {   // start time of each agenda item from the durations
  let t = Date.parse(starts_at);
  return (items || []).map(it => { const at = new Date(t).toISOString(); if (it.duration_min) t += it.duration_min * 60000; return { ...it, at }; });
}

/* ── Parte del día ── */
const BRIEF_SECTIONS = Object.freeze([
  ['notes', 'Mensaje del día'], ['entradas', 'Entradas'], ['oncall', 'Guardia'], ['absences', 'Ausencias'],
  ['units', 'Unidades'], ['interconsults', 'Interconsultas'], ['meetings', 'Agenda de hoy'], ['actions', 'Pendientes'], ['residents', 'Residentes por unidad'],
]);
const BRIEF_DEFAULT = Object.freeze(['notes', 'entradas', 'oncall', 'absences', 'units', 'interconsults', 'meetings', 'actions']);
function validateBriefEdit(body) {
  const out = {};
  if (body.notes !== undefined) out.notes = str(body.notes, 4000);
  if (body.sections !== undefined) {
    if (!Array.isArray(body.sections) || !body.sections.every(s => BRIEF_SECTIONS.some(([k]) => k === s))) return { error: 'Unknown section.' };
    out.sections = BRIEF_SECTIONS.map(([k]) => k).filter(k => body.sections.includes(k));
  }
  return { value: out };
}
/* data: { date, notes, sections, entradas:[post], oncall:[{name, role, shift}], absences:[{name, until, covered_by}],
     units:[{name, level, reasons:[{level,text}]}], interconsults:{waiting, overdue, unassigned, oldest_waiting_hours},
     calls_today, meetings:[{title, kind_label, starts_at, location}], actions:[{text, owner, due_on, state}], residents:[{unit, names:[]}] } */
function buildDailyBrief(data) {
  const on = new Set(data.sections && data.sections.length ? data.sections : BRIEF_DEFAULT);
  const s = {};
  if (on.has('notes') && data.notes) s.notes = data.notes;
  if (on.has('entradas')) s.entradas = (data.entradas || []).map(p => ({ title: p.title || String(p.content || '').slice(0, 100), source: [p.source_label || p.source_service, p.source_detail].filter(Boolean).join(' · '), category: p.category_label || p.category || null, priority: p.priority_level }));
  if (on.has('oncall')) s.oncall = (data.oncall || []).map(o => ({ name: o.name, role: o.role, shift: o.shift || null }));
  if (on.has('absences')) s.absences = (data.absences || []).map(a => ({ name: a.name, until: a.until || null, covered_by: a.covered_by || null }));   // never the reason
  if (on.has('units')) s.units = (data.units || []).filter(u => u.level !== 'ok').map(u => ({ name: u.name, level: u.level, reasons: (u.reasons || []).slice(0, 3).map(r => r.text) }));
  if (on.has('units')) s.units_ok = (data.units || []).filter(u => u.level === 'ok').length;
  if (on.has('interconsults') && data.interconsults) s.interconsults = { ...data.interconsults, calls_today: data.calls_today || 0 };
  if (on.has('meetings')) s.meetings = (data.meetings || []).map(m => ({ title: m.title, kind: m.kind_label || null, at: m.starts_at, location: m.location || null }));
  if (on.has('actions')) s.actions = (data.actions || []).filter(a => a.state === 'overdue' || a.state === 'due_today' || a.state === 'open').map(a => ({ text: a.text, owner: a.owner || null, due_on: a.due_on || null, state: a.state }));
  if (on.has('residents')) s.residents = (data.residents || []).filter(r => r.names && r.names.length);
  return { date: data.date, sections: [...on], content: s };
}

/* ── Sharing (WhatsApp / copy): plain text + a link back into neumDesk (login required; no public pages) ── */
const DOW = ['dom', 'lun', 'mar', 'mié', 'jue', 'vie', 'sáb'], MON = ['ene', 'feb', 'mar', 'abr', 'may', 'jun', 'jul', 'ago', 'sep', 'oct', 'nov', 'dic'];
const fmtDay = d => { const x = new Date(iso(d) + 'T12:00:00Z'); return `${DOW[x.getUTCDay()]} ${x.getUTCDate()} ${MON[x.getUTCMonth()]}`; };
const fmtTime = (ts, tz = 'Europe/Madrid') => new Date(ts).toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit', timeZone: tz });
function briefText(b, link) {
  const c = b.content || {}, L = [`*Parte del día · ${fmtDay(b.date)}*`];
  if (c.notes) L.push('', c.notes);
  if (c.entradas && c.entradas.length) { L.push('', '*Entradas*'); for (const e of c.entradas) L.push(`• ${e.priority === 'urgent' ? '⚠️ ' : ''}${e.title}${e.source ? ` (${e.source})` : ''}`); }
  if (c.oncall && c.oncall.length) L.push('', '*Guardia*: ' + c.oncall.map(o => o.name + (o.role ? ` (${o.role})` : '')).join(', '));
  if (c.absences && c.absences.length) L.push('*Ausencias*: ' + c.absences.map(a => a.name + (a.covered_by ? ` → cubre ${a.covered_by}` : '')).join(', '));
  if (c.units) { L.push('', '*Unidades*' + (c.units_ok ? ` (${c.units_ok} sin incidencias)` : '')); for (const u of c.units) L.push(`• ${u.level === 'alert' ? '🔴' : '🟡'} ${u.name}: ${u.reasons.join('; ')}`); }
  if (c.interconsults) L.push('', `*Interconsultas*: ${c.interconsults.waiting} en espera${c.interconsults.overdue ? `, ${c.interconsults.overdue} fuera de plazo` : ''}${c.interconsults.unassigned ? `, ${c.interconsults.unassigned} sin asignar` : ''}`);
  if (c.meetings && c.meetings.length) { L.push('', '*Agenda de hoy*'); for (const m of c.meetings) L.push(`• ${fmtTime(m.at)} ${m.title}${m.location ? ` · ${m.location}` : ''}`); }
  if (c.actions && c.actions.length) { L.push('', '*Pendientes*'); for (const a of c.actions) L.push(`• ${a.state === 'overdue' ? '⏰ ' : ''}${a.text}${a.owner ? ` — ${a.owner}` : ''}`); }
  if (c.residents && c.residents.length) { L.push('', '*Residentes*'); for (const r of c.residents) L.push(`• ${r.unit}: ${r.names.join(', ')}`); }
  if (link) L.push('', link);
  return L.join('\n');
}
function postText(p, link) {
  const head = p.priority_level === 'urgent' ? '⚠️ *' + (p.title || '') + '*' : '*' + (p.title || '') + '*';
  const src = [p.source_label || p.source_service, p.source_detail].filter(Boolean).join(' · ');
  const body = p.content && p.content !== p.title ? '\n' + p.content : '';
  return head + (src ? `\n_De: ${src}_` : '') + body + (link ? '\n\n' + link : '');
}
function meetingText(m, items, link) {
  const L = [`*${m.title}*`, `${fmtDay(m.starts_at)} · ${fmtTime(m.starts_at)}${m.ends_at ? '–' + fmtTime(m.ends_at) : ''}${m.location ? ' · ' + m.location : ''}`];
  if (m.online_url) L.push(m.online_url);
  const sched = meetingSchedule(m.starts_at, items);
  if (sched.length) { L.push('', '*Orden del día*'); for (const it of sched) L.push(`• ${fmtTime(it.at)} ${it.topic}${it.presenter ? ` — ${it.presenter}` : ''}`); }
  if (link) L.push('', link);
  return L.join('\n');
}
const whatsappUrl = text => 'https://wa.me/?text=' + encodeURIComponent(String(text || '').slice(0, 3500));

/* ── CM-2: event files and the public view ── */
const EVENT_FILES = Object.freeze({
  banner: { types: { 'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp' }, maxBytes: 5 * 1024 * 1024 },
  flyer: { types: { 'application/pdf': '.pdf', 'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp' }, maxBytes: 10 * 1024 * 1024 },
});
// Check the declared type AND the file's first bytes (a renamed file is refused).
function checkEventFile(kind, mimetype, buffer) {
  const spec = EVENT_FILES[kind]; if (!spec) return { error: 'Unknown file kind.' };
  const ext = spec.types[mimetype]; if (!ext) return { error: kind === 'banner' ? 'The banner must be a JPEG, PNG or WEBP image.' : 'The flyer must be a PDF or an image.' };
  if (!buffer || !buffer.length) return { error: 'Empty file.' };
  if (buffer.length > spec.maxBytes) return { error: `Too large (max ${Math.round(spec.maxBytes / 1048576)} MB).` };
  const b = buffer, sig = { '.jpg': b[0] === 0xff && b[1] === 0xd8, '.png': b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47,
    '.webp': b.slice(0, 4).toString('latin1') === 'RIFF' && b.slice(8, 12).toString('latin1') === 'WEBP', '.pdf': b.slice(0, 5).toString('latin1') === '%PDF-' };
  if (!sig[ext]) return { error: 'The file content does not match its type.' };
  return { ext };
}
const eventFilePath = (meetingId, kind, ext, now = Date.now()) => `comms/meetings/${meetingId}/${kind}-${now}${ext}`;
// What a public event shows — nothing internal (no minutes, follow-ups, audience, organiser account, creator).
function publicEvent(m, { kindLabel, bannerUrl, flyerUrl } = {}) {
  return { id: m.id, title: m.title, kind: m.kind, kind_label: kindLabel || m.kind, starts_at: m.starts_at, ends_at: m.ends_at || null,
    location: m.location || null, online_url: m.online_url || null, description: m.description || null, status: m.status === 'cancelled' ? 'cancelled' : 'scheduled',
    banner_url: bannerUrl || null, banner_alt: m.banner_alt || m.title, flyer_url: flyerUrl || null, flyer_name: m.flyer_name || null };
}
// Month grid (Monday first) for the calendar: weeks of 7 days, each { date, in_month }.
function monthGrid(year, month /* 1-12 */) {
  const first = new Date(Date.UTC(year, month - 1, 1)), start = new Date(first); start.setUTCDate(1 - ((first.getUTCDay() + 6) % 7));
  const weeks = []; let d = new Date(start);
  do { const w = []; for (let i = 0; i < 7; i++) { w.push({ date: d.toISOString().slice(0, 10), in_month: d.getUTCMonth() === month - 1 }); d.setUTCDate(d.getUTCDate() + 1); } weeks.push(w); }
  while (d.getUTCMonth() === month - 1);
  return weeks;
}

/* ── CM-3: private messages (one message → a private copy per clinician, read in Mi espacio) ── */
const CLINICIAN_TYPES = Object.freeze(['attending_physician', 'medical_resident']);   // residents are clinicians too
function validateMessage(body) {
  const b = str(body.body, 4000); if (!b || b.length < 2) return { error: 'Write the message.' };
  const subject = str(body.subject, 120);
  let audience = body.audience === undefined || body.audience === null || body.audience === 'clinicians' ? { clinicians: true } : body.audience;
  if (typeof audience !== 'object') return { error: 'Invalid recipients.' };
  if (audience.clinicians === true) audience = { clinicians: true };
  else { const a = validateAudience(audience); if (a.error) return a; if (!a.value) return { error: 'Choose who receives it.' }; audience = a.value; }
  return { value: { subject, body: b, audience } };
}
// staff: [{id, staff_type, employment_status, deleted_at}], roster: [{staff_id, unit_id}] (current), oncallIds: []
function resolveRecipients(audience, staff, roster = [], oncallIds = [], { excludeId = null } = {}) {
  const active = (staff || []).filter(s => !s.deleted_at && (s.employment_status || 'active') === 'active');
  let ids;
  if (!audience || audience.clinicians) ids = active.filter(s => CLINICIAN_TYPES.includes(s.staff_type)).map(s => String(s.id));
  else {
    const set = new Set();
    for (const s of active) {
      const me = { staff_id: s.id, unit_ids: (roster || []).filter(r => String(r.staff_id) === String(s.id)).map(r => r.unit_id), roles: [s.staff_type] };
      if (audienceIncludes(audience, me, oncallIds)) set.add(String(s.id));
    }
    ids = [...set];
  }
  return ids.filter(id => !excludeId || id !== String(excludeId));
}

/* ── "Hoy para mí" (Mi espacio): only the signed-in person's own items, most urgent first ── */
const ACTION_ORDER = { overdue: 0, due_today: 1, open: 2 };
function buildMyToday({ today, actions = [], interconsults = [], oncall = null, meetings = [], units = [], rotation = null, unread = 0 }) {
  const acts = actions.map(a => ({ ...a, state: actionState(a, today) })).filter(a => a.status === 'open')
    .sort((a, b) => ACTION_ORDER[a.state] - ACTION_ORDER[b.state] || String(a.due_on || '9999').localeCompare(String(b.due_on || '9999')));
  const ics = interconsults.slice().sort((a, b) => (b.clock && b.clock.over ? 1 : 0) - (a.clock && a.clock.over ? 1 : 0) || String(a.received_at).localeCompare(String(b.received_at)));
  const attention = acts.filter(a => a.state === 'overdue').length + ics.filter(i => i.clock && i.clock.over).length + units.filter(u => u.level === 'alert').length;
  const lines = [];
  if (oncall) lines.push(`De guardia hoy (${oncall.role})`);
  if (rotation) lines.push(`Rotando en ${rotation.unit_name} hasta ${rotation.end_date}`);
  if (unread) lines.push(`${unread} mensaje${unread === 1 ? '' : 's'} sin leer`);
  return { today, attention, headline: lines, actions: acts.slice(0, 20), interconsults: ics.slice(0, 20), meetings: meetings.slice(0, 10), units, oncall, rotation, unread,
    empty: !acts.length && !ics.length && !meetings.length && !units.length && !oncall && !rotation && !unread };
}

module.exports = { buildMyToday, CLINICIAN_TYPES, validateMessage, resolveRecipients, EVENT_FILES, checkEventFile, eventFilePath, publicEvent, monthGrid, POST_TYPES, SYSTEM_TYPES, PRIORITIES, COMMS_FALLBACK, validateAudience, audienceIncludes, validatePost, validateAction, actionTransition, actionState,
  validateMeeting, meetingSchedule, BRIEF_SECTIONS, BRIEF_DEFAULT, validateBriefEdit, buildDailyBrief, briefText, postText, meetingText, whatsappUrl, fmtDay };
