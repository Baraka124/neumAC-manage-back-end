'use strict';
// Communication CM-1: posts (entradas briefed to the team), follow-ups, agenda, Parte del día, sharing.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const C = require('../comms.js');
const T = '2026-10-17';
const U1 = '11111111-1111-4111-8111-111111111111', U2 = '22222222-2222-4222-8222-222222222222', S1 = '33333333-3333-4333-8333-333333333333';
const idx = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
const mig = fs.readFileSync(path.join(__dirname, '..', 'migrations', '2026-10-17_comms_cm1_posts_actions_meetings_briefs.sql'), 'utf8');

test('posts: types, default priority per type, title from the first line, entradas need a source', () => {
  const v = C.validatePost({ type: 'entrada', content: 'Urgencias: 3 pacientes pendientes de cama\nUno con VMNI', source_service: 'urgencias', category: 'admission_request' }, { today: T, categories: ['admission_request'] }).value;
  assert.equal(v.title, 'Urgencias: 3 pacientes pendientes de cama'); assert.equal(v.priority_level, 'normal'); assert.equal(v.type, 'entrada');
  assert.match(C.validatePost({ type: 'entrada', content: 'Algo' }, { today: T }).error, /where it came from/);
  assert.equal(C.validatePost({ type: 'broadcast', content: 'Corte de luz' }, { today: T }).value.priority_level, 'urgent');
  assert.match(C.validatePost({ type: 'parte', content: 'x x' }, { today: T }).error, /Choose/);            // system-only types
  assert.match(C.validatePost({ content: 'ok ok', category: 'nope' }, { today: T, categories: ['information'] }).error, /category/);
  assert.match(C.validatePost({ content: 'ok ok', publish_end_date: '2026-10-01' }, { today: T }).error, /past/);
  assert.equal(C.validatePost({ content: 'x'.repeat(5000) }, { today: T }).value.content.length, 4000);
});

test('audience: who it concerns (everyone can still read it)', () => {
  assert.equal(C.validateAudience({ all: true }).value, null);
  assert.deepEqual(C.validateAudience({ units: [U1, U1], roles: ['medical_resident'], staff: [], oncall_today: true }).value, { units: [U1], roles: ['medical_resident'], oncall_today: true });
  assert.match(C.validateAudience({ units: ['x'] }).error, /units/);
  const me = { staff_id: S1, unit_ids: [U2], roles: ['attending_physician'] };
  assert.equal(C.audienceIncludes(null, me), true);
  assert.equal(C.audienceIncludes({ units: [U1] }, me), false);
  assert.equal(C.audienceIncludes({ units: [U2] }, me), true);
  assert.equal(C.audienceIncludes({ roles: ['attending_physician'] }, me), true);
  assert.equal(C.audienceIncludes({ oncall_today: true }, me, [S1]), true);
  assert.equal(C.audienceIncludes({ staff: [S1] }, me), true);
});

test('follow-ups: owner, due date, done / cancelled / reopen, overdue state', () => {
  assert.match(C.validateAction({ text: '' }).error, /done/);
  assert.deepEqual(C.validateAction({ text: 'Confirmar camas con Urgencias', owner_id: S1, due_on: T }).value, { text: 'Confirmar camas con Urgencias', owner_id: S1, due_on: T });
  const now = '2026-10-17T09:00:00.000Z';
  assert.deepEqual(C.actionTransition({ status: 'open' }, 'done', { userId: 'u', nowIso: now }).patch, { status: 'done', done_at: now, done_by: 'u' });
  assert.deepEqual(C.actionTransition({ status: 'done' }, 'open', { nowIso: now }).patch, { status: 'open', done_at: null, done_by: null });
  assert.match(C.actionTransition({ status: 'open' }, 'open', {}).error, /already/);
  assert.equal(C.actionState({ status: 'open', due_on: '2026-10-16' }, T), 'overdue');
  assert.equal(C.actionState({ status: 'open', due_on: T }, T), 'due_today');
  assert.equal(C.actionState({ status: 'done', due_on: '2026-10-01' }, T), 'done');
});

test('agenda: meeting with ordered items, https links only, schedule from durations', () => {
  const r = C.validateMeeting({ title: 'Sesión clínica: EPID', kind: 'sesion_clinica', starts_at: '2026-10-20T07:30:00Z', ends_at: '2026-10-20T08:30:00Z', location: 'Aula 3',
    online_url: 'https://teams.example/abc', materials: [{ label: 'Guía', url: 'https://example.org/guia.pdf' }],
    items: [{ topic: 'Caso 1', presenter_id: S1, duration_min: 20 }, { topic: 'Revisión', presenter_name: 'Dra. Invitada (Reumatología)', duration_min: 30 }] }, { kinds: ['sesion_clinica'] });
  assert.equal(r.items.length, 2); assert.equal(r.items[1].presenter_name, 'Dra. Invitada (Reumatología)'); assert.equal(r.items[0].presenter_name, null);
  const sch = C.meetingSchedule('2026-10-20T07:30:00Z', r.items);
  assert.equal(sch[1].at, '2026-10-20T07:50:00.000Z');
  assert.match(C.validateMeeting({ title: 'X y', starts_at: '2026-10-20T08:00:00Z', ends_at: '2026-10-20T07:00:00Z' }).error, /before it starts/);
  assert.match(C.validateMeeting({ title: 'X y', starts_at: '2026-10-20T08:00:00Z', online_url: 'http://insecure' }).error, /https/);
  assert.match(C.validateMeeting({ title: 'X y', starts_at: '2026-10-20T08:00:00Z', materials: [{ url: 'javascript:alert(1)' }] }).error, /https/);
  assert.match(C.validateMeeting({ title: 'X y', starts_at: '2026-10-20T08:00:00Z', kind: 'fiesta' }, { kinds: ['otra'] }).error, /kind/);
  assert.match(C.validateMeeting({ title: 'X y', starts_at: 'nope' }).error, /starts/);
});

test('Parte del día: sections, never the absence reason, units in order collapsed to a count', () => {
  const b = C.buildDailyBrief({ date: T, notes: 'Hoy cerramos 2 camas por obras.', entradas: [{ title: '3 ingresos desde Urgencias', source_label: 'Urgencias', priority_level: 'urgent' }],
    oncall: [{ name: 'Dra. Pérez', role: 'Adjunto/a' }], absences: [{ name: 'Dr. Gómez', until: '2026-10-20', covered_by: 'Dra. Ruiz', reason: 'enfermedad' }],
    units: [{ name: 'PFR', level: 'alert', reasons: [{ text: '1 out of service' }] }, { name: 'Sueño', level: 'ok', reasons: [] }],
    interconsults: { waiting: 4, overdue: 1, unassigned: 2 }, calls_today: 3,
    meetings: [{ title: 'Sesión EPID', starts_at: '2026-10-17T07:30:00Z', location: 'Aula 3' }],
    actions: [{ text: 'Confirmar camas', owner: 'Dra. Pérez', state: 'overdue' }, { text: 'Hecho', state: 'done' }],
    residents: [{ unit: 'PFR', names: ['Laura'] }] });
  assert.deepEqual(b.sections, [...C.BRIEF_DEFAULT]);
  assert.equal(JSON.stringify(b).includes('enfermedad'), false);
  assert.equal(b.content.units.length, 1); assert.equal(b.content.units_ok, 1);
  assert.equal(b.content.actions.length, 1);
  assert.equal(b.content.residents, undefined);                       // not in the default sections
  const text = C.briefText(b, 'https://desk.neumact.org/?c=brief:2026-10-17');
  assert.match(text, /^\*Parte del día · sáb 17 oct\*/);
  assert.match(text, /⚠️ 3 ingresos desde Urgencias \(Urgencias\)/);
  assert.match(text, /\*Guardia\*: Dra\. Pérez \(Adjunto\/a\)/);
  assert.match(text, /Dr\. Gómez → cubre Dra\. Ruiz/);
  assert.match(text, /🔴 PFR: 1 out of service/);
  assert.match(text, /4 en espera, 1 fuera de plazo, 2 sin asignar/);
  assert.match(text, /09:30 Sesión EPID · Aula 3/);                    // Madrid time
  assert.match(text, /⏰ Confirmar camas — Dra\. Pérez/);
  assert.match(C.validateBriefEdit({ sections: ['notes', 'nope'] }).error, /Unknown section/);
  assert.deepEqual(C.validateBriefEdit({ sections: ['residents', 'notes'] }).value.sections, ['notes', 'residents']);
});

test('sharing: WhatsApp text with a link back into neumDesk; no public pages', () => {
  const t = C.postText({ title: 'Cierre de 2 camas', content: 'Cierre de 2 camas\nPor obras hasta el lunes', source_label: 'Dirección Médica', priority_level: 'urgent' }, 'https://desk.neumact.org/?c=post:1');
  assert.match(t, /^⚠️ \*Cierre de 2 camas\*\n_De: Dirección Médica_\n/);
  assert.match(C.whatsappUrl(t), /^https:\/\/wa\.me\/\?text=/);
  assert.match(idx, /const commsLink = \(kind, id\) => `\$\{COMMS_APP_URL\}\/\?c=\$\{kind\}:\$\{id\}`/);
  assert.doesNotMatch(idx, /app\.get\('\/api\/public\/comms/);
});

test('routes: one permission map; author / owner / organiser may change their own; interconsultas logged once', () => {
  assert.match(idx, /const COMMS_PERMS = \{ read: \['communications', 'read'\]/);
  for (const r of ["app.get('/api/comms/overview'", "app.post('/api/comms/posts'", "app.post('/api/comms/actions'", "app.post('/api/comms/meetings'", "app.post('/api/comms/meetings/:id/announce'", "app.get('/api/comms/brief'", "app.post('/api/comms/brief/send'"])
    assert.ok(idx.includes(r), r);
  assert.match(idx, /if \(v\.value\.category === 'interconsulta' && req\.body\.log_interconsult === true\)/);
  assert.match(idx, /type: \['announcement', 'broadcast', 'protocol', 'kudos', 'entrada'\]\.includes\(req\.body\?\.type\)/);   // composer type kept
  assert.match(idx, /meetings\.forEach\(m => events\.push\(\{ id: m\.id, title: m\.title/);                                 // one calendar
});

test('migration: additive, RLS + audit on every new table, lists editable, no patient fields', () => {
  for (const t of ['comm_meetings', 'comm_meeting_items', 'comm_actions', 'comm_daily_briefs']) {
    assert.match(mig, new RegExp(`create table if not exists public\\.${t}`));
    assert.match(mig, new RegExp(`alter table public\\.${t} enable row level security`));
    assert.match(mig, new RegExp(`create trigger audit_${t} `));
  }
  assert.match(mig, /'comm_category','meeting_kind'\)\)/);
  for (const banned of ['patient_name', 'nhc', 'dni', 'birth', 'diagnosis']) assert.ok(!mig.toLowerCase().includes(banned), banned);
});

/* ── CM-2: events with banner / flyer, internal or public ── */
const mig2 = fs.readFileSync(path.join(__dirname, '..', 'migrations', '2026-10-17_comms_cm2_event_visibility_banner.sql'), 'utf8');
test('event files: banner = image, flyer = PDF or image; content must match the type; size capped', () => {
  const jpg = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0, 0]), png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a]), pdf = Buffer.from('%PDF-1.7 …');
  assert.equal(C.checkEventFile('banner', 'image/jpeg', jpg).ext, '.jpg');
  assert.equal(C.checkEventFile('banner', 'image/png', png).ext, '.png');
  assert.match(C.checkEventFile('banner', 'application/pdf', pdf).error, /JPEG, PNG or WEBP/);
  assert.equal(C.checkEventFile('flyer', 'application/pdf', pdf).ext, '.pdf');
  assert.match(C.checkEventFile('banner', 'image/png', jpg).error, /does not match/);                // renamed file refused
  assert.match(C.checkEventFile('flyer', 'image/svg+xml', Buffer.from('<svg/>')).error, /PDF or an image/);   // no SVG (scripts)
  assert.match(C.checkEventFile('banner', 'image/jpeg', Buffer.alloc(6 * 1024 * 1024, 0xff)).error, /Too large/);
  assert.match(C.eventFilePath('m1', 'banner', '.jpg', 5), /^comms\/meetings\/m1\/banner-5\.jpg$/);
});
test('public event: only safe fields — never minutes, follow-ups, audience or who created it', () => {
  const m = { id: 'm1', title: 'Seminario VMNI', kind: 'seminario', starts_at: '2026-11-05T15:00:00Z', location: 'Salón de actos', description: 'Abierto a residentes de Galicia',
    minutes: 'acta interna', audience: { roles: ['medical_resident'] }, created_by: 'u1', organizer_id: 's1', banner_path: 'comms/meetings/m1/banner-1.jpg', status: 'planned', visibility: 'public' };
  const p = C.publicEvent(m, { kindLabel: 'Seminario', bannerUrl: 'https://signed/x' });
  assert.deepEqual(Object.keys(p).sort(), ['banner_alt', 'banner_url', 'description', 'ends_at', 'flyer_name', 'flyer_url', 'id', 'kind', 'kind_label', 'location', 'online_url', 'starts_at', 'status', 'title']);
  assert.equal(p.status, 'scheduled'); assert.equal(p.banner_alt, 'Seminario VMNI');
  assert.equal(C.publicEvent({ ...m, status: 'cancelled' }).status, 'cancelled');
  assert.equal(C.validateMeeting({ title: 'X y', starts_at: '2026-11-05T15:00:00Z', visibility: 'secret' }).error, 'Visibility is internal or public.');
  assert.equal(C.validateMeeting({ title: 'X y', starts_at: '2026-11-05T15:00:00Z', visibility: 'public', description: 'd'.repeat(3000) }).value.description.length, 2000);
});
test('calendar month grid: Monday first, whole weeks', () => {
  const g = C.monthGrid(2026, 10);
  assert.equal(g[0][0].date, '2026-09-28'); assert.equal(g[0][3].date, '2026-10-01'); assert.equal(g[0][3].in_month, true);
  assert.ok(g.every(w => w.length === 7)); assert.equal(g[g.length - 1][6].date, '2026-11-01');
});
test('CM-2 routes and migration: private bucket + signed links; public feed without sign-in; internal looks missing', () => {
  assert.match(idx, /app\.get\('\/api\/public\/events', publicApiLimiterGuarded,/);
  assert.match(idx, /if \(!m \|\| m\.deleted_at \|\| m\.visibility !== 'public'\) return res\.status\(404\)/);
  assert.match(idx, /createSignedUrls\(list, 3600\)/);
  assert.match(idx, /app\.post\('\/api\/comms\/meetings\/:id\/files\/:kind', authenticateToken/);
  assert.match(mig2, /visibility text not null default 'internal'/);
  assert.match(mig2, /Run AFTER 2026-10-17_comms_cm1/);
});

/* ── CM-3: private messages ── */
const mig3 = fs.readFileSync(path.join(__dirname, '..', 'migrations', '2026-10-17_comms_cm3_private_messages.sql'), 'utf8');
test('private message: default recipients = all active clinicians (adjuntos + residentes), not the sender', () => {
  const staff = [{ id: 'a1', staff_type: 'attending_physician' }, { id: 'r1', staff_type: 'medical_resident' }, { id: 'e1', staff_type: 'biomedical_engineer' },
    { id: 'r2', staff_type: 'medical_resident', employment_status: 'inactive' }, { id: 'a2', staff_type: 'attending_physician', deleted_at: '2026-01-01' }, { id: 'boss', staff_type: 'attending_physician' }];
  assert.deepEqual(C.validateMessage({ body: 'Reunión el lunes' }).value.audience, { clinicians: true });
  assert.deepEqual(C.resolveRecipients({ clinicians: true }, staff, [], [], { excludeId: 'boss' }), ['a1', 'r1']);
  assert.ok(C.CLINICIAN_TYPES.includes('medical_resident'));
  // Narrower audiences reuse the same rules as posts
  assert.deepEqual(C.resolveRecipients({ roles: ['medical_resident'] }, staff), ['r1']);
  assert.deepEqual(C.resolveRecipients({ units: [U1] }, staff, [{ staff_id: 'a1', unit_id: U1 }]), ['a1']);
  assert.match(C.validateMessage({ body: '' }).error, /Write/);
  assert.match(C.validateMessage({ body: 'hola', audience: {} }).error, /who receives/);
});
test('private messages: copies per recipient, inbox only shows my own, sender sees counts only; migration safe', () => {
  assert.match(idx, /app\.post\('\/api\/comms\/messages', authenticateToken, commsCan\('message'\)/);
  assert.match(idx, /\.eq\('staff_id', sid\)\.is\('message\.deleted_at', null\)/);                 // my copies only
  assert.match(idx, /return data && String\(data\.staff_id\) === String\(sid\) \? data : null;/);     // read / archive only my copy
  assert.match(idx, /read_count: count\[m\.id\] \|\| 0/);                                           // counts, never who
  assert.doesNotMatch(idx.slice(idx.indexOf("app.get('/api/me/messages'"), idx.indexOf("async function commsMyCopy")), /staff_id:|recipients:/);
  for (const t of ['comm_messages', 'comm_message_recipients']) { assert.match(mig3, new RegExp(`alter table public\\.${t} enable row level security`)); assert.match(mig3, new RegExp(`create trigger audit_${t} `)); }
  assert.match(mig3, /unique \(message_id, staff_id\)/);
});
