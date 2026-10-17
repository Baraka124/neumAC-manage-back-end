'use strict';
// Notifications NT-1: email to registered users only; test mode; preferences; signed unsubscribe; safe HTML.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const N = require('../notify.js');
const idx = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
const mig = fs.readFileSync(path.join(__dirname, '..', 'migrations', '2026-10-17_notify_nt1_email_outbox_prefs.sql'), 'utf8');
const U = '11111111-1111-4111-8111-111111111111';

test('only registered, active accounts with an email; notifications on; kind not switched off', () => {
  const u = { email: 'ana@sergas.es', account_status: 'active', notifications_enabled: true };
  assert.equal(N.eligible(u, 'message'), true);
  assert.equal(N.eligible({ ...u, email: '' }, 'message'), false);
  assert.equal(N.eligible({ ...u, email: 'not-an-email' }, 'message'), false);
  assert.equal(N.eligible({ ...u, account_status: 'suspended' }, 'message'), false);
  assert.equal(N.eligible({ ...u, archived_at: '2026-01-01' }, 'message'), false);
  assert.equal(N.eligible({ ...u, notifications_enabled: false }, 'message'), false);
  assert.equal(N.eligible({ ...u, email_prefs: { parte: false } }, 'parte'), false);
  assert.equal(N.eligible({ ...u, email_prefs: { parte: false } }, 'message'), true);
  assert.match(N.validatePrefs({ parte: 'no' }).error, /on or off/);
  assert.deepEqual(N.validatePrefs({ parte: false, hack: true }).value, { parte: false });
});

test('test mode: every email goes to the test inbox, subject shows the real recipient', () => {
  assert.deepEqual(N.routeAddress('ana@sergas.es', { mode: 'test', testTo: 'test@x.com' }), { to: 'test@x.com', subjectPrefix: '[TEST → ana@sergas.es] ' });
  assert.deepEqual(N.routeAddress('ana@sergas.es', { mode: 'live', testTo: 'test@x.com' }), { to: 'ana@sergas.es', subjectPrefix: '' });
  assert.match(idx, /const EMAIL_MODE = String\(process\.env\.EMAIL_MODE \|\| 'test'\)\.toLowerCase\(\) === 'live' \? 'live' : 'test';/);   // test unless explicitly live
});

test('unsubscribe links are signed per user and kind', () => {
  const s = N.signUnsub('secret', U, 'parte');
  assert.equal(N.verifyUnsub('secret', U, 'parte', s), true);
  assert.equal(N.verifyUnsub('secret', U, 'message', s), false);
  assert.equal(N.verifyUnsub('other', U, 'parte', s), false);
  assert.equal(N.verifyUnsub('secret', 'x', 'parte', s), false);
  assert.equal(N.verifyUnsub('secret', U, 'parte', 'zz'), false);
});

test('emails escape everything; digest only when there is something; Madrid 07:00', () => {
  const m = N.messageEmail({ author: 'Dr. <b>X</b>', subject: 'Hola', body: '<script>alert(1)</script>\nlínea 2', link: 'https://desk.neumact.org/?view=mensajes' });
  assert.ok(!m.html.includes('<script>')); assert.ok(m.html.includes('&lt;script&gt;')); assert.ok(m.html.includes('<br>línea 2'));
  assert.equal(m.subject, 'Mensaje de Dr. <b>X</b>: Hola');   // subjects are plain text (not HTML)
  assert.equal(N.digestEmail({ name: 'Ana', dayLabel: 'sáb 17 oct', actions: [], events: [] }), null);
  const d = N.digestEmail({ name: 'Ana Pérez', dayLabel: 'sáb 17 oct', actions: [{ text: 'Confirmar camas', due_on: '2026-10-16', state: 'overdue' }], events: [] });
  assert.match(d.subject, /pendientes vencidos/); assert.match(d.html, /Buenos días, Ana/);
  const p = N.parteEmail({ dayLabel: 'sáb 17 oct', text: '*Parte del día · sáb 17 oct*\n\n*Guardia*: Dra. Pérez' });
  assert.ok(!p.html.includes('*')); assert.match(p.html, /Guardia: Dra\. Pérez/);
  assert.deepEqual(N.madridNow(new Date('2026-10-17T05:00:00Z')), { date: '2026-10-17', hour: 7 });   // CEST
  assert.deepEqual(N.madridNow(new Date('2026-12-17T06:00:00Z')), { date: '2026-12-17', hour: 7 });   // CET
  assert.ok(!/patient|paciente_|nhc/i.test(N.layout({ heading: 'x' }).replace('Sin datos de pacientes', '')));
});

test('wiring: outbox with dedupe, claim before send, retries, expiry, hooks never break actions', () => {
  assert.match(mig, /create unique index if not exists notif_outbox_dedupe on public\.notif_outbox \(dedupe_key\)/);
  assert.match(mig, /alter table public\.notif_outbox enable row level security/);
  assert.match(idx, /\.update\(\{ status: 'sending', attempts: \(row\.attempts \|\| 0\) \+ 1 \}\)\.eq\('id', row\.id\)\.eq\('status', 'queued'\)/);
  assert.match(idx, /expired \(older than 24 h\)/);
  assert.match(idx, /notifySafe\(notifyPrivateMessage\(msg, ids\)\)/);
  assert.match(idx, /if \(data\.priority_level === 'urgent'\) notifySafe\(notifyUrgentPost\(data, lists\)\)/);
  assert.match(idx, /notifySafe\(notifyParte\(date, Comms\.briefText\(brief, null\)\)\)/);
  assert.match(idx, /if \(NODE_ENV !== 'test'\) \{ const t = setInterval/);
  assert.match(idx, /app\.get\('\/api\/public\/email\/unsubscribe', publicApiLimiterGuarded,/);
  assert.equal(N.backoffMinutes(0), 1); assert.equal(N.backoffMinutes(9), 240);
});
