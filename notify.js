'use strict';
/* Notifications NT-1 — pure rules (no database, no network). Email only to REGISTERED users (accounts with an email).
   Instant: private messages, urgent posts, the Parte del día. Daily summary (07:00 Madrid): follow-ups and events.
   TEST MODE (default): every email goes to one test inbox, with the real recipient shown — nobody else receives anything. */
const crypto = require('crypto');

const KINDS = Object.freeze({
  message: { label: 'Mensajes privados', instant: true },
  urgent: { label: 'Avisos urgentes', instant: true },
  parte: { label: 'Parte del día', instant: true },
  digest: { label: 'Resumen diario (pendientes y agenda)', instant: false },
});
const esc = s => String(s === undefined || s === null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const nl2br = s => esc(s).replace(/\n/g, '<br>');
const isEmail = e => /^[^\s@<>()]+@[^\s@<>()]+\.[^\s@<>()]{2,}$/.test(String(e || ''));

// Who may receive an email of this kind: active account, real email, notifications on, kind not switched off.
function eligible(user, kind) {
  if (!user || !isEmail(user.email)) return false;
  if (user.account_status && !['active'].includes(String(user.account_status).toLowerCase())) return false;
  if (user.archived_at || user.suspended_at || user.locked_at) return false;
  if (user.notifications_enabled === false) return false;
  const p = user.email_prefs || {};
  return p[kind] !== false;
}
function validatePrefs(body) {
  const out = {};
  for (const k of Object.keys(KINDS)) if (body && body[k] !== undefined) { if (typeof body[k] !== 'boolean') return { error: 'Each preference is on or off.' }; out[k] = body[k]; }
  return { value: out };
}

// Test mode: one inbox receives everything; the subject says who it was for.
function routeAddress(realEmail, { mode = 'test', testTo = '' } = {}) {
  if (mode === 'live') return { to: realEmail, subjectPrefix: '' };
  return { to: testTo, subjectPrefix: `[TEST → ${realEmail}] ` };
}

// Unsubscribe links: HMAC-signed (user, kind) so nobody can switch off someone else's email.
const signUnsub = (secret, userId, kind) => crypto.createHmac('sha256', String(secret)).update(`unsub:${userId}:${kind}`).digest('hex').slice(0, 32);
function verifyUnsub(secret, userId, kind, sig) {
  if (!KINDS[kind] || !/^[0-9a-f-]{36}$/i.test(String(userId || '')) || !/^[0-9a-f]{32}$/.test(String(sig || ''))) return false;
  const a = Buffer.from(signUnsub(secret, userId, kind)), b = Buffer.from(String(sig));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// One layout for every email. `blocks` = [{title?, html}] (already escaped by the caller via these helpers).
function layout({ heading, intro, blocks = [], cta, footerLinks = [] }) {
  const html = `<div style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:600px;margin:0 auto;color:#10283c">
<div style="background:#10283c;padding:14px 20px;border-radius:10px 10px 0 0"><span style="color:#7fd6d6;font-weight:700;font-size:15px">neumDesk</span><span style="color:rgba(255,255,255,.55);font-size:12px;margin-left:8px">Servicio de Neumología · CHUAC</span></div>
<div style="background:#fff;padding:20px 24px;border:1px solid #e3e7ea;border-top:none;border-radius:0 0 10px 10px">
<h2 style="margin:0 0 8px;font-size:18px">${esc(heading)}</h2>${intro ? `<p style="margin:0 0 14px;color:#4a5a66;font-size:14px">${esc(intro)}</p>` : ''}
${blocks.map(b => `${b.title ? `<h3 style="margin:16px 0 6px;font-size:13px;letter-spacing:.04em;text-transform:uppercase;color:#4a5a66">${esc(b.title)}</h3>` : ''}<div style="font-size:14px;line-height:1.5">${b.html}</div>`).join('')}
${cta ? `<p style="margin:20px 0 4px"><a href="${esc(cta.href)}" style="display:inline-block;background:#10283c;color:#fff;text-decoration:none;padding:10px 16px;border-radius:8px;font-weight:600;font-size:14px">${esc(cta.label)}</a></p><p style="margin:4px 0 0;font-size:12px;color:#7a8a96">Requiere iniciar sesión en neumDesk.</p>` : ''}
</div>
<p style="color:#8a98a3;font-size:11px;margin:10px 0 0;text-align:center">Sin datos de pacientes. ${footerLinks.map(l => `<a href="${esc(l.href)}" style="color:#8a98a3">${esc(l.label)}</a>`).join(' · ')}</p></div>`;
  return html;
}
const toText = html => String(html).replace(/<br\s*\/?>/gi, '\n').replace(/<\/(p|h2|h3|li|div)>/gi, '\n').replace(/<[^>]+>/g, '').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/\n{3,}/g, '\n\n').trim();

function messageEmail({ author, subject, body, link }) {
  return { subject: `Mensaje de ${author}${subject ? ': ' + subject : ''}`.slice(0, 200),
    html: layout({ heading: subject || 'Mensaje privado', intro: `De ${author} · solo para ti`, blocks: [{ html: nl2br(body) }], cta: link ? { href: link, label: 'Abrir en Mi espacio' } : null }) };
}
function urgentEmail({ title, content, source, link }) {
  return { subject: `⚠️ Urgente: ${title}`.slice(0, 200),
    html: layout({ heading: title, intro: source ? `De: ${source}` : 'Aviso urgente del servicio', blocks: [{ html: nl2br(content) }], cta: link ? { href: link, label: 'Ver en neumDesk' } : null }) };
}
function parteEmail({ dayLabel, text, link }) {
  const body = String(text || '').replace(/^\*Parte del día[^\n]*\n?/, '').replace(/\*([^*\n]+)\*/g, '$1').replace(/_([^_\n]+)_/g, '$1').trim();
  return { subject: `Parte del día · ${dayLabel}`.slice(0, 200), html: layout({ heading: `Parte del día · ${dayLabel}`, blocks: [{ html: nl2br(body) }], cta: link ? { href: link, label: 'Ver el parte' } : null }) };
}
// Daily summary: only sent when something is in it. actions = mine (overdue / due today / open), events = today + tomorrow.
function digestEmail({ name, dayLabel, actions = [], events = [], link }) {
  if (!actions.length && !events.length) return null;
  const blocks = [];
  if (actions.length) blocks.push({ title: 'Tus pendientes', html: '<ul style="margin:0;padding-left:18px">' + actions.map(a => `<li>${a.state === 'overdue' ? '<b style="color:#a2321f">Vencido · </b>' : a.state === 'due_today' ? '<b style="color:#8a5a00">Hoy · </b>' : ''}${esc(a.text)}${a.due_on ? ` <span style="color:#7a8a96">(${esc(a.due_on)})</span>` : ''}</li>`).join('') + '</ul>' });
  if (events.length) blocks.push({ title: 'Agenda (hoy y mañana)', html: '<ul style="margin:0;padding-left:18px">' + events.map(e => `<li><b>${esc(e.when)}</b> ${esc(e.title)}${e.location ? ` · ${esc(e.location)}` : ''}</li>`).join('') + '</ul>' });
  return { subject: `neumDesk · Resumen del ${dayLabel}${actions.some(a => a.state === 'overdue') ? ' · pendientes vencidos' : ''}`.slice(0, 200),
    html: layout({ heading: `Buenos días${name ? ', ' + name.split(' ')[0] : ''}`, intro: `Tu resumen del ${dayLabel}.`, blocks, cta: link ? { href: link, label: 'Abrir neumDesk' } : null }) };
}
// Madrid local date / hour (the daily summary goes out at 07:00 local).
function madridNow(d = new Date()) {
  const parts = Object.fromEntries(new Intl.DateTimeFormat('en-GB', { timeZone: 'Europe/Madrid', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', hour12: false }).formatToParts(d).map(p => [p.type, p.value]));
  return { date: `${parts.year}-${parts.month}-${parts.day}`, hour: Number(parts.hour) % 24 };
}
const backoffMinutes = attempts => [1, 5, 15, 60, 240][Math.min(attempts, 4)];

module.exports = { KINDS, esc, nl2br, isEmail, eligible, validatePrefs, routeAddress, signUnsub, verifyUnsub, layout, toText, messageEmail, urgentEmail, parteEmail, digestEmail, madridNow, backoffMinutes };
