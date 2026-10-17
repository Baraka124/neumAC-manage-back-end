'use strict';
/* Pilot readiness (PR-1) — pure rules for the system status panel, the error log and backups.
   No database, no clock: probes' results and `nowMs` are passed in. */

const crypto = require('crypto');

// Each database update and the tables that prove it was applied. Order = the order they must be run.
const MIGRATIONS = [
  { key: 'OR-1/2/3', file: '2026-10-16_ops_room_or1… / or2… / or2b_or3…', tables: ['ops_resources', 'ops_measurements', 'ops_interconsults', 'ops_indicators'], feature: 'Ops Room' },
  { key: 'OR-C', file: '2026-10-17_ops_room_orc_catalogues_targets.sql', tables: ['ops_catalog_items', 'ops_targets'], feature: 'Configuración lists and targets' },
  { key: 'OR-R', file: '2026-10-17_ops_room_orr_breakdowns_calls_reports.sql', tables: ['ops_reports'], feature: 'Breakdowns, calls, reports' },
  { key: 'CM-1', file: '2026-10-17_comms_cm1_posts_actions_meetings_briefs.sql', tables: ['comm_actions', 'comm_meetings', 'comm_daily_briefs'], feature: 'Comunicación' },
  { key: 'CM-3', file: '2026-10-17_comms_cm3_private_messages.sql', tables: ['comm_messages', 'comm_message_recipients'], feature: 'Private messages' },
  { key: 'NT-1', file: '2026-10-17_notify_nt1_email_outbox_prefs.sql', tables: ['notif_outbox'], feature: 'Email notifications' },
  { key: 'JB-1', file: '2026-10-17_jobs_jb1_runs_and_atomic_writes.sql', tables: ['job_runs'], feature: 'Job log + atomic writes' },
  { key: 'IM-1', file: '2026-10-17_import_im1_mappings_batches.sql', tables: ['ops_import_mappings', 'ops_import_batches'], feature: 'Importar datos' },
  { key: 'PR-1', file: '2026-10-17_pilot_pr1_error_log.sql', tables: ['app_errors'], feature: 'Error log' }
];

// What a backup holds, in restore order (parents before children). Counts and operational records only.
const BACKUP_TABLES = [
  'training_units', 'unit_staff',
  'ops_catalog_items', 'ops_targets', 'ops_resources', 'ops_resource_events', 'ops_measure_types', 'ops_import_mappings', 'ops_import_batches',
  'ops_measurements', 'ops_incidents', 'ops_interconsults', 'ops_indicators', 'ops_indicator_values', 'ops_reports',
  'department_announcements', 'comm_actions', 'comm_meetings', 'comm_meeting_items', 'comm_daily_briefs', 'comm_messages', 'comm_message_recipients'
];
const BACKUP_KEEP_DAYS = 30;
const backupPath = (date, stamp) => `${date}/neumdesk-ops-comms-${stamp}.json.gz`;

// Remove things that should never be stored in an error log: query strings, bearer tokens, e-mails, long digit runs.
function scrub(s, max = 500) {
  return String(s ?? '')
    .replace(/Bearer\s+[A-Za-z0-9._-]+/gi, 'Bearer [redacted]')
    .replace(/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+/g, '[jwt]')
    .replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, '[email]')
    .replace(/\?[^\s'"]*/g, '?…')
    .replace(/\b\d{6,}\b/g, '[n]')
    .slice(0, max);
}
// Route without ids: /api/ops/units/8f1c…/measures → /api/ops/units/:id/measures
const routeShape = p => String(p || '').split('?')[0].replace(/\/[0-9a-f]{8}-[0-9a-f-]{27,}/gi, '/:id').replace(/\/\d+(?=\/|$)/g, '/:n').slice(0, 200);
const fingerprint = (source, route, message) => crypto.createHash('sha1').update(`${source}|${route}|${String(message).replace(/\d+/g, '#').slice(0, 200)}`).digest('hex').slice(0, 20);

function errorEntry({ source, route, status = null, message, detail = null, release = null, userId = null, userAgent = null }) {
  const r = routeShape(route), m = scrub(message || 'Unknown error');
  return { source: source === 'browser' ? 'browser' : 'server', route: r, status: Number.isInteger(status) ? status : null, message: m,
    detail: detail ? scrub(detail, 2000) : null, release: release ? String(release).slice(0, 60) : null, user_id: userId || null,
    user_agent: userAgent ? String(userAgent).slice(0, 200) : null, fingerprint: fingerprint(source, r, m) };
}
// One row per fingerprint per window; repeats inside the window are counted and written with the next row.
function makeThrottle(windowMs = 5 * 60000, maxKeys = 500) {
  const seen = new Map();
  return (fp, nowMs) => {
    const s = seen.get(fp);
    if (s && nowMs - s.at < windowMs) { s.suppressed++; return null; }
    const count = 1 + (s ? s.suppressed : 0);
    seen.set(fp, { at: nowMs, suppressed: 0 });
    if (seen.size > maxKeys) seen.delete(seen.keys().next().value);
    return count;
  };
}
// Group the log for the admin view.
function groupErrors(rows) {
  const g = new Map();
  for (const r of rows || []) {
    const k = r.fingerprint || r.id, cur = g.get(k) || { fingerprint: k, source: r.source, route: r.route, status: r.status, message: r.message, count: 0, first_seen: r.created_at, last_seen: r.created_at, release: r.release, users: new Set() };
    cur.count += Number(r.count) || 1;
    if (r.created_at < cur.first_seen) cur.first_seen = r.created_at;
    if (r.created_at > cur.last_seen) { cur.last_seen = r.created_at; cur.release = r.release; cur.detail = r.detail; }
    if (r.user_id) cur.users.add(r.user_id);
    g.set(k, cur);
  }
  return [...g.values()].map(x => ({ ...x, users: x.users.size })).sort((a, b) => String(b.last_seen).localeCompare(String(a.last_seen)));
}

/* Status panel. in = {
     db: { ok, ms, error }, tables: { name: true|false },
     env: { email_provider, email_mode, feed_token, jwt_secret_len, public_api_url, node_env },
     jobs: Jobs.summarize(...) | null, outbox: { queued, failed_7d, oldest_queued_min } | null,
     errors24h: { server, browser } | null, backups: { last_at, count } | null,
     accounts: { staff, with_account, with_email, without: [names] } | null, nowMs } */
function buildStatus(x) {
  const items = [];
  const add = (area, level, text, fix = null) => items.push({ area, level, text, fix });
  if (!x.db?.ok) add('database', 'alert', 'Database not reachable' + (x.db?.error ? `: ${x.db.error}` : ''), 'Check Supabase status and SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY in Railway.');
  else add('database', x.db.ms > 1500 ? 'watch' : 'ok', `Database reachable (${x.db.ms} ms)`);

  const migrations = MIGRATIONS.map(m => {
    const missing = m.tables.filter(t => x.tables && x.tables[t] === false);
    return { key: m.key, file: m.file, feature: m.feature, applied: !missing.length, missing };
  });
  const pending = migrations.filter(m => !m.applied);
  if (pending.length) add('database', 'alert', `${pending.length} database update(s) not applied: ${pending.map(m => m.key).join(', ')}`, 'Run the files in order in Supabase → SQL Editor (they are idempotent).');
  else add('database', 'ok', 'All database updates applied');

  const e = x.env || {};
  if ((e.jwt_secret_len || 0) < 32) add('security', 'alert', 'JWT_SECRET is short', 'Set a random secret of 32+ characters in Railway (this signs out everyone once).');
  if (!e.email_provider) add('email', 'watch', 'No email provider (RESEND_API_KEY): emails stay queued and expire after 24 h', 'Add RESEND_API_KEY in Railway.');
  else add('email', e.email_mode === 'live' ? 'ok' : 'watch', e.email_mode === 'live' ? 'Email: live (real recipients)' : 'Email: test mode (everything goes to the test inbox)');
  if (!e.public_api_url) add('email', 'watch', 'PUBLIC_API_URL not set: unsubscribe links use the default host');
  add('feed', e.feed_token ? 'ok' : 'info', e.feed_token ? 'Hospital feed on (OPS_FEED_TOKEN set)' : 'Hospital feed off (set OPS_FEED_TOKEN to enable)');

  if (x.jobs) for (const [job, j] of Object.entries(x.jobs)) {
    if (j.kind !== 'daily') continue;
    if (j.state === 'failed') add('jobs', 'alert', `${j.label}: failed today${j.last?.error ? ' — ' + j.last.error : ''}`, 'Open “Background jobs” below and press “run now”, or check the error.');
    else if (j.state === 'late') add('jobs', 'watch', `${j.label}: has not run yet today`, 'The server may have been asleep; it runs on the next minute it is awake.');
  }
  if (x.outbox) {
    if (x.outbox.oldest_queued_min > 30) add('email', 'watch', `${x.outbox.queued} email(s) waiting, the oldest for ${x.outbox.oldest_queued_min} min`);
    if (x.outbox.failed_7d) add('email', 'watch', `${x.outbox.failed_7d} email(s) failed in the last 7 days`);
  }
  if (x.errors24h) {
    const n = (x.errors24h.server || 0) + (x.errors24h.browser || 0);
    if (n) add('errors', n >= 20 ? 'alert' : 'watch', `${n} error(s) in the last 24 h (${x.errors24h.server || 0} server, ${x.errors24h.browser || 0} browser)`, 'See the error log below.');
    else add('errors', 'ok', 'No errors in the last 24 h');
  }
  if (x.backups) {
    const age = x.backups.last_at ? Math.round((x.nowMs - Date.parse(x.backups.last_at)) / 3600000) : null;
    if (age === null) add('backup', 'alert', 'No backup yet', 'Run “Back up now”; then it runs every night.');
    else add('backup', age > 30 ? 'alert' : 'ok', `Last backup ${age} h ago (${x.backups.count} kept)`);
  }
  if (x.accounts) {
    const a = x.accounts;
    add('accounts', a.with_account < a.staff ? 'watch' : 'ok', `${a.with_account} of ${a.staff} active staff have an account; ${a.with_email} with email`,
      a.with_account < a.staff ? 'Invite the rest from Access (Usuarios) before the pilot.' : null);
  }
  const order = { alert: 0, watch: 1, info: 2, ok: 3 };
  items.sort((p, q) => order[p.level] - order[q.level]);
  const level = items.some(i => i.level === 'alert') ? 'alert' : items.some(i => i.level === 'watch') ? 'watch' : 'ok';
  return { level, items, migrations };
}

module.exports = { MIGRATIONS, BACKUP_TABLES, BACKUP_KEEP_DAYS, backupPath, scrub, routeShape, fingerprint, errorEntry, makeThrottle, groupErrors, buildStatus };
