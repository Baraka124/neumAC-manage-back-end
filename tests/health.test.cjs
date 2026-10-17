'use strict';
const test = require('node:test'), assert = require('node:assert');
const fs = require('fs'), path = require('path');
const H = require('../health.js');
const src = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');

test('scrub: no tokens, emails, query strings or long numbers', () => {
  const s = H.scrub('GET /api/x?token=abc&nhc=123 failed for ana@chuac.es Bearer eyJhbGciOi.eyJzdWIiOiIx.sig id 12345678');
  assert.doesNotMatch(s, /token=abc|nhc|ana@|eyJ|12345678/); assert.match(s, /\[email\]/); assert.match(s, /Bearer \[redacted\]/);
  assert.equal(H.scrub('x'.repeat(900)).length, 500);
});

test('route shape hides ids; same error → same fingerprint', () => {
  assert.equal(H.routeShape('/api/ops/units/8f1c2a3b-1111-2222-3333-444455556666/measures?x=1'), '/api/ops/units/:id/measures');
  assert.equal(H.routeShape('/api/items/42/edit'), '/api/items/:n/edit');
  const a = H.errorEntry({ source: 'server', route: '/api/ops/units/8f1c2a3b-1111-2222-3333-444455556666', message: 'timeout after 3000 ms' });
  const b = H.errorEntry({ source: 'server', route: '/api/ops/units/9f1c2a3b-1111-2222-3333-444455556666', message: 'timeout after 5000 ms' });
  assert.equal(a.fingerprint, b.fingerprint); assert.equal(a.source, 'server');
  assert.equal(H.errorEntry({ source: 'evil', message: 'x' }).source, 'server');
});

test('throttle: one row per fingerprint per window, repeats counted', () => {
  const t = H.makeThrottle(1000);
  assert.equal(t('f', 0), 1); assert.equal(t('f', 100), null); assert.equal(t('f', 200), null); assert.equal(t('f', 1200), 3); assert.equal(t('g', 1200), 1);
});

test('groupErrors sums counts and users', () => {
  const g = H.groupErrors([{ fingerprint: 'a', count: 2, created_at: '2026-10-17T08:00:00Z', user_id: 'u1' }, { fingerprint: 'a', count: 1, created_at: '2026-10-17T09:00:00Z', user_id: 'u2' }, { fingerprint: 'b', count: 1, created_at: '2026-10-17T07:00:00Z' }]);
  assert.equal(g[0].fingerprint, 'a'); assert.equal(g[0].count, 3); assert.equal(g[0].users, 2); assert.equal(g[0].last_seen, '2026-10-17T09:00:00Z');
});

test('status: missing updates, no backup, accounts and short secret are flagged; ok otherwise', () => {
  const all = Object.fromEntries(H.MIGRATIONS.flatMap(m => m.tables).map(t => [t, true]));
  const nowMs = Date.parse('2026-10-17T10:00:00Z');
  const bad = H.buildStatus({ db: { ok: true, ms: 80 }, tables: { ...all, ops_import_batches: false, app_errors: false }, env: { jwt_secret_len: 10 }, backups: { last_at: null, count: 0 }, accounts: { staff: 28, with_account: 10, with_email: 9 }, nowMs });
  assert.equal(bad.level, 'alert');
  assert.deepEqual(bad.migrations.filter(m => !m.applied).map(m => m.key), ['IM-1', 'PR-1']);
  assert.ok(bad.items.some(i => /JWT_SECRET/.test(i.text))); assert.ok(bad.items.some(i => /No backup yet/.test(i.text))); assert.ok(bad.items.some(i => /10 of 28/.test(i.text)));
  const good = H.buildStatus({ db: { ok: true, ms: 80 }, tables: all, env: { jwt_secret_len: 64, email_provider: true, email_mode: 'live', public_api_url: true, feed_token: true }, errors24h: {}, backups: { last_at: '2026-10-17T02:05:00Z', count: 5 }, accounts: { staff: 28, with_account: 28, with_email: 28 }, nowMs });
  assert.equal(good.level, 'ok');
  assert.equal(H.buildStatus({ db: { ok: false, error: 'x' }, tables: all, env: { jwt_secret_len: 64 }, nowMs }).items[0].area, 'database');
});

test('daily job failures appear in status', () => {
  const s = H.buildStatus({ db: { ok: true, ms: 5 }, tables: {}, env: { jwt_secret_len: 64 }, nowMs: 0, jobs: { digest: { kind: 'daily', label: 'Resumen', state: 'failed', last: { error: 'boom' } }, reports: { kind: 'daily', label: 'Informes', state: 'late' }, email_send: { kind: 'every', state: 'ok' } } });
  assert.ok(s.items.some(i => i.level === 'alert' && /Resumen: failed today — boom/.test(i.text)));
  assert.ok(s.items.some(i => i.level === 'watch' && /Informes/.test(i.text)));
});

test('backups: tables in restore order, private bucket, retention, nightly job', () => {
  assert.ok(H.BACKUP_TABLES.indexOf('ops_measure_types') < H.BACKUP_TABLES.indexOf('ops_measurements'));
  assert.ok(H.BACKUP_TABLES.indexOf('comm_messages') < H.BACKUP_TABLES.indexOf('comm_message_recipients'));
  assert.ok(!H.BACKUP_TABLES.includes('app_users'), 'no credentials in backups');
  assert.match(H.backupPath('2026-10-17', 'x'), /^2026-10-17\/neumdesk-ops-comms-x\.json\.gz$/);
  assert.match(src, /createBucket\(BACKUP_BUCKET, \{ public: false \}\)/);
  assert.match(src, /JOB_FNS\.backup = \(\) => pilotBackup\('nightly'\)/);
  assert.equal(require('../jobs.js').JOBS.backup.from, 2);
  assert.ok(fs.existsSync(path.join(__dirname, '..', 'scripts', 'restore-backup.js')));
  assert.match(fs.readFileSync(path.join(__dirname, '..', 'scripts', 'restore-backup.js'), 'utf8'), /const apply = args\.includes\('--apply'\)/);
});

test('routes: admin-only status, errors, backup; 5xx captured in one middleware; browser errors public but scrubbed', () => {
  for (const r of ["get('/api/admin/status'", "get('/api/admin/errors'", "post('/api/admin/backup'", "get('/api/admin/backups/link'"])
    assert.match(src, new RegExp(`app\\.${r.replace(/[()/]/g, m => '\\' + m)}, authenticateToken, notifyAdminOnly`), r);
  assert.match(src, /res\.on\('finish', \(\) => \{ if \(res\.statusCode >= 500\) pilotLogError/);
  assert.match(src, /app\.post\('\/api\/public\/client-errors', publicApiLimiterGuarded/);
  assert.ok(src.includes('neumdesk-ops-comms-[\\w-]+\\.json\\.gz$/.test(path)'), 'backup link only for backup files');
});
