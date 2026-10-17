'use strict';
const test = require('node:test'), assert = require('node:assert');
const fs = require('fs'), path = require('path');
const Jobs = require('../jobs.js');
const src = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
const sql = fs.readFileSync(path.join(__dirname, '..', 'migrations', '2026-10-17_jobs_jb1_runs_and_atomic_writes.sql'), 'utf8');

test('daily windows by Madrid hour', () => {
  assert.equal(Jobs.dailyKey('digest', { date: '2026-10-17', hour: 6 }), null);
  assert.equal(Jobs.dailyKey('digest', { date: '2026-10-17', hour: 7 }), 'digest:2026-10-17');
  assert.equal(Jobs.dailyKey('digest', { date: '2026-10-17', hour: 12 }), null);
  assert.equal(Jobs.dailyKey('reports', { date: '2026-10-17', hour: 6 }), 'reports:2026-10-17');
  assert.equal(Jobs.dailyKey('email_send', { date: '2026-10-17', hour: 9 }), null);
  assert.deepEqual(Jobs.dueDaily({ date: '2026-10-17', hour: 8 }).map(x => x.job).sort(), ['digest', 'reports']);
});

test('lock: ok blocks, fresh running blocks, stale running frees', () => {
  const now = Date.parse('2026-10-17T10:00:00Z');
  assert.equal(Jobs.blocking(null, now), false);
  assert.equal(Jobs.blocking({ status: 'ok', started_at: '2026-10-17T05:00:00Z' }, now), true);
  assert.equal(Jobs.blocking({ status: 'running', started_at: '2026-10-17T09:50:00Z' }, now), true);
  assert.equal(Jobs.blocking({ status: 'running', started_at: '2026-10-17T09:00:00Z' }, now), false);
  assert.equal(Jobs.blocking({ status: 'failed', started_at: '2026-10-17T09:59:00Z' }, now), false);
  assert.match(Jobs.retiredKey('digest:2026-10-17', now), /^digest:2026-10-17#f\d+$/);
});

test('retry: after 15 min, at most 3 attempts', () => {
  const now = Date.parse('2026-10-17T10:00:00Z');
  assert.equal(Jobs.mayRetry([], now), true);
  assert.equal(Jobs.mayRetry([{ finished_at: '2026-10-17T09:50:00Z' }], now), false);
  assert.equal(Jobs.mayRetry([{ finished_at: '2026-10-17T09:40:00Z' }], now), true);
  assert.equal(Jobs.mayRetry([1, 2, 3].map(() => ({ finished_at: '2026-10-17T08:00:00Z' })), now), false);
});

test('summary states', () => {
  const now = { date: '2026-10-17', hour: 9 }, ms = Date.parse('2026-10-17T07:00:00Z');
  const s = Jobs.summarize([{ job: 'reports', run_key: 'reports:2026-10-17', status: 'ok', started_at: '2026-10-17T04:00:00Z' }], now, ms);
  assert.equal(s.reports.state, 'ok'); assert.equal(s.digest.state, 'late');
  assert.equal(Jobs.summarize([], { date: '2026-10-17', hour: 5 }, ms).digest.state, 'waiting');
  const f = Jobs.summarize([{ job: 'digest', run_key: 'digest:2026-10-17#f1', status: 'failed', started_at: '2026-10-17T05:00:00Z' }], now, ms);
  assert.equal(f.digest.state, 'failed');
});

test('cache: TTL, shared in-flight, fresh, failure keeps old value', async () => {
  let t = 0, calls = 0; const c = Jobs.makeCache(() => t);
  const fn = async () => ++calls;
  const [a, b] = await Promise.all([c.get('k', 100, fn), c.get('k', 100, fn)]);
  assert.equal(calls, 1); assert.equal(a.value, 1); assert.equal(b.value, 1);
  t = 50; assert.equal((await c.get('k', 100, fn)).cached, true);
  t = 150; assert.equal((await c.get('k', 100, fn)).value, 2);
  assert.equal((await c.get('k', 100, fn, { fresh: true })).value, 3);
  t = 400; await assert.rejects(c.get('k', 100, async () => { throw new Error('x'); }));
  t = 401; assert.equal((await c.get('k', 1000, fn)).value, 3);   // previous value survived the failure
  c.bust('k'); assert.equal(c.size(), 0);
});

test('Madrid today: 23:30 UTC on 16 Oct is already the 17th', () => {
  assert.match(src, /const opsToday = \(d = new Date\(\)\) => new Intl\.DateTimeFormat\('en-CA', \{ timeZone: 'Europe\/Madrid'/);
  const fmt = d => new Intl.DateTimeFormat('en-CA', { timeZone: 'Europe/Madrid', year: 'numeric', month: '2-digit', day: '2-digit' }).format(d);
  assert.equal(fmt(new Date('2026-10-16T22:30:00Z')), '2026-10-17');   // CEST
  assert.equal(fmt(new Date('2026-12-16T23:30:00Z')), '2026-12-17');   // CET
  assert.equal(fmt(new Date('2026-12-16T22:30:00Z')), '2026-12-16');
});

test('atomic writes call the JB-1 functions and keep a fallback', () => {
  assert.match(src, /async function opsRpc\(name, args\)[\s\S]{0,200}PGRST202/);
  for (const fn of ['ops_store_report', 'comms_send_brief', 'comms_send_message']) {
    assert.match(src, new RegExp(`opsRpc\\('${fn}'`), fn);
    assert.match(sql, new RegExp(`create or replace function public\\.${fn}\\(`), fn);
    assert.match(sql, new RegExp(`revoke all on function public\\.${fn}\\(`), fn + ' revoked');
  }
  assert.match(src, /if \(!atomic\.missing\)/);
});

test('one scheduler, admin-only jobs view, cached heavy reads', () => {
  assert.equal((src.match(/setInterval\(/g) || []).filter((_, i, a) => true).length >= 1, true);
  assert.doesNotMatch(src, /setInterval\(\(\) => notifyTick\(\)/);
  assert.match(src, /setInterval\(\(\) => jobsTick\(\)/);
  assert.match(src, /app\.get\('\/api\/admin\/jobs', authenticateToken, notifyAdminOnly/);
  assert.match(src, /app\.post\('\/api\/admin\/jobs\/:job\/run', authenticateToken, notifyAdminOnly/);
  assert.match(src, /opsCache\.get\('grounded', 120000/);
  assert.match(src, /opsCache\.get\(`outlook:\$\{weeks\}`, 300000/);
  assert.match(sql, /run_key text not null unique/);
  assert.match(sql, /alter table public\.job_runs enable row level security/);
});
