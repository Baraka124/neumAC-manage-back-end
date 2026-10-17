'use strict';
/* Jobs — the single scheduler's rules (pure: no database, no clock; `now` is passed in as Madrid wall time).
   Daily jobs get one run key per Madrid date (e.g. 'digest:2026-10-17'); the key is the lock in job_runs, so one
   server instance runs it once. Interval jobs (email sending, cache warm) are not logged. */

const JOBS = {
  digest:  { kind: 'daily', from: 7, until: 12, label: 'Resumen diario por email (07:00)' },
  reports: { kind: 'daily', from: 6, until: 23, label: 'Informes semana / mes (06:00)' },
  email_send: { kind: 'every', minutes: 1, label: 'Envío de emails en cola' },
  cache_warm: { kind: 'every', minutes: 5, label: 'Precarga de Grounded y Outlook' }
};
const STALE_RUNNING_MIN = 30;   // a 'running' row older than this belongs to a crashed instance
const RETRY_AFTER_MIN = 15;     // a failed daily job is retried after this, within its window
const MAX_ATTEMPTS = 3;

// now: { date: 'YYYY-MM-DD', hour, minute }. Returns the run key if the daily job is inside its window, else null.
function dailyKey(job, now) {
  const s = JOBS[job]; if (!s || s.kind !== 'daily' || !now?.date) return null;
  return now.hour >= s.from && now.hour < s.until ? `${job}:${now.date}` : null;
}
function dueDaily(now) { return Object.keys(JOBS).map(j => ({ job: j, key: dailyKey(j, now) })).filter(x => x.key); }

// Is an existing job_runs row for this key blocking a new run? (ok → yes; running → yes unless stale; failed → handled by renaming)
function blocking(row, nowMs) {
  if (!row) return false;
  if (row.status === 'ok') return true;
  if (row.status === 'running') return nowMs - Date.parse(row.started_at) < STALE_RUNNING_MIN * 60000;
  return false;
}
// A failed or stale run is renamed so the key is free again: 'digest:2026-10-17#f1697…'.
const retiredKey = (key, nowMs) => `${key}#f${nowMs}`;
// May we try again? attempts: previous failed rows for this key, newest first.
function mayRetry(failed, nowMs) {
  if (!failed.length) return true;
  if (failed.length >= MAX_ATTEMPTS) return false;
  return nowMs - Date.parse(failed[0].finished_at || failed[0].started_at) >= RETRY_AFTER_MIN * 60000;
}

// Admin view: last run per job + health.
function summarize(rows, now, nowMs) {
  const out = {};
  for (const job of Object.keys(JOBS)) {
    const s = JOBS[job], mine = rows.filter(r => r.job === job).sort((a, b) => String(b.started_at).localeCompare(String(a.started_at)));
    const last = mine[0] || null, okToday = mine.find(r => r.status === 'ok' && String(r.run_key).startsWith(`${job}:${now.date}`));
    let state = 'ok';
    if (s.kind === 'daily') {
      if (okToday) state = 'ok';
      else if (now.hour < s.from) state = 'waiting';
      else if (last && last.status === 'running' && blocking(last, nowMs)) state = 'running';
      else state = mine.some(r => r.status === 'failed' && String(r.run_key).startsWith(`${job}:${now.date}`)) ? 'failed' : 'late';
    }
    out[job] = { label: s.label, kind: s.kind, state, last: last && { status: last.status, run_key: last.run_key, started_at: last.started_at, duration_ms: last.duration_ms, detail: last.detail, error: last.error } };
  }
  return out;
}

// TTL cache with in-flight sharing (two requests at once compute once).
function makeCache(clock = () => Date.now()) {
  const store = new Map();
  return {
    async get(key, ttlMs, fn, { fresh = false } = {}) {
      const hit = store.get(key), t = clock();
      if (!fresh && hit && hit.value !== undefined && t - hit.at < ttlMs) return { value: hit.value, as_of: new Date(hit.at).toISOString(), cached: true };
      if (!fresh && hit && hit.pending) return hit.pending;
      const pending = Promise.resolve().then(fn).then(value => { store.set(key, { value, at: t }); return { value, as_of: new Date(t).toISOString(), cached: false }; },
        e => { if (hit && hit.value !== undefined) store.set(key, hit); else store.delete(key); throw e; });
      store.set(key, { ...(hit || {}), pending });
      return pending;
    },
    bust(prefix = '') { for (const k of [...store.keys()]) if (k.startsWith(prefix)) store.delete(k); },
    size: () => store.size
  };
}

module.exports = { JOBS, STALE_RUNNING_MIN, RETRY_AFTER_MIN, MAX_ATTEMPTS, dailyKey, dueDaily, blocking, retiredKey, mayRetry, summarize, makeCache };
