# Designing a strong Ops Room backend

How the Pneumo Ops Room backend (and Comunicación, Notifications, Outlook) is built, the rules that keep it
trustworthy, where it is weak today, and the checklist for adding anything new. Read this before changing the backend.
Plan of record and history: `OPS_ROOMS.md` and `COMMS.md` in the frontend repo; email: `NOTIFICATIONS.md`.

---

## 1. What "strong" means here

An Ops Room backend is strong when a head of department can act on what it says without double-checking:

1. **Every number has one owner and one source.** Rotations come from Rotations, guardias from On-call, staff from
   Staff. The Ops Room *links* to them and never copies them.
2. **Nothing is invented.** No default targets, no guessed thresholds, no inferred causes. If the department has not
   set a target, nothing is "not met".
3. **The past does not move.** Targets have history, reports are frozen snapshots, renames keep codes, switch-offs keep
   records. Changing something today never rewrites last month.
4. **No patient data, ever.** Counts and operational facts only. This is enforced by the schema (no such columns), by
   length caps on free text, and by the screens saying so.
5. **It degrades, it does not break.** A missing table, a missing column, a down email provider or a failing
   sub-query makes one part quiet. The rest keeps working.

## 2. Layers

```
HTTP route (index.js)       guard → validate → load → call rule → write → respond      (thin)
   │
Pure rules (*.js)           ops-room.js · comms.js · outlook.js · narrative.js · notify.js
   │                        no database, no network, no clock (today/now passed in) → fully unit-tested
Data helpers (index.js)     opsLoadUnits · opsCatalog (30 s cache) · opsIndicatorData · opsSoft / opsSoftOrNull /
   │                        opsCompat · opsOwned · commsOncall · notifyEnqueue
Postgres (Supabase)         tables with CHECK constraints · unique indexes for "one per…" · RLS on · audit trigger
```

Rule of thumb: **if it decides something, it is a pure function with a test.** Routes only move data in and out.

| Module | Decides |
|---|---|
| `ops-room.js` | roster rules, resource events, measures + breakdowns, incidents, interconsultas (+ calls), indicators + target in force, catalogues, report engine, unit pulse |
| `comms.js` | posts, audience, follow-ups, meetings + agenda times, Parte del día, share text, event files, public event fields, private-message recipients, "Hoy para ti" |
| `outlook.js` | next-weeks signals from the plan + trends against set targets |
| `narrative.js` | report "in plain words" |
| `notify.js` | who may get which email, test-mode routing, signed unsubscribe, email bodies, digest |
| `jobs.js` | daily job windows, run lock + retry rules, admin summary, TTL cache |
| `health.js` | status panel checks, error-log scrubbing + throttle + grouping, backup tables and paths |
| `imports.js` | CSV/feed parsing, patient-column guard, key → measure plan, manual-kept rule, checksum |

## 3. Data model rules

- **Codes are fixed, labels are editable** (`ops_catalog_items`). Records store codes. Items used by logic are `locked`.
- **One per…** is a unique index, not application logic: one active roster row per person and unit, one measurement per
  type and day, one report per scope, unit, period and start, one brief per date, one outbox email per dedupe key, and
  one message copy per recipient.
- **History instead of overwrite:** `ops_targets` (valid_from), `ops_reports` (frozen content), `comm_daily_briefs.snapshot`.
  The target in force for a period is the one valid on its **last day** (`targetAt`).
- **Soft delete** (`deleted_at`) everywhere people delete; permanent delete is head of department / admin only. The
  audit trigger keeps everything.
- **Counts only:** breakdowns are one list per measure (condition × age × sex are never crossed), and absence
  *reasons* never leave the absences module.
- **Every new table:** `enable row level security` + `fn_audit_trigger`. The API uses the service role, so RLS with no
  policies means *deny everyone else* (a leaked anon key reads nothing).

## 4. API rules

- **Guard first, by capability:** `Portfolio.read/write('training_units')` for units, `opsAdmin` for department-wide,
  `COMMS_PERMS` for communication. "Author, owner or organiser may change their own" is checked in the handler.
- **The URL decides scope:** `/api/ops/units/:unitId/...` and `opsOwned(table, id, unitId)` checks the row belongs to
  that unit. Never trust an id in the body to pick the unit.
- **Validate in the pure layer:** routes call `validateX(body, { partial, categories, today })` and return its
  `{ error }` as 400. Unknown fields are dropped. Every string is capped.
- **Writes never wait on side effects:** notifications go through `notifySafe(...)` into the outbox, so a broken
  provider cannot fail a save.
- **Pre-migration safety:** `opsSoft` (missing table → empty), `opsSoftOrNull` (→ null, "not migrated"),
  `opsCompat` (missing column → retry with older columns). New routes answer `409 "needs the X database update"`
  rather than 500.
- **Public endpoints** (`/api/public/...`) use `publicApiLimiterGuarded`, return only whitelisted fields (`publicEvent`),
  and answer 404 for anything not public, so internal items look missing.
- **Files** live in the private bucket and are served through 1-hour signed links. Type *and* content are checked.
  No SVG.

## 5. Background work

- **Outbox pattern** (`notif_outbox`): enqueue with a dedupe key → a 60-second sender *claims* a row
  (`queued → sending` with a conditional update) → sends → `sent` or retries with backoff (1, 5, 15, 60, 240 min, 5 tries)
  → anything older than 24 h is `skipped`. This is safe with more than one server instance.
- **One scheduler** (`jobsTick`, every 60 s; rules in `jobs.js`). Nothing else starts its own interval.

  | Job | When (Madrid) | Logged | What |
  |---|---|---|---|
  | `email_send` | every minute | no | sends the outbox |
  | `digest` | daily, window 07:00–12:00 | yes | the morning email |
  | `reports` | daily, window 06:00–23:00 | yes | last complete week + month for the department and every Ops unit |
  | `cache_warm` | every 5 min | no | recomputes Grounded and the 8-week Outlook |
| `backup` | daily, window 02:00–06:00 | yes | Ops + Comms tables → gzipped JSON in the private `backups` bucket; keeps 30 days; prunes the error log to 90 days |

- **Run log and lock** (`job_runs`, JB-1): a daily job *claims* `job:YYYY-MM-DD` by inserting a row; the unique
  `run_key` means only one server instance runs it. `ok` blocks for the day; a `running` row older than 30 min is treated
  as a crashed instance; a failure is renamed (`…#f<ms>`) so the key is free and retried after 15 min, at most 3 times.
  Without the table it falls back to an in-memory lock (one instance only).
- **Admin:** `GET /api/admin/jobs` (state per job today: ok / waiting / running / late / failed, last 30 runs) and
  `POST /api/admin/jobs/:job/run` (run now; e-mail dedupe keys still stop duplicates).
- **Lazy snapshots stay** as a safety net: Informes still creates a missing report on open.
- **Atomic multi-step writes** are Postgres functions called with `opsRpc(name, args)`: `comms_send_message`
  (message + every recipient copy), `comms_send_brief` (feed post + frozen brief), `ops_store_report` (one upsert).
  `opsRpc` returns `{ missing: true }` when the function is not created yet, and the route then uses its previous path.
  New multi-step writes should follow the same pattern.
- **Cache:** `opsCache.get(key, ttl, fn)` (in-process, shares in-flight work, keeps the old value if a refresh fails).
  Grounded 2 min, Outlook 5 min; both answer `as_of` + `cached`; `?fresh=1` recomputes; sending the Parte busts Grounded.
  Cache only department-wide data that does not depend on who asks.

## 6. Time

- Periods are Monday–Sunday weeks and calendar months. A period is judged with the target in force on its last day; an
  interconsulta is judged with the target in force on the day it was received.
- **"Today" is always the Madrid date:** `opsToday()` (Intl, `Europe/Madrid`). Fixed in JB-1 for every caller in
  `index.js`, including on-call, absences and announcements (it used to be the UTC date, so 00:00–02:00 was "yesterday").
  Never write `formatDate(new Date())` or `toISOString().slice(0,10)` for "today".
- Jobs and the digest use `madridNow()` (date + hour). Timestamps are stored in UTC (`timestamptz`).

## 7. Testing

| Layer | How | Where |
|---|---|---|
| Pure rules | `node --test`, real inputs → exact outputs | `tests/ops-room*.test.cjs`, `comms`, `outlook`, `narrative`, `notify` |
| Routes and guards | structural assertions on `index.js` (guard present, scope check present) | same files |
| Boot | load `index.js` with dummy env until `listen` | `tests/boot-smoke.cjs` |
| Screens | in-DOM template compile + headless render at 1280 and 390 px | frontend `tests/` + render harness |

**Missing:** integration tests against a real Postgres (migrations applied, routes called, rows checked). The structural
tests prove a guard *is written*, not that it *works*. See §8.

## 8. Where it is weak today (honest list, in order of risk)

1. **Permissions are three systems** (`Portfolio`, `opsAdmin`, `COMMS_PERMS`) and mostly mean "Communications create"
   or "Units write". There is no role matrix for jefe / coordinador / adjunto / residente, and committed `.env` keys still
   need rotating.
2. **No integration tests and manual migrations.** SQL is run by hand in the SQL editor. Nothing proves the database
   matches the code, and a forgotten file fails quietly (thanks to the compat helpers).
3. **One 10,600-line `index.js` with 340 routes.** The three multi-step writes are now transactions (JB-1); other legacy
   modules still write step by step.
4. **Jobs still run inside the web process.** JB-1 gives one scheduler, a run log and a lock, but if Railway sleeps the
   process, jobs wait until it wakes (the admin view shows them as *late*).
5. **The cache is per instance** (fine for one instance; with several, each warms its own).
6. ~~UTC "today"~~ fixed in JB-1.
7. ~~All activity typed by hand~~ — IM-1 imports (§10). Still to do: agree the keys and file format with hospital IT.

## 9. Checklist — adding a new Ops capability

1. **Owner:** which module owns this fact? If it already exists elsewhere, *link* to it instead.
2. **Schema:** an idempotent migration file. CHECK constraints for every enum and length, a unique index for every
   "one per…", RLS on, audit trigger. No patient fields.
3. **Rules:** pure functions in the right `*.js`, taking `today`/`now` as arguments, with tests for the edges (empty,
   past, partial, wrong unit).
4. **Route:** guard → URL scope (`opsOwned`) → validate → write → `notifySafe` for side effects. Use
   `opsSoft`/`opsCompat` so it works before the migration runs.
5. **History:** if it can change and has been reported on, keep a valid-from history or a snapshot.
6. **Screens:** status first, forms in drawers, a shareable route if it is a place people will link to, and the in-DOM
   rule (never `<` inside `{{ }}`).
7. **Docs:** add the table, the routes and the migration to `OPS_ROOMS.md` §8 (or `COMMS.md`), and send the SQL to
   whoever applies it.

## 10. Imports from hospital systems (IM-1)

Hospital counts arrive as rows `key · date · value [· category]`, from a CSV upload (Configuración → Importar datos) or the
token feed. Nothing about patients ever enters: a column whose header looks like a patient identifier (NHC, nombre, DNI,
SIP, CIP, fecha de nacimiento, teléfono…) rejects the **whole** file.

| Piece | Where |
|---|---|
| Mapping `(system, external_key)` → unit measure (+ category for a measure with a breakdown) | `ops_import_mappings` |
| One row per committed file / feed call, with counts, date range, checksum | `ops_import_batches` |
| Provenance on each value: `source` (`import`/`feed`), `import_batch_id`, `import_previous` | `ops_measurements` |
| Commit and undo, each one transaction | `ops_import_commit`, `ops_import_undo` |

Rules:
1. **Preview first** (`POST /api/ops/import/preview`, no writes). Commit re-plans on the server; it never trusts a client plan.
2. **Manual wins:** a value entered by hand is never overwritten (checked in the plan *and* inside the transaction).
   Unchanged values are skipped.
3. **Once:** the checksum is over the normalised content (row order and file format do not matter), unique per system
   while committed. Re-sending the same data is a no-op (feed) or a 409 (upload).
4. **Undo** restores what each value was before the batch, or removes it if the batch created it. A value edited by hand
   since then, or replaced by a later batch, is left alone.
5. **Feed** `POST /api/feed/ops/measurements` — off (404) unless `OPS_FEED_TOKEN` is set; `Authorization: Bearer <token>`
   (constant-time check); public rate limiter; exempt from the release header and maintenance mode. Body
   `{ system, rows: [{ key, date, value, category? }] }` or `{ system, csv }`.
6. Department-wide → head of department / system admin (`opsDeptOnlyEarly`). Max 5,000 rows, 1 MB.

SQL: `migrations/2026-10-17_import_im1_mappings_batches.sql` (after OR-2 and OR-R).

## 11. Operating it (PR-1)

- **Estado del sistema** (`GET /api/admin/status`, shown first in Configuración) puts these checks in one call:
  database ping, which database updates are applied (one or more tables per update, `health.js` `MIGRATIONS`), secrets
  and email mode, today's daily jobs, the email backlog, errors in the last 24 h, the last backup, and staff without an
  account. **When you add a migration, add it to `MIGRATIONS`.**
- **Error log** (`app_errors`): a single middleware records every 5xx answer from any route, old or new (route shape
  without ids + scrubbed message). The browser reports what it shows on screen to `POST /api/public/client-errors`,
  at most 10 per page load. Messages are scrubbed of query strings, tokens, e-mails and long numbers. Rows are written
  once per fingerprint per 5 minutes, with repeats counted.
- **Backups:** nightly plus "Back up now"; restore with `scripts/restore-backup.js` (dry run by default, upsert by id,
  never deletes). Drill: frontend `PILOT.md` §4. **When you add a table that holds Ops or Comms records, add it to
  `BACKUP_TABLES`** (parents before children).
