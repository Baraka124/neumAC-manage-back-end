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
- **Lazy snapshots:** the last complete week and month reports are created the first time someone opens Informes.
  This is simple and cheap, but it means a report exists only if someone looked (see §8).
- **Daily jobs** (the 07:00 digest) run inside the same interval, guarded by date. The dedupe key stops duplicates after
  restarts.

## 6. Time

- Periods are Monday–Sunday weeks and calendar months. A period is judged with the target in force on its last day; an
  interconsulta is judged with the target in force on the day it was received.
- The digest uses Madrid time (`madridNow`).
- ⚠️ **Known bug:** `opsToday()` uses `formatDate(new Date())`, which is the **UTC** date. Between 00:00 and 02:00
  Madrid time (01:00 in winter) "today" is still yesterday. The fix is one helper (`madridNow().date`) used by every
  `opsToday()` caller, plus a test.

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
3. **One 10,600-line `index.js` with 338 routes.** Multi-step writes (message fan-out, Parte send, report store) are
   several calls with manual rollback, not one transaction.
4. **Background work lives inside the web process** (interval + lazy generation). If the process sleeps, the 07:00
   digest and reports wait. There is no single scheduler and no record of job runs.
5. **Heavy read endpoints** (`/api/ops/grounded`, the department report, the outlook) recompute everything per request
   and per server (only the catalogue is cached).
6. **The UTC "today" bug** (§6).
7. **All activity is typed by hand.** There is no import pipeline from hospital systems yet.

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
