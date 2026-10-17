# Pneumo Ops Room — backend notes

The plan of record and the full **handoff** live in the frontend repo: `OPS_ROOMS.md` (§8 "Handoff — how to continue")
in `Baraka124/neumAC-manage-Frontend-end`. Read that first.

Backend quick map:
- Rules (pure, tested): `ops-room.js` — roster, resources/events, measures, incidents, interconsultas (`IC_*`,
  provisional targets `IC_TARGET_HOURS`), indicator engine (`IND_KINDS`, `periodBounds`, `computeIndicator`).
- Routes: `index.js`, blocks `PNEUMO OPS ROOM (OR-1)`, `(OR-2)`, `(OR-2b)`, `(OR-3)`, `(OR-C)`, `(OR-R)`; all under `/api/ops/...`.
- Configuration (OR-C): `ops_catalog_items` + `ops_targets`; loader `opsCatalog()` (30 s cache, `opsCatalogBust()` on writes);
  `targetAt()` = target in force on a date. Interconsulta targets are edited in the Ops Room (Configuración), not in code.
- Reports + clinical counts (OR-R): `buildUnitReport` / `buildDepartmentReport` / `reportPeriod` (pure); measures may
  carry ONE breakdown (`clinical_condition` | `age_band` | `sex`, catalogues) → `ops_measurements.breakdown` {code: count};
  calls from other departments live in `ops_interconsults` with `channel` phone/in_person + `outcome`, logged closed
  (`callRecord`), excluded from response times and counted by `callStats`. Snapshots in `ops_reports` (block `(OR-R)`,
  lazy generation of the last complete week/month on first open). `opsCompat()` retries without OR-R columns pre-migration.
- Interface pass: `unitPulse()` (pure) gives each unit `level` + `reasons` + activity freshness / pending / objectives;
  served as `pulse` by `opsLoadUnits` (never blocks the list).
- SQL: `migrations/2026-10-1*_ops_room_*.sql` (idempotent). Run them in Supabase → SQL Editor when the assistant
  cannot write to the database.
- Tests: `tests/ops-room*.test.cjs` + `tests/boot-smoke.cjs`; CI `.github/workflows/ops-room.yml`.
- Conventions: no patient data · rows must belong to the unit in the URL (`opsOwned`) · missing tables read as
  empty (`opsSoft`) · permanent deletes = head of department / admin · never invent targets.
- Outlook (`outlook.js`, `GET /api/ops/outlook`) and report narrative (`narrative.js`); Grounded snapshot `GET /api/ops/grounded`.
