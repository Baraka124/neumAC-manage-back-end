# Pneumo Ops Room — backend notes

The plan of record and the full **handoff** live in the frontend repo: `OPS_ROOMS.md` (§8 "Handoff — how to continue")
in `Baraka124/neumAC-manage-Frontend-end`. Read that first.

Backend quick map:
- Rules (pure, tested): `ops-room.js` — roster, resources/events, measures, incidents, interconsultas (`IC_*`,
  provisional targets `IC_TARGET_HOURS`), indicator engine (`IND_KINDS`, `periodBounds`, `computeIndicator`).
- Routes: `index.js`, blocks `PNEUMO OPS ROOM (OR-1)`, `(OR-2)`, `(OR-2b)`, `(OR-3)`; all under `/api/ops/...`.
- SQL: `migrations/2026-10-16_ops_room_*.sql` (idempotent). Run them in Supabase → SQL Editor when the assistant
  cannot write to the database.
- Tests: `tests/ops-room*.test.cjs` + `tests/boot-smoke.cjs`; CI `.github/workflows/ops-room.yml`.
- Conventions: no patient data · rows must belong to the unit in the URL (`opsOwned`) · missing tables read as
  empty (`opsSoft`) · permanent deletes = head of department / admin · never invent targets.
