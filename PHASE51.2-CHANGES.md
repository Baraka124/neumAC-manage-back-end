# neumDesk V46.14 — Phase 5.1.2 Rotation Intelligence Surface Hardening

## Purpose
Phase 5.1.2 hardens the presentation of temporal/data-quality findings exposed by Phase 5.0 and Phase 5.1. It does not change Decision51 policy, backend commit rules, Temporal50 semantics, permissions, or database schema.

## Changes
- Replaces the always-expanded historical-termination grid with a compact **Rotation records to review** data-quality surface.
- Data-quality review is collapsed by default so maintenance work does not displace the operational Rotations workspace.
- Header summarizes three deterministic review classes:
  - terminated-early rotations missing an explicit actual end date;
  - one-day clinical/elective rotation records;
  - rotation records whose resident relationship is absent or unresolved.
- Missing-actual-end review shows only the first three records initially, with an explicit **Show remaining N** control.
- Review rows separate Resident, Unit, Planned period and Actual end instead of placing long dates in overflowing pills.
- One-day rotations are labelled as unusual records to review, not automatically erroneous records.
- Missing resident relationships are labelled as relationship-integrity review items.
- A persistent review boundary states that findings do not prove a record is wrong and no historical state is auto-corrected.
- Tablet/mobile layouts are specifically hardened.
- Resident gap warnings and the normal Rotations table remain unchanged.

## Preservation boundary
Unchanged:
- Decision51 engine and severity/override policy;
- Phase 5.0 temporal interpreter;
- backend rotation review/commit logic;
- Supabase migrations/schema;
- Grounded action integrity;
- Access Gate 4.4 / 5.1.1 startup fix;
- global `style.css` and main Rotations table layout.

## Deployment
Frontend only. Replace:
- `app.js`
- `index.html`
- `decision51.css`

The complete Phase 5.1.2 frontend ZIP may instead be deployed as a full static frontend checkpoint.
