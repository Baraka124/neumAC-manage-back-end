neumDesk V46.14 — Phase 5.1.2 Rotation Intelligence Surface Hardening

FRONTEND-ONLY RELEASE.
No backend deployment and no SQL migration are required for Phase 5.1.2.

Fast patch: replace these three files:
  app.js
  index.html
  decision51.css

Or replace the complete frontend directory from this ZIP.

The new cache markers are:
  app.js?v=46.14-phase51.2-rotation-surface
  decision51.css?v=46.14-phase51.2-rotation-surface

Expected first view in Resident Rotations:
- compact collapsed "Rotation records to review" bar;
- main operational workspace remains immediately visible;
- expanding the bar shows structured historical review rows;
- no historical records are changed automatically.

Phase 5.1.1 startup-integrity behavior is preserved.
