# neumDesk V46.14 — Phase 5.1 Deployment Order

Phase 5.1 depends on the Phase 5.0 Temporal Integrity schema/runtime.

## If Phase 5.0 is already deployed

1. Apply `PHASE51_DECISION_INTELLIGENCE_MIGRATION.sql` in Supabase.
2. Deploy `decision51.js` beside the backend server `index.js` (the backend uses `require('./decision51.js')`).
3. Deploy `backend-index-phase51.js` as the backend `index.js` and restart the backend.
4. Add/deploy frontend `decision51.js` and `decision51.css`.
5. Deploy Phase 5.1 `app.js`.
6. Deploy Phase 5.1 `index.html`.
7. Hard-refresh/cache-bust once and perform the live acceptance matrix in `VALIDATION-V46.14-DECISION51.md`.
8. Explicitly grant `rotation_exceptions` write permission only to roles/users who should approve operational exceptions. The migration intentionally does not guess this from job title.

## If Phase 5.0 is NOT yet deployed

Deploy Phase 5.0 first, in its documented order:

1. Phase 5.0 temporal migration.
2. Phase 5.0 backend.
3. `temporal50.js`.
4. `activity50.js`.
5. Phase 5.0 `app.js` / `index.html`.

Then follow the Phase 5.1 sequence above. Do not deploy the Phase 5.1 backend against a database that has not received the Phase 5.0 temporal columns.

## Files that remain from Phase 5.0

Phase 5.1 continues to use `temporal50.js` and `activity50.js`; they are included in the full Phase 5.1 package for completeness.

## Rollback boundary

Because the database changes are additive, the safest application rollback is to restore the Phase 5.0 frontend/backend while leaving the new decision-event table present. Do not remove Phase 5.0 actual/planned temporal columns.
