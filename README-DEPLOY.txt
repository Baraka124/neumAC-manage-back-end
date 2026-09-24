neumDesk V46.14 — Phase 5.1 BACKEND DEPLOYMENT BUNDLE

Server files:
- index.js          -> deploy as your backend server index.js
- decision51.js     -> place beside index.js (index.js requires ./decision51.js)

Database migrations are under migrations/.
If Phase 5.0 is NOT already applied:
  1. Apply migrations/PHASE50_TEMPORAL_INTEGRITY_MIGRATION.sql
  2. Apply migrations/PHASE51_DECISION_INTELLIGENCE_MIGRATION.sql
If Phase 5.0 IS already applied:
  - Apply only migrations/PHASE51_DECISION_INTELLIGENCE_MIGRATION.sql

Then deploy index.js + decision51.js and restart the backend.

SUPABASE_SCHEMA-PHASE51.sql is included as the current reference schema; do not execute it blindly over an existing database in place of the migrations.
