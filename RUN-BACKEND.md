# Backend — 5.3-production.2

Deploy this as a matched pair with the supplied frontend.

1. In Supabase SQL Editor, run MIGRATION-5.3-PRODUCTION.sql before deploying. It adds one nullable timestamp column to app_users. It does not change passwords, accounts or existing records. Keep the existing schema and data.
2. Copy ALL backend archive files into your backend project root. Preserve your existing environment variables and persistent uploads. The archive includes all required local modules, package.json and the tested dependency lockfile.
3. Use `npm ci`, then `npm start` (startup checked on Node 24.19.0). Keep NODE_ENV=production. Do not enable development-password or test-session flags.
4. Keep SUPABASE_URL, SUPABASE_SERVICE_KEY (or SUPABASE_SERVICE_ROLE_KEY) and JWT_SECRET. Ensure ALLOWED_ORIGINS contains https://desk.neumact.org and any other actual frontend origin. APP_URL must point to the actual frontend for emailed links. No email provider is needed to issue temporary credentials; invitation/reset email still needs your existing email provider.
5. Deploy the matched frontend immediately afterwards. Old/unversioned clients cannot sign in or save authenticated changes after this backend goes live. Check /health and /api/release, then refresh the frontend.
6. Sign in as system administrator. In People & access, select a person, enter your own administrator password and a reason, and generate temporary credentials. Copy/reveal the receipt and share privately. The recipient signs in using their email and temporary password, chooses their personal password, then signs in normally. Existing personal passwords cannot be retrieved.

Before deployment: `python verify_release.py --frontend ../frontend --backend .` (adjust paths). Backend tests after npm ci: `node verification/credentials.cjs` and `node verification/integration.cjs`. They use fake identities/database responses and do not contact production.

For local use: backend on port 3000, frontend at http://localhost:8080; include that origin in ALLOWED_ORIGINS. Use a test Supabase project if you want to avoid writing to your real data.

Rollback: redeploy BOTH previous recovery packages together. The added nullable database column can remain. Accounts already issued temporary credentials still require individual password setup; use the previous email-reset flow or complete setup before rolling back. Do not remove the migration column during rollback.

Update .2: existing system-administrator passwords cannot be changed or reset within the application. Entering your current administrator password only confirms your identity. Generated user credentials now appear visibly and scroll into view. If the .1 migration was already applied, no further SQL is needed.


Milestone 10 — Audited public publishing fixes (2026-10-05)

Matched release: 5.3-production.3. Frontend baseline: Milestone 9, b56e318. Backend baseline: 88604a5. Install both matching packages. No new database migration is required for this update; existing 5.3 schema requirements still apply. Back up the installed files, replace the backend server files and restart, then upload the frontend files and refresh. During the version mismatch the existing release guard blocks writes. Rollback requires restoring both matched previous packages.

The public team endpoint now requires active, public, non-deleted staff. Its publication context requires published, public, unexpired, non-deleted records. Linked project counts include only projects flagged for website display. These corrections can reduce public results; private flags are not automatically changed.

News feature updates use a partial schema without injecting creation defaults. Feature-only updates preserve titles, status and publication dates. New records persist the selected feature flag, subject to the existing five-record check; count failures abort the write. The existing count-then-write limit is not a database-atomic concurrent quota.

Public visibility is distinguished from public-feed eligibility. Grounded and publishing messages no longer assert website delivery based solely on the public flag. The publication review shows proposed eligibility, expiry, content fields and image URLs. Metadata exposed by the public API is described separately. This is a preview of feed content, not a rendering or delivery receipt from neumact.org. Existing website refresh/caching behaviour has not been inspected or changed.

Validation: actual backend handler tests with a mock database cover public staff/publication exclusion, feature creation and partial update, limit rejection and database errors. Vue browser tests cover review eligibility, expired records, content preview, mobile controls and feature-only writes. Research and Grounded regression suites passed. Actual backend startup/integration checks preserve administrator password protections and release matching. Release verification covers hashes, JavaScript syntax, modules, assets and archive integrity. No live production reads or writes, deployment or repository push occurred.
