# Backend — 5.3-production.1

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
