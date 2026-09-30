# Backend recovery — 28 September 2026

This package is backend-only. index.js and package.json are at the archive root. It includes every local runtime module required by index.js, plus package-lock.json for the dependencies used in the startup check.

## Existing Railway deployment
1. Replace the backend repository runtime files with this archive's contents, including access.js, portfolio.js, identity.js and test-sessions.js. Preserve your existing environment variables and persistent uploads.
2. Install with `npm ci`; start with `npm start`. Startup was checked on Node 24.19.0.
3. Keep SUPABASE_URL, SUPABASE_SERVICE_KEY (or SUPABASE_SERVICE_ROLE_KEY), and JWT_SECRET unchanged.
4. Ensure ALLOWED_ORIGINS includes https://desk.neumact.org. The existing source defaults do not include that subdomain. Preserve any additional origins you use.
5. Set APP_URL to your actual frontend URL for account links. Preserve your existing email and identity feature configuration.
6. Check `/health`, then deploy the paired frontend and test sign-in.

## Local run
Copy .env.example to .env and insert your existing configuration. For a separate test database, use its credentials instead. Use APP_URL=http://localhost:8080 and include http://localhost:8080 in ALLOWED_ORIGINS. Run `npm ci`, then `npm start` from this directory. API: http://localhost:3000.

No new database migration is introduced by this recovery. SQL scripts are not included in this runnable package; do not roll back your database. Existing database schema compatibility and real account/email behavior have not been verified here.

Source: runtime files match backend commit 6fa7cad8e29e556eba36e90b67056354bfc18de7. New packaging files are this guide, .env.example, package-lock.json and CHECKSUMS.sha256. Unshipped Phase 5.3F changes are excluded.

Checks: every packaged JavaScript file passed syntax checking; every local require resolves; actual server starts; GET /health returns 200; configured frontend-origin CORS succeeds; unauthenticated /api/auth/me and /api/identity/users return 401. Startup checks used dummy configuration pointed at an unreachable local database, so no live data was accessed.
