# Release 5.3-production.1 — 30 September 2026

Baseline confirmed against the current GitHub deployment sources: frontend 813fb4c3a830f692199b56ffea653882cb2b525a; backend 1e9fa8ce57210d08e83233976fc8cb97c2057526. These match the recovery accepted by the user. Unshipped work from the older, regressed 5.3F baseline was not used.

## Delivered
1. Release protection: paired release IDs, asset cache versions, a visible release indicator, a read-only release endpoint, and rejection of authenticated writes/login from mismatched or unversioned clients. A repeatable archive-verification command and checksums accompany both packages.
2. Production credentials: system administrators can create non-administrator accounts or replace their temporary passwords without development mode or an email provider. Requires the administrator's current password and a reason. Server-generated passwords are shown once, stored only as bcrypt hashes, expire in 24 hours, invalidate previous sessions and allow only a 10-minute personal-password setup session. Setup consumption uses conditional database updates and increments session version. The initial and personal password must differ. New personal passwords in reset, invitation and change flows require at least 15 characters, with the existing 72-byte bcrypt limit retained.
3. Account design/access: the existing scoped permission editor, role controls, explanations and history are preserved, with clearer production onboarding, readiness labels, credential receipt and mobile styling. Development password configuration advice is removed from the production workspace. Development impersonation remains development-only.
4. Dates: creating an already-terminated rotation now requires an actual end date, matching the existing update rule. Missing historical dates are surfaced for review; existing records are not automatically changed.
5. Grounded: existing authority checks, previews, conflict enforcement and human confirmation are preserved. Regression checks prove unconfirmed and authority-denied writes do not execute. This release does not add a new Grounded action engine.
6–7. Conflict review/daily work: a dashboard review panel surfaces missing rotation end dates, active rotations past their planned end and today's on-call/leave overlaps (including residents), using only permission-gated records already available to the user. These are advisory checks, not exhaustive conflict analysis.
8. UI consistency: account setup, review cards and readiness checklists share typography, spacing, focus treatment and mobile behavior. This is not a redesign of every existing module.
9. Profiles: a professional-profile completeness checklist adds biography, photo, email and ORCID visibility. It does not invent publication counts or change public-profile permissions.
10. Publishing: a record-details checklist makes title, public visibility, publication state and DOI readiness inspectable beside the existing public preview and publishing controls. No public content is automatically published.

## Validation
- All packaged JavaScript syntax and local dependency/asset references verified.
- 13 production credential test scenarios, covering production availability, administrator role and password confirmation, issuance, hashing, forced setup, expiration, token-purpose separation, replay rejection, suspended accounts, account creation and rate limiting.
- Actual backend integration: startup/health, release endpoint, mismatched/unversioned sign-in rejection, matching login returning a setup-only token, protected API rejecting that token, release-header CORS.
- Browser: application mount and invitation/recovery screens; production account workspace and one-time receipt; mobile layout; personal-password setup; no setup token in browser storage. Mock APIs and test identities were used.
- Operational review tests: inclusive leave overlap, resident on-call assignment, cancelled-record exclusion, actual-end-date omissions and overdue rotations. Grounded confirmation/authority regression tests.

## Remaining scope and limits
Live database compatibility, delivery by your email provider, authenticated operational writes and the public website must be checked on your deployment. This is a production-account release with focused improvements across the other areas, not a claim that all ten broad workstreams are complete. Deeper Grounded proposal UX, comprehensive module-wide design standardisation, research/profile analytics and an expanded public publishing workflow remain further work.
