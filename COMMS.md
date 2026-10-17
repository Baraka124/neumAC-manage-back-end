# Communication — backend notes

The plan of record and full handoff live in the frontend repo: `COMMS.md` in `Baraka124/neumAC-manage-Frontend-end`.

Backend quick map:
- Rules (pure, tested): `comms.js` (CM-2: `checkEventFile`, `publicEvent`, `monthGrid`); tests `tests/comms.test.cjs` (CI workflow "Ops Room + Communication").
- Routes: `index.js`, block `COMMUNICATION (CM-1)`, all under `/api/comms/...`. Every guard goes through `COMMS_PERMS`.
- SQL: `migrations/2026-10-17_comms_cm1_posts_actions_meetings_briefs.sql` (idempotent; run in Supabase → SQL Editor).
- Conventions: no patient data · absence reasons never in the Parte · sharing = WhatsApp text + link back (no public pages)
  · interconsultas that come in are logged once in `ops_interconsults` and linked.
- CM-2: events internal / public; banner + flyer in the private `attachments` bucket (signed 1 h links);
  public feed `GET /api/public/events[/:id]` (no sign-in, safe fields only).
- CM-3: private messages (`comm_messages` + one copy per recipient in `comm_message_recipients`); inbox at `/api/me/messages`.
