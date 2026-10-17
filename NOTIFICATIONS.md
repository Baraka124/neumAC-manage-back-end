# Email notifications (NT-1) — handoff

Status (17 Oct 2026): built, **TEST MODE** — every email goes to `EMAIL_TEST_TO` (default barakaaloyce@gmail.com)
with the real recipient in the subject (`[TEST → ana@…]`). Nobody else receives anything until `EMAIL_MODE=live`.

## Who and what
- **Only registered users**: accounts (`app_users`) that are active, have an email and `notifications_enabled`.
- **Instant**: private messages (full text), urgent posts, the Parte del día when sent.
- **Daily summary 07:00 Madrid** (only if non-empty): my open follow-ups (overdue, due today, due within 3 days) and the
  agenda for today/tomorrow that concerns me.
- Each person switches kinds on/off in **Mi espacio → Email**; every email has a signed one-click unsubscribe link.
- No patient data in emails (same rule as the app); links open only that view, sign-in required.

## How it works
`notify.js` (pure rules, tested) · `index.js` block `NOTIFICATIONS (NT-1)`: hooks enqueue rows in `notif_outbox`
(dedupe key per person and item), a 60-second sender claims each row, sends through Resend, retries with backoff
(1, 5, 15, 60, 240 min; 5 attempts), and expires anything older than 24 h. Email never blocks or breaks an action.

## To make it send (Railway → Variables)
1. `RESEND_API_KEY` = a Resend API key. Without it nothing is sent (rows wait, then expire after 24 h).
2. Test mode works without a domain: the sender is `onboarding@resend.dev`, which Resend only delivers to **the Resend
   account owner's address** — create the Resend account with barakaaloyce@gmail.com.
3. To go live: verify a domain in Resend (e.g. `neumact.org`), set `EMAIL_FROM="neumDesk <neumdesk@neumact.org>"`,
   then `EMAIL_MODE=live`. Optional: `EMAIL_TEST_TO`, `PUBLIC_API_URL` (for unsubscribe links).
4. Check: Comunicación → Mensajes → "Email" panel (admins): status + "Send test email".

## Database
`migrations/2026-10-17_notify_nt1_email_outbox_prefs.sql`: `app_users.email_prefs` (jsonb) + `notif_outbox` (RLS, audit).
