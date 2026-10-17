-- Notifications NT-1: email to registered users (accounts with an email) only.
-- Every email is first written to an outbox, then sent by the server with retries; actions never wait on email.
-- Per-person preferences (on/off per kind) + one-click unsubscribe. Idempotent; additive. NO PATIENT DATA in emails.
alter table public.app_users add column if not exists email_prefs jsonb;   -- {message, urgent, parte, digest}: false = off; missing = on

create table if not exists public.notif_outbox (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.app_users(id) on delete cascade,
  to_email text not null check (length(to_email) between 3 and 320),
  kind text not null check (kind in ('message','urgent','parte','digest','test')),
  subject text not null check (length(subject) <= 200),
  html text not null,
  text_body text,
  dedupe_key text not null,                       -- one email per (user, thing): re-sends never duplicate
  status text not null default 'queued' check (status in ('queued','sending','sent','failed','skipped')),
  attempts int not null default 0,
  last_error text,
  send_after timestamptz not null default now(),
  created_at timestamptz not null default now(),
  sent_at timestamptz,
  delivered_to text                               -- the real address used (in test mode: the test inbox)
);
create unique index if not exists notif_outbox_dedupe on public.notif_outbox (dedupe_key);
create index if not exists notif_outbox_queue on public.notif_outbox (status, send_after) where status = 'queued';

alter table public.notif_outbox enable row level security;
drop trigger if exists audit_notif_outbox on public.notif_outbox;
create trigger audit_notif_outbox after insert or update or delete on public.notif_outbox for each row execute function fn_audit_trigger();
