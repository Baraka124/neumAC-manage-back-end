-- PR-1: error log for the pilot (server 500s and browser errors). Idempotent.
-- No patient data: messages are scrubbed by the API (no query strings, tokens, e-mails or long numbers) and capped.
create table if not exists public.app_errors (
  id uuid primary key default gen_random_uuid(),
  source text not null check (source in ('server','browser')),
  route text check (route is null or length(route) <= 200),
  status int,
  message text not null check (length(message) <= 500),
  detail text check (detail is null or length(detail) <= 2000),
  release text check (release is null or length(release) <= 60),
  user_id uuid,
  user_agent text check (user_agent is null or length(user_agent) <= 200),
  fingerprint text not null check (length(fingerprint) <= 40),
  count int not null default 1 check (count >= 1),
  created_at timestamptz not null default now()
);
create index if not exists app_errors_recent on public.app_errors (created_at desc);
create index if not exists app_errors_fp on public.app_errors (fingerprint, created_at desc);
alter table public.app_errors enable row level security;
-- Not audited (it is itself a log). Rows older than 90 days are removed by the nightly backup job.
