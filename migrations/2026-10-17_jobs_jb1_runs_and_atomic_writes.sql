-- JB-1: one scheduler with a run log, and atomic multi-step writes as Postgres functions.
-- Run after CM-1, CM-3 and OR-R. Idempotent. The API calls these with the service role; if a function is missing
-- the API falls back to its previous (non-atomic) path, so nothing breaks before this file is applied.

-- 1. Job runs: one row per scheduled run. The unique run_key is also the lock: only one server instance runs a job
--    for a given key (e.g. 'digest:2026-10-17').
create table if not exists public.job_runs (
  id uuid primary key default gen_random_uuid(),
  job text not null check (job ~ '^[a-z0-9_]{2,40}$'),
  run_key text not null unique check (length(run_key) <= 120),
  status text not null default 'running' check (status in ('running','ok','failed')),
  started_at timestamptz not null default now(),
  finished_at timestamptz,
  duration_ms int,
  detail jsonb,
  error text
);
create index if not exists job_runs_recent on public.job_runs (job, started_at desc);
alter table public.job_runs enable row level security;

-- 2. Private message: the message and every recipient copy in one transaction.
create or replace function public.comms_send_message(p_author_user uuid, p_author_staff uuid, p_author_name text, p_subject text,
  p_body text, p_audience jsonb, p_recipients uuid[])
returns public.comm_messages language plpgsql as $$
declare m public.comm_messages;
begin
  if coalesce(array_length(p_recipients, 1), 0) = 0 then raise exception 'no recipients'; end if;
  insert into public.comm_messages (author_user_id, author_staff_id, author_name, subject, body, audience, recipient_count)
  values (p_author_user, p_author_staff, p_author_name, p_subject, p_body, p_audience, array_length(p_recipients, 1))
  returning * into m;
  insert into public.comm_message_recipients (message_id, staff_id)
  select m.id, r from unnest(p_recipients) as r on conflict do nothing;
  return m;
end $$;

-- 3. Parte del día: the feed post (created or replaced) and the frozen brief in one transaction.
create or replace function public.comms_send_brief(p_date date, p_notes text, p_sections jsonb, p_snapshot jsonb,
  p_user uuid, p_user_name text, p_title text, p_content text)
returns public.comm_daily_briefs language plpgsql as $$
declare b public.comm_daily_briefs; pid uuid;
begin
  select post_id into pid from public.comm_daily_briefs where brief_date = p_date for update;
  if pid is not null then
    update public.department_announcements set title = p_title, content = p_content, updated_at = now(), deleted_at = null where id = pid;
    if not found then pid := null; end if;
  end if;
  if pid is null then
    insert into public.department_announcements (type, title, content, priority_level, brief_date, category, target_audience, visible_to_roles,
      publish_start_date, publish_end_date, created_by, created_by_name, created_at, updated_at, announcement_id)
    values ('parte', p_title, p_content, 'normal', p_date, 'organisation', 'all_staff', array['system_admin','department_head','medical_resident']::varchar[],
      p_date, p_date, p_user, p_user_name, now(), now(), 'ANN-' || substr(md5(random()::text || clock_timestamp()::text), 1, 16))
    returning id into pid;
  end if;
  insert into public.comm_daily_briefs (brief_date, notes, sections, snapshot, status, sent_at, sent_by, post_id, updated_by, updated_at)
  values (p_date, p_notes, p_sections, p_snapshot, 'sent', now(), p_user, pid, p_user, now())
  on conflict (brief_date) do update set notes = excluded.notes, sections = excluded.sections, snapshot = excluded.snapshot, status = 'sent',
    sent_at = now(), sent_by = excluded.sent_by, post_id = excluded.post_id, updated_by = excluded.updated_by, updated_at = now()
  returning * into b;
  return b;
end $$;

-- 4. Report snapshot: insert or replace in one statement (no race between two servers).
create or replace function public.ops_store_report(p_scope text, p_unit uuid, p_period text, p_start date, p_end date, p_content jsonb, p_user uuid)
returns public.ops_reports language sql as $$
  insert into public.ops_reports (scope, unit_id, period, period_start, period_end, content, generated_at, generated_by)
  values (p_scope, p_unit, p_period, p_start, p_end, p_content, now(), p_user)
  on conflict (scope, coalesce(unit_id, '00000000-0000-0000-0000-000000000000'::uuid), period, period_start)
  do update set content = excluded.content, period_end = excluded.period_end, generated_at = now(), generated_by = excluded.generated_by
  returning *;
$$;

-- Only the API (service role) may call them.
revoke all on function public.comms_send_message(uuid, uuid, text, text, text, jsonb, uuid[]) from public, anon, authenticated;
revoke all on function public.comms_send_brief(date, text, jsonb, jsonb, uuid, text, text, text) from public, anon, authenticated;
revoke all on function public.ops_store_report(text, uuid, text, date, date, jsonb, uuid) from public, anon, authenticated;
