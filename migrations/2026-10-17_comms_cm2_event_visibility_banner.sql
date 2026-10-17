-- Communication CM-2: programmed events (seminars, sessions…) with a banner / flyer, internal or public.
-- Run AFTER 2026-10-17_comms_cm1_posts_actions_meetings_briefs.sql. Idempotent; additive.
-- Files live in the PRIVATE `attachments` bucket and are served through short-lived signed links.
-- A public event exposes only: title, kind, date/time, place, online link, description, banner, flyer.
alter table public.comm_meetings add column if not exists visibility text not null default 'internal'
  check (visibility in ('internal','public'));
alter table public.comm_meetings add column if not exists description text
  check (description is null or length(description) <= 2000);
alter table public.comm_meetings add column if not exists banner_path text check (banner_path is null or banner_path ~ '^comms/meetings/');
alter table public.comm_meetings add column if not exists banner_alt text check (banner_alt is null or length(banner_alt) <= 160);
alter table public.comm_meetings add column if not exists flyer_path text check (flyer_path is null or flyer_path ~ '^comms/meetings/');
alter table public.comm_meetings add column if not exists flyer_name text check (flyer_name is null or length(flyer_name) <= 160);
create index if not exists comm_meetings_public on public.comm_meetings (starts_at) where deleted_at is null and visibility = 'public';
