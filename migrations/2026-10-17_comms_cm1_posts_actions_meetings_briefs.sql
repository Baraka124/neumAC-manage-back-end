-- Communication CM-1: what comes in from other services is briefed to the team; daily brief (Parte del día);
-- agenda for clinical sessions, seminars and service meetings; follow-ups with an owner.
-- Idempotent; additive. NO PATIENT DATA: posts, minutes and follow-ups hold counts and operational facts only.

-- 1. Lists editable in Configuración (same catalogue as the Ops Room).
alter table public.ops_catalog_items drop constraint if exists ops_catalog_items_catalog_check;
alter table public.ops_catalog_items add constraint ops_catalog_items_catalog_check check (catalog in
  ('ic_service','ic_reason','ic_priority','incident_category','roster_role','device_type','clinical_condition','age_band','sex',
   'comm_category','meeting_kind'));

insert into public.ops_catalog_items (catalog, code, label, sort, locked) values
  ('comm_category','information','Información',1,true),
  ('comm_category','admission_request','Petición de ingreso / cama',2,false),
  ('comm_category','interconsulta','Interconsulta',3,true),
  ('comm_category','instruction','Indicación de Dirección / Jefatura',4,false),
  ('comm_category','organisation','Organización del servicio',5,false),
  ('comm_category','protocol','Protocolo',6,false),
  ('comm_category','training','Formación / sesión',7,false),
  ('comm_category','recognition','Reconocimiento',8,false),
  ('comm_category','other','Otra',99,true),
  ('meeting_kind','sesion_clinica','Sesión clínica',1,false),
  ('meeting_kind','seminario','Seminario',2,false),
  ('meeting_kind','reunion_servicio','Reunión de servicio',3,false),
  ('meeting_kind','comite','Comité',4,false),
  ('meeting_kind','formacion','Formación',5,false),
  ('meeting_kind','otra','Otra',99,true)
on conflict (catalog, code) do nothing;

-- 2. Posts stay in department_announcements (one place for everything posted). New, optional fields:
--    who it came from, its category, who it concerns, and links to the record it belongs to.
alter table public.department_announcements add column if not exists source_service text check (source_service is null or length(source_service) between 2 and 80);
alter table public.department_announcements add column if not exists source_detail text check (source_detail is null or length(source_detail) <= 120);
alter table public.department_announcements add column if not exists category text check (category is null or category ~ '^[a-z0-9_]{2,40}$');
alter table public.department_announcements add column if not exists audience jsonb;          -- {all:true} | {units:[],roles:[],staff:[],oncall_today:bool}
alter table public.department_announcements add column if not exists interconsult_id uuid references public.ops_interconsults(id) on delete set null;
alter table public.department_announcements add column if not exists meeting_id uuid;          -- FK added below
alter table public.department_announcements add column if not exists brief_date date;          -- set on a sent Parte del día
alter table public.department_announcements add column if not exists deleted_at timestamptz;
create index if not exists department_announcements_recent on public.department_announcements (created_at desc) where deleted_at is null;

-- 3. Agenda: clinical sessions, seminars, service meetings — with their agenda items.
create table if not exists public.comm_meetings (
  id uuid primary key default gen_random_uuid(),
  kind text not null default 'otra' check (kind ~ '^[a-z0-9_]{2,40}$'),
  title text not null check (length(title) between 2 and 160),
  starts_at timestamptz not null,
  ends_at timestamptz,
  location text check (location is null or length(location) <= 120),
  online_url text check (online_url is null or (length(online_url) <= 300 and online_url ~* '^https://')),
  organizer_id uuid references public.medical_staff(id) on delete set null,
  audience jsonb,
  status text not null default 'planned' check (status in ('planned','held','cancelled')),
  minutes text check (minutes is null or length(minutes) <= 8000),
  materials jsonb,                                   -- [{label, url}] (https only, checked by the API)
  created_by uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  deleted_at timestamptz,
  check (ends_at is null or ends_at >= starts_at)
);
create index if not exists comm_meetings_when on public.comm_meetings (starts_at) where deleted_at is null;

create table if not exists public.comm_meeting_items (
  id uuid primary key default gen_random_uuid(),
  meeting_id uuid not null references public.comm_meetings(id) on delete cascade,
  sort int not null default 0,
  topic text not null check (length(topic) between 2 and 200),
  presenter_id uuid references public.medical_staff(id) on delete set null,
  presenter_name text check (presenter_name is null or length(presenter_name) <= 120),   -- guests from outside the service
  duration_min int check (duration_min is null or duration_min between 1 and 480),
  notes text check (notes is null or length(notes) <= 1000)
);
create index if not exists comm_meeting_items_meeting on public.comm_meeting_items (meeting_id, sort);

do $$ begin
  if not exists (select 1 from pg_constraint where conname = 'department_announcements_meeting_fk') then
    alter table public.department_announcements add constraint department_announcements_meeting_fk foreign key (meeting_id) references public.comm_meetings(id) on delete set null;
  end if;
end $$;

-- 4. Follow-ups: something someone must do, from a post or from a meeting.
create table if not exists public.comm_actions (
  id uuid primary key default gen_random_uuid(),
  text text not null check (length(text) between 2 and 300),
  owner_id uuid references public.medical_staff(id) on delete set null,
  due_on date,
  status text not null default 'open' check (status in ('open','done','cancelled')),
  done_at timestamptz,
  done_by uuid,
  post_id uuid references public.department_announcements(id) on delete cascade,
  meeting_id uuid references public.comm_meetings(id) on delete cascade,
  created_by uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  deleted_at timestamptz
);
create index if not exists comm_actions_open on public.comm_actions (status, due_on) where deleted_at is null;

-- 5. Parte del día: one per date. Built live from the records; frozen into `snapshot` when sent.
create table if not exists public.comm_daily_briefs (
  id uuid primary key default gen_random_uuid(),
  brief_date date not null unique,
  notes text check (notes is null or length(notes) <= 4000),
  sections jsonb,                                    -- which sections are included
  snapshot jsonb,                                    -- what was sent
  status text not null default 'draft' check (status in ('draft','sent')),
  sent_at timestamptz,
  sent_by uuid,
  post_id uuid references public.department_announcements(id) on delete set null,
  updated_by uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- 6. RLS (the API uses the service role) + audit on every table.
alter table public.comm_meetings enable row level security;
alter table public.comm_meeting_items enable row level security;
alter table public.comm_actions enable row level security;
alter table public.comm_daily_briefs enable row level security;
drop trigger if exists audit_comm_meetings on public.comm_meetings;
create trigger audit_comm_meetings after insert or update or delete on public.comm_meetings for each row execute function fn_audit_trigger();
drop trigger if exists audit_comm_meeting_items on public.comm_meeting_items;
create trigger audit_comm_meeting_items after insert or update or delete on public.comm_meeting_items for each row execute function fn_audit_trigger();
drop trigger if exists audit_comm_actions on public.comm_actions;
create trigger audit_comm_actions after insert or update or delete on public.comm_actions for each row execute function fn_audit_trigger();
drop trigger if exists audit_comm_daily_briefs on public.comm_daily_briefs;
create trigger audit_comm_daily_briefs after insert or update or delete on public.comm_daily_briefs for each row execute function fn_audit_trigger();
drop trigger if exists audit_department_announcements on public.department_announcements;
create trigger audit_department_announcements after insert or update or delete on public.department_announcements for each row execute function fn_audit_trigger();
