-- Pneumo Ops Room OR-2b (interconsultas) + OR-3 (¿Cumplimos? — indicators). Idempotent; additive only.
-- No patient data: an interconsult record holds operational facts only (service, priority, times, people, status).

-- OR-2b. One record per interconsult request received by Pulmonology (department-wide service).
create table if not exists public.ops_interconsults (
  id uuid primary key default gen_random_uuid(),
  requesting_service text not null check (length(requesting_service) between 2 and 80),
  priority text not null default 'ordinary' check (priority in ('urgent','preferente','ordinary')),
  reason_category text check (reason_category is null or length(reason_category) <= 40),
  received_at timestamptz not null default now(),
  assigned_to uuid references public.medical_staff(id) on delete set null,
  assigned_at timestamptz,
  answered_at timestamptz,
  answered_by uuid references public.medical_staff(id) on delete set null,
  closed_at timestamptz,
  status text not null default 'received' check (status in ('received','assigned','answered','follow_up','closed')),
  unit_id uuid references public.training_units(id) on delete set null,
  notes text check (notes is null or length(notes) <= 300),
  created_by uuid, created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  deleted_at timestamptz,
  check (answered_at is null or answered_at >= received_at),
  check (assigned_at is null or assigned_at >= received_at)
);
create index if not exists ops_interconsults_open on public.ops_interconsults(status, received_at) where deleted_at is null;
create index if not exists ops_interconsults_received on public.ops_interconsults(received_at desc) where deleted_at is null;

-- OR-3. Indicator definitions: computed from Ops Room records (or entered by hand for 'manual').
-- unit_id null = department-wide (e.g. interconsult indicators).
create table if not exists public.ops_indicators (
  id uuid primary key default gen_random_uuid(),
  unit_id uuid references public.training_units(id) on delete cascade,
  name text not null check (length(name) between 3 and 120),
  kind text not null check (kind in ('measure_total','stock_latest','oldest_pending_days','calibration_ok_pct','incidents_open',
                                     'incident_resolution_days','interconsult_within_target_pct','interconsult_median_hours','interconsult_pending','manual')),
  params jsonb not null default '{}'::jsonb,
  period text not null default 'month' check (period in ('week','month','quarter')),
  direction text not null check (direction in ('min','max')),
  target numeric check (target is null or target >= 0),
  unit_label text check (unit_label is null or length(unit_label) <= 20),
  owner_id uuid references public.medical_staff(id) on delete set null,
  iso_clause text check (iso_clause is null or length(iso_clause) <= 40),
  notes text check (notes is null or length(notes) <= 300),
  active boolean not null default true,
  sort int not null default 0,
  created_by uuid, created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create index if not exists ops_indicators_unit on public.ops_indicators(unit_id) where active;

-- Values for 'manual' indicators only (computed kinds are derived from the records, never stored).
create table if not exists public.ops_indicator_values (
  id uuid primary key default gen_random_uuid(),
  indicator_id uuid not null references public.ops_indicators(id) on delete cascade,
  period_start date not null,
  value numeric not null check (value >= 0),
  note text check (note is null or length(note) <= 300),
  entered_by uuid, created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  unique (indicator_id, period_start)
);

alter table public.ops_interconsults enable row level security;
alter table public.ops_indicators enable row level security;
alter table public.ops_indicator_values enable row level security;
do $$ declare t text; begin
  foreach t in array array['ops_interconsults','ops_indicators','ops_indicator_values'] loop
    execute format('drop trigger if exists audit_%1$s on public.%1$s', t);
    execute format('create trigger audit_%1$s after insert or update or delete on public.%1$s for each row execute function fn_audit_trigger()', t);
  end loop;
end $$;
