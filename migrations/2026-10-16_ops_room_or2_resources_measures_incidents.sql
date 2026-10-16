-- Pneumo Ops Room OR-2: resources (+ events), measures (activity flows and pending stocks), incidents.
-- Idempotent. No patient data: counts and operational facts only.

-- 1. Resources: rooms, beds, devices of a unit, with current state.
create table if not exists public.ops_resources (
  id uuid primary key default gen_random_uuid(),
  unit_id uuid not null references public.training_units(id) on delete cascade,
  kind text not null check (kind in ('room','bed','device')),
  name text not null check (length(name) between 1 and 120),
  identifier text check (identifier is null or length(identifier) <= 80),
  location text check (location is null or length(location) <= 120),
  status text not null default 'available' check (status in ('available','in_use','out_of_service','maintenance','lent')),
  calibration_interval_days int check (calibration_interval_days is null or calibration_interval_days between 1 and 3650),
  last_calibrated_on date,
  next_calibration_due date,
  loan_due_back date,
  notes text check (notes is null or length(notes) <= 500),
  created_by uuid, created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  deleted_at timestamptz
);
create index if not exists ops_resources_unit on public.ops_resources(unit_id) where deleted_at is null;

-- 2. Resource history: every status change, calibration, maintenance, loan and return.
create table if not exists public.ops_resource_events (
  id uuid primary key default gen_random_uuid(),
  resource_id uuid not null references public.ops_resources(id) on delete cascade,
  unit_id uuid not null references public.training_units(id) on delete cascade,
  event_type text not null check (event_type in ('created','status','calibration','maintenance','loan_out','loan_return','note')),
  from_status text, to_status text,
  event_on date not null default current_date,
  due_on date,
  note text check (note is null or length(note) <= 500),
  actor_id uuid, created_at timestamptz not null default now()
);
create index if not exists ops_resource_events_res on public.ops_resource_events(resource_id, created_at desc);

-- 3. Measure types: each unit's own catalogue. flow = activity counted per day (¿Qué hemos hecho?);
--    stock = a point-in-time count such as a waiting list (¿Qué está pendiente?).
create table if not exists public.ops_measure_types (
  id uuid primary key default gen_random_uuid(),
  unit_id uuid not null references public.training_units(id) on delete cascade,
  code text not null check (code ~ '^[a-z0-9_]{2,40}$'),
  label text not null check (length(label) between 1 and 80),
  kind text not null check (kind in ('flow','stock')),
  sort int not null default 0,
  active boolean not null default true,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  unique (unit_id, code)
);

-- 4. Measurements: one value per type and date, with source and who entered it.
create table if not exists public.ops_measurements (
  id uuid primary key default gen_random_uuid(),
  unit_id uuid not null references public.training_units(id) on delete cascade,
  type_id uuid not null references public.ops_measure_types(id) on delete cascade,
  measured_on date not null,
  value int not null check (value between 0 and 100000),
  oldest_pending_on date,
  source text not null default 'manual' check (source in ('manual','import','feed')),
  entered_by uuid, created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  unique (type_id, measured_on)
);
create index if not exists ops_measurements_unit_date on public.ops_measurements(unit_id, measured_on desc);

-- 5. Incidents: what went wrong, who owns it, when it was resolved.
create table if not exists public.ops_incidents (
  id uuid primary key default gen_random_uuid(),
  unit_id uuid not null references public.training_units(id) on delete cascade,
  resource_id uuid references public.ops_resources(id) on delete set null,
  category text not null check (category in ('equipment','room','cancellation','staffing','supplies','other')),
  title text not null check (length(title) between 3 and 140),
  details text check (details is null or length(details) <= 500),
  status text not null default 'open' check (status in ('open','in_progress','resolved')),
  owner_id uuid references public.medical_staff(id) on delete set null,
  opened_on date not null default current_date,
  resolved_on date,
  resolution text check (resolution is null or length(resolution) <= 500),
  created_by uuid, created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  deleted_at timestamptz,
  check (resolved_on is null or resolved_on >= opened_on)
);
create index if not exists ops_incidents_unit on public.ops_incidents(unit_id, status) where deleted_at is null;

-- RLS on (the API uses the service role; no direct client access) + audit trail on every table.
alter table public.ops_resources enable row level security;
alter table public.ops_resource_events enable row level security;
alter table public.ops_measure_types enable row level security;
alter table public.ops_measurements enable row level security;
alter table public.ops_incidents enable row level security;
do $$ declare t text; begin
  foreach t in array array['ops_resources','ops_resource_events','ops_measure_types','ops_measurements','ops_incidents'] loop
    execute format('drop trigger if exists audit_%1$s on public.%1$s', t);
    execute format('create trigger audit_%1$s after insert or update or delete on public.%1$s for each row execute function fn_audit_trigger()', t);
  end loop;
end $$;

-- Starting catalogue per unit (edit later in the Ops Room). Codes are stable; labels can change.
insert into public.ops_measure_types (unit_id, code, label, kind, sort)
select u.id, v.code, v.label, v.kind, v.sort from public.training_units u
join (values
  ('PFR','espirometria','Espirometrías','flow',1),('PFR','dlco','DLCO','flow',2),('PFR','pletismografia','Pletismografías','flow',3),('PFR','test_marcha','Test de marcha 6 min','flow',4),('PFR','lista_espera','Lista de espera','stock',10),
  ('SUEÑO','poligrafia','Poligrafías','flow',1),('SUEÑO','polisomnografia','Polisomnografías','flow',2),('SUEÑO','pendientes_informar','Estudios pendientes de informar','stock',10),('SUEÑO','lista_espera','Lista de espera','stock',11),
  ('BFC','broncoscopia','Broncoscopias','flow',1),('BFC','ebus','EBUS','flow',2),('BFC','lista_espera','Lista de espera','stock',10),
  ('UTB','toracocentesis','Toracocentesis','flow',1),('UTB','biopsia_pleural','Biopsias pleurales','flow',2),('UTB','drenaje','Drenajes torácicos','flow',3),('UTB','lista_espera','Lista de espera','stock',10),
  ('HOSP-NEUM','ingresos','Ingresos','flow',1),('HOSP-NEUM','altas','Altas','flow',2),('HOSP-NEUM','altas_pendientes','Altas pendientes','stock',10),
  ('HOSP-NEUM-AI','ingresos','Ingresos','flow',1),('HOSP-NEUM-AI','altas','Altas','flow',2),('HOSP-NEUM-AI','altas_pendientes','Altas pendientes','stock',10),
  ('UCRI','ingresos','Ingresos','flow',1),('UCRI','dias_vmni','Días de VMNI','flow',2),
  ('CCEE','primeras','Primeras visitas','flow',1),('CCEE','sucesivas','Visitas sucesivas','flow',2),('CCEE','lista_espera','Lista de espera','stock',10),
  ('AG','visitas','Visitas','flow',1),('AG','pacientes_programa','Pacientes en programa','stock',10)
) as v(unit_code, code, label, kind, sort) on v.unit_code = u.unit_code
on conflict (unit_id, code) do nothing;
