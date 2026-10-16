-- Pneumo Ops Room OR-C (steps 1 + 2): catalogues as data + target history. Idempotent; additive.
-- Principle: codes are fixed, labels are editable; switching an item off hides it but keeps history;
-- targets carry a valid-from date and past periods are judged with the target in force then.

-- 1. Catalogues the department edits itself.
create table if not exists public.ops_catalog_items (
  id uuid primary key default gen_random_uuid(),
  catalog text not null check (catalog in ('ic_service','ic_reason','ic_priority','incident_category','roster_role','device_type')),
  code text not null check (code ~ '^[a-z0-9_]{2,40}$'),
  label text not null check (length(label) between 1 and 80),
  sort int not null default 0,
  active boolean not null default true,
  locked boolean not null default false,        -- the code is used by the system logic (cannot be switched off)
  meta jsonb not null default '{}'::jsonb,       -- e.g. device_type: {"calibration_days": 180}
  updated_by uuid, created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  unique (catalog, code)
);

insert into public.ops_catalog_items (catalog, code, label, sort, locked) values
  ('ic_priority','urgent','Urgente',1,true),('ic_priority','preferente','Preferente',2,true),('ic_priority','ordinary','Ordinaria',3,true),
  ('roster_role','coordinator','Coordinador/a',1,true),('roster_role','primary','Adjunto/a de la unidad',2,false),('roster_role','secondary','Colaborador/a',3,false),
  ('incident_category','equipment','Equipo',1,false),('incident_category','room','Sala / espacio',2,false),('incident_category','cancellation','Cancelación',3,false),
  ('incident_category','staffing','Personal',4,false),('incident_category','supplies','Material / suministros',5,false),('incident_category','other','Otro',6,true),
  ('ic_reason','disnea','Disnea',1,false),('ic_reason','insuf_resp','Insuficiencia respiratoria',2,false),('ic_reason','derrame','Derrame pleural',3,false),
  ('ic_reason','nodulo','Nódulo / masa pulmonar',4,false),('ic_reason','epoc_asma','EPOC / asma',5,false),('ic_reason','infeccion','Infección respiratoria',6,false),
  ('ic_reason','preop','Valoración preoperatoria',7,false),('ic_reason','vmni','Ventilación no invasiva',8,false),('ic_reason','hemoptisis','Hemoptisis',9,false),
  ('ic_reason','tep','TEP / circulación pulmonar',10,false),('ic_reason','intersticial','Enfermedad intersticial',11,false),('ic_reason','sueno','Trastorno respiratorio del sueño',12,false),
  ('ic_reason','otro','Otro motivo',13,true),
  ('ic_service','urgencias','Urgencias',1,false),('ic_service','medicina_interna','Medicina Interna',2,false),('ic_service','cardiologia','Cardiología',3,false),
  ('ic_service','cirugia_general','Cirugía General',4,false),('ic_service','cirugia_toracica','Cirugía Torácica',5,false),('ic_service','uci_reanimacion','UCI / Reanimación',6,false),
  ('ic_service','oncologia','Oncología',7,false),('ic_service','hematologia','Hematología',8,false),('ic_service','nefrologia','Nefrología',9,false),
  ('ic_service','neurologia','Neurología',10,false),('ic_service','digestivo','Digestivo',11,false),('ic_service','traumatologia','Traumatología',12,false),
  ('ic_service','ginecologia_y_obstetricia','Ginecología y Obstetricia',13,false),('ic_service','geriatria','Geriatría',14,false),('ic_service','infecciosas','Infecciosas',15,false),
  ('ic_service','reumatologia','Reumatología',16,false),('ic_service','endocrinologia','Endocrinología',17,false),('ic_service','urologia','Urología',18,false),
  ('ic_service','orl','ORL',19,false),('ic_service','psiquiatria','Psiquiatría',20,false),('ic_service','pediatria','Pediatría',21,false),
  ('ic_service','otro_servicio','Otro servicio',22,true),
  -- Device types: no default calibration interval is invented — each unit sets it.
  ('device_type','espirometro','Espirómetro',1,false),('device_type','pletismografo','Pletismógrafo',2,false),('device_type','equipo_dlco','Equipo de difusión (DLCO)',3,false),
  ('device_type','broncoscopio','Broncoscopio',4,false),('device_type','ebus','Ecobroncoscopio (EBUS)',5,false),('device_type','ecografo','Ecógrafo',6,false),
  ('device_type','poligrafo','Polígrafo',7,false),('device_type','polisomnografo','Polisomnógrafo',8,false),('device_type','ventilador_vmni','Ventilador VMNI',9,false),
  ('device_type','monitor','Monitor',10,false),('device_type','otro_equipo','Otro equipo',11,true)
on conflict (catalog, code) do nothing;

-- Interconsultas store the service CODE (labels can be renamed). Convert any label written before OR-C.
update public.ops_interconsults i set requesting_service = c.code
from public.ops_catalog_items c where c.catalog = 'ic_service' and c.label = i.requesting_service;

-- Lists that were fixed in the schema become catalogue-driven (validated by the API against the catalogue).
alter table public.ops_incidents drop constraint if exists ops_incidents_category_check;
alter table public.ops_incidents drop constraint if exists ops_incidents_category_code;
alter table public.ops_incidents add constraint ops_incidents_category_code check (category ~ '^[a-z0-9_]{2,40}$');
alter table public.unit_staff drop constraint if exists unit_staff_role_check;
alter table public.unit_staff drop constraint if exists unit_staff_role_code;
alter table public.unit_staff add constraint unit_staff_role_code check (role ~ '^[a-z0-9_]{2,40}$');

-- Device type on resources (its default calibration interval pre-fills new devices).
alter table public.ops_resources add column if not exists device_type text check (device_type is null or device_type ~ '^[a-z0-9_]{2,40}$');

-- 2. Target history. scope 'indicator' → ref = indicator id; scope 'ic_priority' → ref = priority code (hours).
create table if not exists public.ops_targets (
  id uuid primary key default gen_random_uuid(),
  scope text not null check (scope in ('indicator','ic_priority')),
  ref text not null check (length(ref) between 2 and 64),
  value numeric check (value is null or value >= 0),      -- null = "no target from this date"
  direction text check (direction is null or direction in ('min','max')),
  valid_from date not null,
  note text check (note is null or length(note) <= 300),
  set_by uuid, created_at timestamptz not null default now(),
  unique (scope, ref, valid_from)
);
create index if not exists ops_targets_lookup on public.ops_targets(scope, ref, valid_from desc);

-- Interconsulta response targets: the provisional values in use until now (to be confirmed by the department).
insert into public.ops_targets (scope, ref, value, valid_from, note) values
  ('ic_priority','urgent',24,'2026-01-01','Provisional — to be confirmed by the department'),
  ('ic_priority','preferente',72,'2026-01-01','Provisional — to be confirmed by the department'),
  ('ic_priority','ordinary',168,'2026-01-01','Provisional — to be confirmed by the department')
on conflict (scope, ref, valid_from) do nothing;

-- Existing indicator targets become their first history entry, valid from the month the indicator was created.
insert into public.ops_targets (scope, ref, value, direction, valid_from, note)
select 'indicator', i.id::text, i.target, i.direction, date_trunc('month', i.created_at)::date, 'Target at creation'
from public.ops_indicators i where i.target is not null
on conflict (scope, ref, valid_from) do nothing;

alter table public.ops_catalog_items enable row level security;
alter table public.ops_targets enable row level security;
do $$ declare t text; begin
  foreach t in array array['ops_catalog_items','ops_targets'] loop
    execute format('drop trigger if exists audit_%1$s on public.%1$s', t);
    execute format('create trigger audit_%1$s after insert or update or delete on public.%1$s for each row execute function fn_audit_trigger()', t);
  end loop;
end $$;
