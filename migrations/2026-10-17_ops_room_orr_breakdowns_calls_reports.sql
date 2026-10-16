-- Pneumo Ops Room OR-R: clinical counts with breakdowns · calls from other departments · weekly/monthly reports.
-- Idempotent; additive. COUNTS ONLY: nothing here identifies a patient. One breakdown per measure, so
-- condition × age × sex are never crossed (no tiny combinations that could point to a person).

-- 1. Breakdown lists, editable in Configuración like the other catalogues.
alter table public.ops_catalog_items drop constraint if exists ops_catalog_items_catalog_check;
alter table public.ops_catalog_items add constraint ops_catalog_items_catalog_check check (catalog in
  ('ic_service','ic_reason','ic_priority','incident_category','roster_role','device_type','clinical_condition','age_band','sex'));

insert into public.ops_catalog_items (catalog, code, label, sort, locked) values
  ('clinical_condition','epoc_agudizado','EPOC agudizada',1,false),('clinical_condition','neumonia','Neumonía',2,false),
  ('clinical_condition','asma_agudizada','Asma agudizada',3,false),('clinical_condition','epid','EPID',4,false),
  ('clinical_condition','tep','TEP',5,false),('clinical_condition','derrame_pleural','Derrame pleural',6,false),
  ('clinical_condition','cancer_pulmon','Cáncer de pulmón',7,false),('clinical_condition','insuf_respiratoria','Insuficiencia respiratoria',8,false),
  ('clinical_condition','bronquiectasias','Bronquiectasias',9,false),('clinical_condition','neumotorax','Neumotórax',10,false),
  ('clinical_condition','otra','Otra',99,true),
  ('age_band','a_lt45','< 45 años',1,true),('age_band','a45_64','45–64 años',2,true),('age_band','a65_79','65–79 años',3,true),('age_band','a80p','≥ 80 años',4,true),
  ('sex','mujer','Mujer',1,true),('sex','hombre','Hombre',2,true),('sex','no_consta','No consta',3,true)
on conflict (catalog, code) do nothing;

-- 2. A measure may be broken down by one list; each value then stores its counts per item (value = their sum).
alter table public.ops_measure_types add column if not exists breakdown text
  check (breakdown is null or breakdown in ('clinical_condition','age_band','sex'));
alter table public.ops_measurements add column if not exists breakdown jsonb;

-- 3. Calls and in-person requests from other departments, in the same record as interconsultas.
alter table public.ops_interconsults add column if not exists channel text not null default 'formal'
  check (channel in ('formal','phone','in_person'));
alter table public.ops_interconsults add column if not exists outcome text
  check (outcome is null or outcome in ('advice','seen','converted'));
alter table public.ops_interconsults add column if not exists duration_min int
  check (duration_min is null or duration_min between 1 and 600);
create index if not exists ops_interconsults_channel on public.ops_interconsults(channel, received_at desc) where deleted_at is null;

-- 4. Reports: a fixed snapshot per unit (or the department) and per week / month.
create table if not exists public.ops_reports (
  id uuid primary key default gen_random_uuid(),
  scope text not null check (scope in ('unit','department')),
  unit_id uuid references public.training_units(id) on delete cascade,
  period text not null check (period in ('week','month')),
  period_start date not null,
  period_end date not null,
  content jsonb not null,
  generated_at timestamptz not null default now(),
  generated_by uuid,                       -- null = generated automatically on first view after the period ended
  check ((scope = 'unit') = (unit_id is not null)),
  check (period_end >= period_start)
);
create unique index if not exists ops_reports_one on public.ops_reports (scope, coalesce(unit_id, '00000000-0000-0000-0000-000000000000'::uuid), period, period_start);
create index if not exists ops_reports_list on public.ops_reports (scope, unit_id, period, period_start desc);

alter table public.ops_reports enable row level security;
drop trigger if exists audit_ops_reports on public.ops_reports;
create trigger audit_ops_reports after insert or update or delete on public.ops_reports for each row execute function fn_audit_trigger();
