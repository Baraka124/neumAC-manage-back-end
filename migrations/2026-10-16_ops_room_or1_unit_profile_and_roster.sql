-- Pneumo Ops Room OR-1: one unit identity (training_units) + operational profile + unit roster (unit_staff).
-- Additive only: no data is deleted; unit_staff was empty when this was written.
alter table public.training_units
  add column if not exists ops_enabled boolean not null default false,
  add column if not exists ops_capabilities text[] not null default '{}';

comment on column public.training_units.ops_enabled is 'Run by Pulmonology and shown in the Pneumo Ops Room.';
comment on column public.training_units.ops_capabilities is 'Ops Room capabilities switched on for this unit: roster, resources, beds, calibration, loans, activity, pending, incidents, indicators.';

update public.training_units set ops_enabled = true,
  ops_capabilities = case unit_code
    when 'HOSP-NEUM'    then array['roster','resources','beds','activity','pending','incidents','indicators']
    when 'HOSP-NEUM-AI' then array['roster','resources','beds','activity','pending','incidents','indicators']
    when 'UCRI'         then array['roster','resources','beds','activity','incidents','indicators']
    when 'BFC'          then array['roster','resources','activity','pending','incidents','indicators']
    when 'UTB'          then array['roster','resources','activity','pending','incidents','indicators']
    when 'PFR'          then array['roster','resources','calibration','activity','pending','incidents','indicators']
    when 'SUEÑO'        then array['roster','resources','loans','activity','pending','incidents','indicators']
    when 'CCEE'         then array['roster','resources','activity','pending','indicators']
    when 'AG'           then array['roster','activity','indicators']
  end
where unit_code in ('HOSP-NEUM','HOSP-NEUM-AI','UCRI','BFC','UTB','PFR','SUEÑO','CCEE','AG');

-- Unit roster = unit_staff (already linked to training_units and used by Units):
-- coordinator role · history (one ACTIVE membership per person and unit, ended ones kept) · audit trail.
alter table public.unit_staff drop constraint if exists unit_staff_role_check;
alter table public.unit_staff add constraint unit_staff_role_check check (role = any (array['coordinator','primary','secondary']));
alter table public.unit_staff drop constraint if exists unit_staff_unique_active;
create unique index if not exists unit_staff_one_active on public.unit_staff (unit_id, staff_id) where assigned_until is null;
alter table public.unit_staff add constraint unit_staff_dates_check check (assigned_until is null or assigned_from is null or assigned_until >= assigned_from);

drop trigger if exists audit_unit_staff on public.unit_staff;
create trigger audit_unit_staff after insert or delete or update on public.unit_staff for each row execute function fn_audit_trigger();
