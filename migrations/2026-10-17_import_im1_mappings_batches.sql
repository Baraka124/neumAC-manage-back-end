-- IM-1: hospital data into Ops measures — mappings, import batches with provenance, one-transaction commit and undo.
-- Run after OR-2 and OR-R. Idempotent. Counts only: no patient columns exist anywhere in this file.

-- 1. Mappings: a hospital system's key → one unit measure (and, for a measure with a breakdown, one category of it).
create table if not exists public.ops_import_mappings (
  id uuid primary key default gen_random_uuid(),
  system text not null check (system ~ '^[a-z0-9_]{2,30}$'),
  external_key text not null check (length(external_key) between 1 and 80),
  unit_id uuid not null references public.training_units(id) on delete cascade,
  type_id uuid not null references public.ops_measure_types(id) on delete cascade,
  category_code text check (category_code is null or category_code ~ '^[a-z0-9_]{1,40}$'),
  active boolean not null default true,
  note text check (note is null or length(note) <= 200),
  created_by uuid, created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  unique (system, external_key)
);

-- 2. Batches: one row per committed file or feed call. The same content (checksum) is committed once per system.
create table if not exists public.ops_import_batches (
  id uuid primary key default gen_random_uuid(),
  system text not null check (system ~ '^[a-z0-9_]{2,30}$'),
  channel text not null check (channel in ('upload','feed')),
  filename text check (filename is null or length(filename) <= 200),
  checksum text not null check (length(checksum) = 64),
  status text not null default 'committed' check (status in ('committed','undone')),
  counts jsonb not null default '{}'::jsonb,
  range_from date, range_to date,
  created_by uuid, created_at timestamptz not null default now(),
  undone_by uuid, undone_at timestamptz
);
create unique index if not exists ops_import_batches_once on public.ops_import_batches (system, checksum) where status = 'committed';
create index if not exists ops_import_batches_recent on public.ops_import_batches (created_at desc);

-- 3. Provenance on each value: which batch wrote it, and what it replaced (for undo).
alter table public.ops_measurements add column if not exists import_batch_id uuid references public.ops_import_batches(id) on delete set null;
alter table public.ops_measurements add column if not exists import_previous jsonb;

alter table public.ops_import_mappings enable row level security;
alter table public.ops_import_batches enable row level security;
do $$ declare t text; begin
  if exists (select 1 from pg_proc where proname = 'fn_audit_trigger') then
    foreach t in array array['ops_import_mappings','ops_import_batches'] loop
      execute format('drop trigger if exists trg_audit_%1$s on public.%1$s', t);
      execute format('create trigger trg_audit_%1$s after insert or update or delete on public.%1$s for each row execute function fn_audit_trigger()', t);
    end loop;
  end if;
end $$;

-- 4. Commit: the batch and all its values in one transaction. Manual values are never touched (checked again here).
--    p_rows: [{ unit_id, type_id, measured_on, value, breakdown }]
create or replace function public.ops_import_commit(p_system text, p_channel text, p_filename text, p_checksum text, p_counts jsonb,
  p_from date, p_to date, p_user uuid, p_rows jsonb)
returns public.ops_import_batches language plpgsql as $$
declare b public.ops_import_batches; r jsonb; cur public.ops_measurements; src text := case when p_channel = 'feed' then 'feed' else 'import' end;
  ins int := 0; upd int := 0; kept int := 0;
begin
  insert into public.ops_import_batches (system, channel, filename, checksum, counts, range_from, range_to, created_by)
  values (p_system, p_channel, p_filename, p_checksum, coalesce(p_counts, '{}'::jsonb), p_from, p_to, p_user) returning * into b;
  for r in select * from jsonb_array_elements(coalesce(p_rows, '[]'::jsonb)) loop
    select * into cur from public.ops_measurements where type_id = (r->>'type_id')::uuid and measured_on = (r->>'measured_on')::date for update;
    if found then
      if cur.source = 'manual' then kept := kept + 1; continue; end if;
      update public.ops_measurements set value = (r->>'value')::int, breakdown = nullif(r->'breakdown', 'null'::jsonb), source = src,
        import_batch_id = b.id, import_previous = to_jsonb(cur), entered_by = p_user, updated_at = now() where id = cur.id;
      upd := upd + 1;
    else
      insert into public.ops_measurements (unit_id, type_id, measured_on, value, breakdown, source, import_batch_id, entered_by)
      values ((r->>'unit_id')::uuid, (r->>'type_id')::uuid, (r->>'measured_on')::date, (r->>'value')::int, nullif(r->'breakdown', 'null'::jsonb), src, b.id, p_user);
      ins := ins + 1;
    end if;
  end loop;
  update public.ops_import_batches set counts = counts || jsonb_build_object('inserted', ins, 'updated', upd, 'manual_kept_at_commit', kept) where id = b.id returning * into b;
  return b;
end $$;

-- 5. Undo: values still owned by this batch go back to what they were (or are removed if the batch created them).
--    A value someone has since edited by hand, or a later batch has replaced, is left alone.
create or replace function public.ops_import_undo(p_batch uuid, p_user uuid)
returns public.ops_import_batches language plpgsql as $$
declare b public.ops_import_batches; m public.ops_measurements; p jsonb; restored int := 0; removed int := 0;
begin
  select * into b from public.ops_import_batches where id = p_batch for update;
  if not found then raise exception 'batch not found'; end if;
  if b.status <> 'committed' then raise exception 'batch already undone'; end if;
  for m in select * from public.ops_measurements where import_batch_id = p_batch and source in ('import','feed') for update loop
    p := m.import_previous;
    if p is null then delete from public.ops_measurements where id = m.id; removed := removed + 1;
    else
      update public.ops_measurements set value = (p->>'value')::int, breakdown = nullif(p->'breakdown', 'null'::jsonb),
        oldest_pending_on = (p->>'oldest_pending_on')::date, source = p->>'source', import_batch_id = (p->>'import_batch_id')::uuid,
        import_previous = nullif(p->'import_previous', 'null'::jsonb), entered_by = (p->>'entered_by')::uuid, updated_at = now() where id = m.id;
      restored := restored + 1;
    end if;
  end loop;
  update public.ops_import_batches set status = 'undone', undone_by = p_user, undone_at = now(),
    counts = counts || jsonb_build_object('undo_restored', restored, 'undo_removed', removed) where id = p_batch returning * into b;
  return b;
end $$;

revoke all on function public.ops_import_commit(text, text, text, text, jsonb, date, date, uuid, jsonb) from public, anon, authenticated;
revoke all on function public.ops_import_undo(uuid, uuid) from public, anon, authenticated;
