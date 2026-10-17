-- Communication CM-3: private messages. One message from the head of department (or whoever is allowed) to many
-- clinicians; EACH recipient gets a private copy, read in Mi espacio. Not in the feed; recipients never see who else
-- received it. Recipients are fixed when it is sent. Run after CM-1. Idempotent; additive. NO PATIENT DATA.
create table if not exists public.comm_messages (
  id uuid primary key default gen_random_uuid(),
  author_user_id uuid not null,
  author_staff_id uuid references public.medical_staff(id) on delete set null,
  author_name text not null check (length(author_name) <= 160),
  subject text check (subject is null or length(subject) <= 120),
  body text not null check (length(body) between 2 and 4000),
  audience jsonb,                                   -- what was chosen (e.g. {"clinicians":true}); the recipients table is the truth
  recipient_count int not null default 0,
  created_at timestamptz not null default now(),
  deleted_at timestamptz                            -- withdrawn: recipients no longer see it
);
create index if not exists comm_messages_recent on public.comm_messages (created_at desc) where deleted_at is null;

create table if not exists public.comm_message_recipients (
  id uuid primary key default gen_random_uuid(),
  message_id uuid not null references public.comm_messages(id) on delete cascade,
  staff_id uuid not null references public.medical_staff(id) on delete cascade,
  read_at timestamptz,
  archived_at timestamptz,
  unique (message_id, staff_id)
);
create index if not exists comm_message_recipients_inbox on public.comm_message_recipients (staff_id, archived_at, read_at);

alter table public.comm_messages enable row level security;
alter table public.comm_message_recipients enable row level security;
drop trigger if exists audit_comm_messages on public.comm_messages;
create trigger audit_comm_messages after insert or update or delete on public.comm_messages for each row execute function fn_audit_trigger();
drop trigger if exists audit_comm_message_recipients on public.comm_message_recipients;
create trigger audit_comm_message_recipients after insert or update or delete on public.comm_message_recipients for each row execute function fn_audit_trigger();
