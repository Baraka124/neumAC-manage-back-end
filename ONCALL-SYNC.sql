-- Apply before the Phase 5.3K backend. No existing assignments are changed.
BEGIN;
ALTER TABLE public.oncall_schedule ADD COLUMN IF NOT EXISTS resident_physician_id uuid REFERENCES public.medical_staff(id);
ALTER TABLE public.oncall_schedule ADD COLUMN IF NOT EXISTS sync_source jsonb;
ALTER TABLE public.oncall_schedule ADD COLUMN IF NOT EXISTS sync_key text;
CREATE UNIQUE INDEX IF NOT EXISTS oncall_schedule_sync_key_unique ON public.oncall_schedule(sync_key) WHERE sync_key IS NOT NULL;
COMMIT;
