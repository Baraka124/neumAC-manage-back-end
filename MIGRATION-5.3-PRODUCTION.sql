-- Additive migration for 5.3 production credentials. Run before deploying backend.
BEGIN;
ALTER TABLE public.app_users ADD COLUMN IF NOT EXISTS temporary_password_expires_at timestamptz;
COMMIT;
