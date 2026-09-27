-- Phase 5.3I: additive migration for the existing app_users authentication system.
-- Run once before deploying the updated backend. Safe to run again.
BEGIN;
ALTER TABLE public.app_users
  ADD COLUMN IF NOT EXISTS development_credentials boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS password_reset_required boolean NOT NULL DEFAULT false;
COMMENT ON COLUMN public.app_users.development_credentials IS 'Test credential: accepted only when NODE_ENV=development and IDENTITY_DEV_PASSWORDS_ENABLED=true.';
COMMENT ON COLUMN public.app_users.password_reset_required IS 'Blocks login and authenticated requests until a single-use password reset completes.';
COMMIT;
