-- neumDesk V46.14 · Current cumulative migration through Phase 5.3D
-- Stable deployment filename: MIGRATION.sql
-- Phase 5.3D adds no new schema; this stable file retains the cumulative 5.3B/5.3C identity + authority migration.
-- This migration is additive/idempotent where practical and never deletes user identities.

BEGIN;

-- ─────────────────────────────────────────────────────────────────────────────
-- 1. Account lifecycle
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE app_users
  ADD COLUMN IF NOT EXISTS invited_at timestamptz,
  ADD COLUMN IF NOT EXISTS invited_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS invitation_token_hash text,
  ADD COLUMN IF NOT EXISTS invitation_expires_at timestamptz,
  ADD COLUMN IF NOT EXISTS activated_at timestamptz,
  ADD COLUMN IF NOT EXISTS suspended_at timestamptz,
  ADD COLUMN IF NOT EXISTS suspended_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS locked_at timestamptz,
  ADD COLUMN IF NOT EXISTS locked_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS archived_at timestamptz,
  ADD COLUMN IF NOT EXISTS archived_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS lifecycle_reason text,
  ADD COLUMN IF NOT EXISTS last_login_at timestamptz,
  ADD COLUMN IF NOT EXISTS auth_version integer NOT NULL DEFAULT 1;

-- Preserve historical identity rows. The previous "inactive" state becomes
-- "archived"; nothing is physically deleted and no historical timestamp is
-- invented for legacy rows.
ALTER TABLE app_users DROP CONSTRAINT IF EXISTS app_users_account_status_check;
UPDATE app_users SET account_status = 'archived' WHERE account_status = 'inactive';
ALTER TABLE app_users
  ALTER COLUMN account_status SET DEFAULT 'active';
ALTER TABLE app_users
  ADD CONSTRAINT app_users_account_status_check
  CHECK (account_status IN ('invited','active','suspended','locked','archived'));

-- Existing deployments may predate auth_version. Normalize only the version,
-- not lifecycle timestamps whose historical values are unknown.
UPDATE app_users SET auth_version = 1 WHERE auth_version IS NULL OR auth_version < 1;
ALTER TABLE app_users ADD CONSTRAINT app_users_auth_version_positive CHECK (auth_version >= 1);

-- ─────────────────────────────────────────────────────────────────────────────
-- 2. Identity invariants
-- ─────────────────────────────────────────────────────────────────────────────

-- A professional staff profile represents one person and may be linked to at
-- most one neumDesk login identity. Re-activation reuses that identity; admins
-- must not create a second account for an archived person.
DO $$
BEGIN
  IF EXISTS (
    SELECT medical_staff_id
    FROM app_users
    WHERE medical_staff_id IS NOT NULL
    GROUP BY medical_staff_id
    HAVING count(*) > 1
  ) THEN
    RAISE EXCEPTION 'Phase 5.3B cannot enforce one-account-per-staff: duplicate medical_staff_id links exist in app_users. Reconcile them before rerunning MIGRATION.sql.';
  END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS app_users_one_identity_per_staff_uidx
  ON app_users (medical_staff_id)
  WHERE medical_staff_id IS NOT NULL;

-- Login email is an identity key and must be unique regardless of case.
DO $$
BEGIN
  IF EXISTS (
    SELECT lower(email)
    FROM app_users
    GROUP BY lower(email)
    HAVING count(*) > 1
  ) THEN
    RAISE EXCEPTION 'Phase 5.3B cannot enforce case-insensitive email uniqueness: duplicate app_users emails differ only by case. Reconcile them before rerunning MIGRATION.sql.';
  END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS app_users_email_lower_uidx
  ON app_users (lower(email));

CREATE INDEX IF NOT EXISTS app_users_account_status_idx ON app_users(account_status);
CREATE INDEX IF NOT EXISTS app_users_medical_staff_idx ON app_users(medical_staff_id);

-- ─────────────────────────────────────────────────────────────────────────────
-- 3. Identity lifecycle audit
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS identity_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_user_id uuid REFERENCES app_users(id) ON DELETE SET NULL,
  subject_user_id uuid REFERENCES app_users(id) ON DELETE SET NULL,
  event_type text NOT NULL,
  reason text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS identity_events_subject_created_idx
  ON identity_events(subject_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS identity_events_actor_created_idx
  ON identity_events(actor_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS identity_events_type_created_idx
  ON identity_events(event_type, created_at DESC);


-- ─────────────────────────────────────────────────────────────────────────────
-- 4. Dynamic authority overrides (Phase 5.3C)
-- ─────────────────────────────────────────────────────────────────────────────
-- Role defaults live in backend authority.js. This table stores only deliberate
-- per-user deviations from those defaults. Explicit deny overrides win over
-- role defaults and explicit allows. Existing user_permissions remains intact
-- as a temporary compatibility bridge for routes not yet migrated.

CREATE TABLE IF NOT EXISTS authority_overrides (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
  permission_key text NOT NULL,
  effect text NOT NULL CHECK (effect IN ('allow','deny')),
  scope text NOT NULL CHECK (scope IN ('own','supervisees','unit','department','all')),
  visibility text NOT NULL DEFAULT 'full' CHECK (visibility IN ('summary','operational','full')),
  reason text NOT NULL,
  granted_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, permission_key, scope)
);

CREATE INDEX IF NOT EXISTS authority_overrides_user_idx
  ON authority_overrides(user_id);
CREATE INDEX IF NOT EXISTS authority_overrides_permission_idx
  ON authority_overrides(permission_key);
CREATE INDEX IF NOT EXISTS authority_overrides_expires_idx
  ON authority_overrides(expires_at)
  WHERE expires_at IS NOT NULL;

COMMENT ON TABLE authority_overrides IS
  'Per-user authority exceptions. Role defaults remain in backend policy code; explicit deny wins.';

COMMIT;
