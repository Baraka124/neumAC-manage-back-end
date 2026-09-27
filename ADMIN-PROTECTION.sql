-- Apply after IDENTITY-SETUP.sql. Protects the last usable active system administrator.
BEGIN;
CREATE OR REPLACE FUNCTION public.neumdesk_lock_admin_changes() RETURNS trigger
LANGUAGE plpgsql SET search_path=public,pg_temp AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(724691830127::bigint);
 IF TG_OP='TRUNCATE' THEN RAISE EXCEPTION 'Account truncation is disabled: retain a usable system administrator.'; END IF;
 RETURN NULL;
END $$;
CREATE OR REPLACE FUNCTION public.neumdesk_preserve_admin() RETURNS trigger
LANGUAGE plpgsql SET search_path=public,pg_temp AS $$
BEGIN
 IF OLD.user_role='system_admin' AND OLD.account_status='active' THEN
  IF TG_OP='UPDATE' THEN
   IF NEW.user_role='system_admin' AND NEW.account_status='active'
      AND NOT coalesce(NEW.password_reset_required,false)
      AND NOT coalesce(NEW.development_credentials,false)
      AND length(coalesce(NEW.password_hash,''))>0 THEN RETURN NEW; END IF;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM public.app_users u WHERE u.id<>OLD.id
     AND u.user_role='system_admin' AND u.account_status='active'
     AND NOT coalesce(u.password_reset_required,false)
     AND NOT coalesce(u.development_credentials,false)
     AND length(coalesce(u.password_hash,''))>0) THEN
   RAISE EXCEPTION 'Keep another active system administrator with a usable password before restricting this account.' USING ERRCODE='23514';
  END IF;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS neumdesk_admin_change_lock ON public.app_users;
CREATE TRIGGER neumdesk_admin_change_lock BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON public.app_users
 FOR EACH STATEMENT EXECUTE FUNCTION public.neumdesk_lock_admin_changes();
DROP TRIGGER IF EXISTS neumdesk_admin_preservation ON public.app_users;
CREATE TRIGGER neumdesk_admin_preservation BEFORE UPDATE OR DELETE ON public.app_users
 FOR EACH ROW EXECUTE FUNCTION public.neumdesk_preserve_admin();
COMMIT;
