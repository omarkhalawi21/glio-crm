-- ============================================================
-- GLIO CRM -- schema + RLS source of truth
--
-- Rules (same discipline as Hassad POS / HR):
--   * Append-only and numbered: new schema goes in a new numbered
--     block at the end, before the DONE marker. Never rewrite
--     earlier blocks.
--   * Fully idempotent: CREATE TABLE IF NOT EXISTS, CREATE OR
--     REPLACE, drop-then-create policies. Re-running the whole file
--     is safe.
--   * Running this file is MANUAL: paste it into the Supabase SQL
--     editor. Pushing to GitHub ships only the frontend.
--   * After running, execute the diagnostic at the bottom.
--
-- Security model: the publishable key ships in index.html; that is
-- safe ONLY because every table enforces RLS. Never weaken it.
--
-- Roles (staff.role):
--   admin  -- everything: team, delete/restore clients, backups
--   member -- add and edit clients, checklist, activity log
--   viewer -- read only
-- ============================================================

-- =============================================================
-- 0. SAFETY CHECK -- stop if this project already has unrelated
--    tables with the same names (e.g. another app's "staff").
-- =============================================================
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='staff')
     AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='staff' AND column_name='name') THEN
    RAISE EXCEPTION 'This project already has a different "staff" table. Use a new, empty Supabase project for the Glio CRM.';
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='clients')
     AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='clients' AND column_name='checklist') THEN
    RAISE EXCEPTION 'This project already has a different "clients" table. Use a new, empty Supabase project for the Glio CRM.';
  END IF;
END $$;

-- =============================================================
-- 1. STAFF + ROLE HELPERS
-- =============================================================
CREATE TABLE IF NOT EXISTS public.staff (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid unique references auth.users(id) on delete set null,
  email       text not null unique,
  name        text not null default '',
  role        text not null default 'member'
    CHECK (role IN ('admin','member','viewer')),
  active      boolean not null default true,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

CREATE OR REPLACE FUNCTION public.my_staff_id()
RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $fn$
  SELECT id FROM public.staff WHERE user_id = auth.uid() AND active LIMIT 1;
$fn$;

CREATE OR REPLACE FUNCTION public.has_role(roles text[])
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $fn$
  SELECT EXISTS (
    SELECT 1 FROM public.staff
    WHERE user_id = auth.uid() AND role = ANY(roles) AND active
  );
$fn$;

CREATE OR REPLACE FUNCTION public.is_admin()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $fn$
  SELECT public.has_role(ARRAY['admin']);
$fn$;

CREATE OR REPLACE FUNCTION public.is_member()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $fn$
  SELECT public.has_role(ARRAY['admin','member']);
$fn$;

CREATE OR REPLACE FUNCTION public.is_staff()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $fn$
  SELECT public.has_role(ARRAY['admin','member','viewer']);
$fn$;

-- Link a fresh auth.users signup to its staff row by email.
--   1. BOOTSTRAP: the very first signup on an empty staff table
--      becomes the admin (the owner must sign up first).
--   2. LINK: the admin added the email on the Team page first.
-- Unknown emails get no staff row and see nothing (RLS).
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $fn$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM public.staff) THEN
    INSERT INTO public.staff (user_id, email, name, role, active)
    VALUES (NEW.id, lower(NEW.email),
            coalesce(NEW.raw_user_meta_data->>'name',''), 'admin', true);
  ELSE
    UPDATE public.staff
       SET user_id = NEW.id,
           name = CASE WHEN name = '' THEN coalesce(NEW.raw_user_meta_data->>'name','') ELSE name END,
           updated_at = now()
     WHERE lower(email) = lower(NEW.email) AND user_id IS NULL;
  END IF;
  RETURN NEW;
END;
$fn$;
DROP TRIGGER IF EXISTS on_auth_user_created_crm ON auth.users;
CREATE TRIGGER on_auth_user_created_crm
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- Set-once user_id, lowercase email, no self role change / self lock-out.
CREATE OR REPLACE FUNCTION public.enforce_staff_rules()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $fn$
BEGIN
  NEW.email := lower(trim(NEW.email));
  IF TG_OP = 'UPDATE' THEN
    IF OLD.user_id IS NOT NULL AND NEW.user_id IS DISTINCT FROM OLD.user_id THEN
      RAISE EXCEPTION 'staff.user_id is set-once';
    END IF;
    IF OLD.user_id = auth.uid() AND NEW.role IS DISTINCT FROM OLD.role THEN
      RAISE EXCEPTION 'you cannot change your own role';
    END IF;
    IF OLD.user_id = auth.uid() AND NOT NEW.active THEN
      RAISE EXCEPTION 'you cannot deactivate yourself';
    END IF;
    NEW.updated_at := now();
  END IF;
  RETURN NEW;
END;
$fn$;
DROP TRIGGER IF EXISTS enforce_staff_rules_trigger ON public.staff;
CREATE TRIGGER enforce_staff_rules_trigger
  BEFORE INSERT OR UPDATE ON public.staff
  FOR EACH ROW EXECUTE FUNCTION public.enforce_staff_rules();

ALTER TABLE public.staff ENABLE ROW LEVEL SECURITY;
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT policyname FROM pg_policies WHERE schemaname='public' AND tablename='staff' LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON public.staff', r.policyname);
  END LOOP;
END $$;
-- A signed-in person can always read their own row (so the app can
-- tell them "not set up yet"); active staff read the whole team.
CREATE POLICY "staff_select" ON public.staff FOR SELECT TO authenticated
  USING (user_id = auth.uid() OR public.is_staff());
CREATE POLICY "staff_insert_admin" ON public.staff FOR INSERT TO authenticated
  WITH CHECK (public.is_admin());
CREATE POLICY "staff_update_admin" ON public.staff FOR UPDATE TO authenticated
  USING (public.is_admin()) WITH CHECK (public.is_admin());
CREATE POLICY "staff_delete_admin" ON public.staff FOR DELETE TO authenticated
  USING (public.is_admin() AND user_id IS DISTINCT FROM auth.uid());

-- =============================================================
-- 2. PASSWORD GUARD
--    The CRM never stores passwords. Text that looks like
--    "password: ..." is refused by the database itself, not just
--    the page.
-- =============================================================
CREATE OR REPLACE FUNCTION public.looks_like_password(t text)
RETURNS boolean LANGUAGE sql IMMUTABLE AS $fn$
  SELECT coalesce(t, '') ~* '(password|passwd|passcode|\mpass\M|\mpwd\M|\mpw\M|كلمة\s*(المرور|السر)|الباسورد|باسورد)\s*[:=：]';
$fn$;

-- =============================================================
-- 3. CLIENTS
-- =============================================================
CREATE TABLE IF NOT EXISTS public.clients (
  id                   uuid primary key default gen_random_uuid(),
  name                 text not null CHECK (length(trim(name)) > 0),
  status               text not null default 'lead'
    CHECK (status IN ('lead','onboarding','active','paused','past')),
  contact              text not null default '',
  contact_role         text not null default '',
  email                text not null default '',
  phone                text not null default '',
  website              text not null default '',
  instagram            text not null default '',
  industry             text not null default '',
  city                 text not null default '',
  store_platform       text not null default '',
  services             text[] not null default '{}',
  retainer             numeric(12,2) not null default 0 CHECK (retainer >= 0),
  start_date           date,
  renewal_date         date,
  drive_link           text not null default '',
  tags                 text[] not null default '{}',
  notes                text not null default '',
  manager_id           uuid references public.staff(id) on delete set null,
  onboarding_owner_id  uuid references public.staff(id) on delete set null,
  ads_owner_id         uuid references public.staff(id) on delete set null,
  assigned_at          jsonb not null default '{}',
  ad_platforms         text[] not null default '{}',
  ad_budget            numeric(12,2) not null default 0 CHECK (ad_budget >= 0),
  ad_goal              text not null default '',
  google_ads_id        text not null default '',
  meta_ad_account_id   text not null default '',
  tiktok_ad_account_id text not null default '',
  checklist            jsonb not null default '{}',
  access               jsonb not null default '{}',
  deleted_at           timestamptz,
  deleted_by           uuid references public.staff(id) on delete set null,
  created_by           uuid references public.staff(id) on delete set null,
  created_at           timestamptz not null default now(),
  updated_at           timestamptz not null default now(),
  last_activity        timestamptz not null default now()
);

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'clients_no_passwords') THEN
    ALTER TABLE public.clients ADD CONSTRAINT clients_no_passwords
      CHECK (NOT public.looks_like_password(notes || ' ' || access::text));
  END IF;
END $$;

-- Server-owned fields: assignment times, who created/deleted, timestamps.
-- Only admins can delete (soft) or restore a client.
CREATE OR REPLACE FUNCTION public.clients_before_write()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $fn$
DECLARE
  f text;
  newv uuid;
  oldv uuid;
BEGIN
  -- assigned_at is server-owned: ignore whatever the client sent.
  NEW.assigned_at := CASE WHEN TG_OP = 'UPDATE' THEN OLD.assigned_at ELSE '{}'::jsonb END;

  IF TG_OP = 'INSERT' THEN
    NEW.created_by  := public.my_staff_id();
    NEW.created_at  := now();
    NEW.last_activity := now();
    NEW.deleted_at  := NULL;
    NEW.deleted_by  := NULL;
  ELSE
    NEW.created_by := OLD.created_by;
    NEW.created_at := OLD.created_at;
    IF NEW.deleted_at IS DISTINCT FROM OLD.deleted_at THEN
      IF NOT public.is_admin() THEN
        RAISE EXCEPTION 'only admins can delete or restore clients';
      END IF;
      NEW.deleted_by := CASE WHEN NEW.deleted_at IS NULL THEN NULL ELSE public.my_staff_id() END;
    ELSE
      NEW.deleted_by := OLD.deleted_by;
    END IF;
  END IF;

  FOREACH f IN ARRAY ARRAY['manager_id','onboarding_owner_id','ads_owner_id'] LOOP
    newv := (to_jsonb(NEW) ->> f)::uuid;
    oldv := CASE WHEN TG_OP = 'UPDATE' THEN (to_jsonb(OLD) ->> f)::uuid ELSE NULL END;
    IF newv IS NOT NULL AND newv IS DISTINCT FROM oldv THEN
      NEW.assigned_at := NEW.assigned_at || jsonb_build_object(f, now());
    END IF;
  END LOOP;

  NEW.updated_at := now();
  RETURN NEW;
END;
$fn$;
DROP TRIGGER IF EXISTS clients_before_write_trigger ON public.clients;
CREATE TRIGGER clients_before_write_trigger
  BEFORE INSERT OR UPDATE ON public.clients
  FOR EACH ROW EXECUTE FUNCTION public.clients_before_write();

ALTER TABLE public.clients ENABLE ROW LEVEL SECURITY;
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT policyname FROM pg_policies WHERE schemaname='public' AND tablename='clients' LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON public.clients', r.policyname);
  END LOOP;
END $$;
-- Deleted clients are visible to admins only.
CREATE POLICY "clients_select" ON public.clients FOR SELECT TO authenticated
  USING (public.is_staff() AND (deleted_at IS NULL OR public.is_admin()));
CREATE POLICY "clients_insert" ON public.clients FOR INSERT TO authenticated
  WITH CHECK (public.is_member());
CREATE POLICY "clients_update" ON public.clients FOR UPDATE TO authenticated
  USING (public.is_member() AND (deleted_at IS NULL OR public.is_admin()))
  WITH CHECK (public.is_member());
CREATE POLICY "clients_delete" ON public.clients FOR DELETE TO authenticated
  USING (public.is_admin());

-- =============================================================
-- 4. ACTIVITY LOG
-- =============================================================
CREATE TABLE IF NOT EXISTS public.client_notes (
  id          uuid primary key default gen_random_uuid(),
  client_id   uuid not null references public.clients(id) on delete cascade,
  kind        text not null default 'note'
    CHECK (kind IN ('note','onboarding','ads','system')),
  body        text not null CHECK (length(trim(body)) > 0 AND length(body) <= 4000),
  author_id   uuid references public.staff(id) on delete set null,
  created_at  timestamptz not null default now()
);
CREATE INDEX IF NOT EXISTS client_notes_client_idx ON public.client_notes (client_id, created_at desc);

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'client_notes_no_passwords') THEN
    ALTER TABLE public.client_notes ADD CONSTRAINT client_notes_no_passwords
      CHECK (NOT public.looks_like_password(body));
  END IF;
END $$;

CREATE OR REPLACE FUNCTION public.client_notes_before_insert()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $fn$
BEGIN
  NEW.author_id  := public.my_staff_id();
  NEW.created_at := now();
  RETURN NEW;
END;
$fn$;
DROP TRIGGER IF EXISTS client_notes_before_insert_trigger ON public.client_notes;
CREATE TRIGGER client_notes_before_insert_trigger
  BEFORE INSERT ON public.client_notes
  FOR EACH ROW EXECUTE FUNCTION public.client_notes_before_insert();

CREATE OR REPLACE FUNCTION public.client_notes_after_insert()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $fn$
BEGIN
  UPDATE public.clients SET last_activity = now() WHERE id = NEW.client_id;
  RETURN NEW;
END;
$fn$;
DROP TRIGGER IF EXISTS client_notes_after_insert_trigger ON public.client_notes;
CREATE TRIGGER client_notes_after_insert_trigger
  AFTER INSERT ON public.client_notes
  FOR EACH ROW EXECUTE FUNCTION public.client_notes_after_insert();

-- "Client file created" entry, written by the server.
CREATE OR REPLACE FUNCTION public.clients_after_insert()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $fn$
BEGIN
  INSERT INTO public.client_notes (client_id, kind, body) VALUES (NEW.id, 'system', 'Client file created');
  RETURN NEW;
END;
$fn$;
DROP TRIGGER IF EXISTS clients_after_insert_trigger ON public.clients;
CREATE TRIGGER clients_after_insert_trigger
  AFTER INSERT ON public.clients
  FOR EACH ROW EXECUTE FUNCTION public.clients_after_insert();

ALTER TABLE public.client_notes ENABLE ROW LEVEL SECURITY;
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT policyname FROM pg_policies WHERE schemaname='public' AND tablename='client_notes' LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON public.client_notes', r.policyname);
  END LOOP;
END $$;
CREATE POLICY "client_notes_select" ON public.client_notes FOR SELECT TO authenticated
  USING (public.is_staff() AND EXISTS (SELECT 1 FROM public.clients c WHERE c.id = client_id));
-- 'system' entries are written only by the server trigger above.
CREATE POLICY "client_notes_insert" ON public.client_notes FOR INSERT TO authenticated
  WITH CHECK (public.is_member() AND kind <> 'system');
CREATE POLICY "client_notes_delete" ON public.client_notes FOR DELETE TO authenticated
  USING (kind <> 'system' AND (public.is_admin() OR (public.is_member() AND author_id = public.my_staff_id())));

-- =============================================================
-- 5. "SEEN" MARKERS (drives the "new client assigned to you" alert)
-- =============================================================
CREATE TABLE IF NOT EXISTS public.client_seen (
  staff_id   uuid not null references public.staff(id) on delete cascade,
  client_id  uuid not null references public.clients(id) on delete cascade,
  seen_at    timestamptz not null default now(),
  primary key (staff_id, client_id)
);
ALTER TABLE public.client_seen ENABLE ROW LEVEL SECURITY;
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT policyname FROM pg_policies WHERE schemaname='public' AND tablename='client_seen' LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON public.client_seen', r.policyname);
  END LOOP;
END $$;
CREATE POLICY "client_seen_own" ON public.client_seen FOR ALL TO authenticated
  USING (staff_id = public.my_staff_id())
  WITH CHECK (staff_id = public.my_staff_id());

-- =============================================================
-- 6. LIVE UPDATES (Supabase Realtime respects the RLS above)
-- =============================================================
DO $$
DECLARE t text;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime') THEN
    FOREACH t IN ARRAY ARRAY['clients','client_notes','staff'] LOOP
      IF NOT EXISTS (SELECT 1 FROM pg_publication_tables
                     WHERE pubname = 'supabase_realtime' AND schemaname = 'public' AND tablename = t) THEN
        EXECUTE format('ALTER PUBLICATION supabase_realtime ADD TABLE public.%I', t);
      END IF;
    END LOOP;
  END IF;
END $$;

-- =============================================================
-- DONE.
--
-- Diagnostic -- run after pasting; expect: tables_ok = 4,
-- policy_count = 12, password_guard = true, realtime_tables = 3.
--
--   SELECT
--     (SELECT count(*) FROM information_schema.tables WHERE table_schema='public'
--       AND table_name IN ('staff','clients','client_notes','client_seen')) AS tables_ok,
--     (SELECT count(*) FROM pg_policies WHERE schemaname='public'
--       AND tablename IN ('staff','clients','client_notes','client_seen')) AS policy_count,
--     public.looks_like_password('password: test') AS password_guard,
--     (SELECT count(*) FROM pg_publication_tables WHERE pubname='supabase_realtime'
--       AND tablename IN ('clients','client_notes','staff')) AS realtime_tables;
-- =============================================================
