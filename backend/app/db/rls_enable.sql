-- Row-level security (defence in depth for tenant isolation). NOT part of `migrate`: applied explicitly with
--   python -m app.cli rls-enable
-- Policy: a row is visible/writable only when its org_id equals the session setting app.org_id, which the application
-- binds on every connection checkout (app/core/db.py). The value '*' (system work: login lookup, worker, retention) sees
-- every tenant. Roles with SUPERUSER or BYPASSRLS ignore these policies by design, so the web/API process must connect
-- as a plain role (see docs/SECURITY.md "Row-level security"); migrations and the worker may keep the owner role.
DO $$
DECLARE t text;
BEGIN
  FOR t IN
    SELECT c.table_name FROM information_schema.columns c
    JOIN information_schema.tables x ON x.table_schema = c.table_schema AND x.table_name = c.table_name AND x.table_type = 'BASE TABLE'
    WHERE c.table_schema = current_schema() AND c.column_name = 'org_id'
      AND c.table_name NOT IN ('audit_log', 'organizations')
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format($p$CREATE POLICY tenant_isolation ON %I
        USING (org_id = current_setting('app.org_id', true) OR current_setting('app.org_id', true) = '*')
        WITH CHECK (org_id = current_setting('app.org_id', true) OR current_setting('app.org_id', true) = '*')$p$, t);
  END LOOP;
END $$;
