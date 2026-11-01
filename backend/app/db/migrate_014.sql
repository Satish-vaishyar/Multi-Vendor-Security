-- Migration 014: single sign-on (OIDC) identity link. Idempotent.
ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_provider TEXT NOT NULL DEFAULT 'local';
ALTER TABLE users ADD COLUMN IF NOT EXISTS sso_issuer    TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS sso_subject   TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS uq_users_sso ON users (sso_issuer, sso_subject) WHERE sso_subject IS NOT NULL;
