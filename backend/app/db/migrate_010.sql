-- MFA (TOTP) per user + data-retention bookkeeping.
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret_enc TEXT;                       -- Fernet-encrypted base32 secret
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled    BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_recovery   JSONB   NOT NULL DEFAULT '[]';   -- sha256 hashes of unused recovery codes
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_last_step  BIGINT  NOT NULL DEFAULT 0;      -- last accepted TOTP step (replay guard)
