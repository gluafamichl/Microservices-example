-- +goose Up
-- Speichert webauthn.CredentialFlags (BackupEligible, BackupState, UserPresent, UserVerified)
ALTER TABLE passkey_credentials ADD COLUMN flags jsonb NOT NULL DEFAULT '{}';

-- +goose Down
ALTER TABLE passkey_credentials DROP COLUMN flags;
