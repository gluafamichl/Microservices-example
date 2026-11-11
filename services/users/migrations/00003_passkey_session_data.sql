-- +goose Up
ALTER TABLE passkey_challenges
    ADD COLUMN  session_data jsonb,
    DROP COLUMN challenge;

-- Backfill: existing rows get an empty session_data (they are all expired anyway)
UPDATE passkey_challenges SET session_data = '{}' WHERE session_data IS NULL;

ALTER TABLE passkey_challenges ALTER COLUMN session_data SET NOT NULL;

-- +goose Down
ALTER TABLE passkey_challenges
    ADD COLUMN  challenge bytea,
    DROP COLUMN session_data;
UPDATE passkey_challenges SET challenge = '' WHERE challenge IS NULL;
ALTER TABLE passkey_challenges ALTER COLUMN challenge SET NOT NULL;
