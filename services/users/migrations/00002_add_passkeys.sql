-- +goose Up

CREATE TABLE passkey_credentials (
    id            uuid        PRIMARY KEY,
    user_id       uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id bytea       NOT NULL UNIQUE,
    public_key    bytea       NOT NULL,
    sign_count    bigint      NOT NULL DEFAULT 0,
    transports    text[]      NOT NULL DEFAULT '{}',
    name          text        NOT NULL DEFAULT 'Passkey',
    created_at    timestamptz NOT NULL
);

CREATE INDEX passkey_credentials_user_id_idx ON passkey_credentials(user_id);

-- Kurzlebige Challenges (TTL ~5 min).
-- consumed_at statt DELETE, damit Replay-Angriffe erkennbar bleiben.
CREATE TABLE passkey_challenges (
    challenge_id  text        PRIMARY KEY,
    user_id       uuid        REFERENCES users(id) ON DELETE CASCADE,
    challenge     bytea       NOT NULL,
    expires_at    timestamptz NOT NULL,
    consumed_at   timestamptz,
    created_at    timestamptz NOT NULL
);

-- +goose Down
DROP TABLE passkey_challenges;
DROP TABLE passkey_credentials;
