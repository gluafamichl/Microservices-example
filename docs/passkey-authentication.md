# Passkey-Authentifizierung (WebAuthn/FIDO2)

> Status: planned — tracked in issue #1

Dieses Dokument beschreibt die geplante Implementierung der Passkey-Authentifizierung als Alternative zum Passwort-Login.

## Überblick

Nutzer können sich über einen Hardware-Security-Key, Face ID oder Touch ID anmelden, ohne ein Passwort eingeben zu müssen. Das Passwort-Login bleibt als Fallback erhalten.

## Geplante Änderungen

### Proto (`proto/user/v1/user.proto`)

Neue RPCs im `user.v1`-Service:

```protobuf
// Registrierung
rpc PasskeyRegistrationBegin(PasskeyRegistrationBeginRequest) returns (PasskeyRegistrationBeginResponse);
rpc PasskeyRegistrationFinish(PasskeyRegistrationFinishRequest) returns (PasskeyRegistrationFinishResponse);

// Authentifizierung
rpc PasskeyAuthenticationBegin(PasskeyAuthenticationBeginRequest) returns (PasskeyAuthenticationBeginResponse);
rpc PasskeyAuthenticationFinish(PasskeyAuthenticationFinishRequest) returns (PasskeyAuthenticationFinishResponse);

// Verwaltung
rpc ListPasskeys(ListPasskeysRequest) returns (ListPasskeysResponse);
rpc DeletePasskey(DeletePasskeyRequest) returns (google.protobuf.Empty);
```

### Datenbank (`services/users/migrations/`)

Neue Tabelle `passkey_credentials`:

```sql
CREATE TABLE passkey_credentials (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL UNIQUE,
    public_key    BYTEA NOT NULL,
    sign_count    BIGINT NOT NULL DEFAULT 0,
    transports    TEXT[] NOT NULL DEFAULT '{}',
    name          TEXT NOT NULL DEFAULT 'Passkey',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### Go-Abhängigkeiten

- [`github.com/go-webauthn/webauthn`](https://github.com/go-webauthn/webauthn) — WebAuthn-Library für den Server

### Gateway (`services/gateway/src/`)

Neue SvelteKit-Routen:
- `POST /api/passkey/register/begin`
- `POST /api/passkey/register/finish`
- `POST /api/passkey/authenticate/begin`
- `POST /api/passkey/authenticate/finish`

Browser-seitig: [`@simplewebauthn/browser`](https://simplewebauthn.dev/)

## Sicherheitshinweise

- Challenges sind kurzlebig (TTL ~5 min, In-Memory-Cache im `users`-Service)
- `RelyingPartyID` und `RelyingPartyOrigin` müssen konfigurierbar sein (Env-Vars)
- Passkey-Authentifizierung mündet in denselben Access/Refresh-Token-Flow wie Passwort-Login
- Keine Änderung am bestehenden `authn`-Platform-Package erforderlich
