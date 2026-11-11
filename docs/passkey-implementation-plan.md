# Implementierungsplan: Passkey-Authentifizierung (WebAuthn/FIDO2)

> Tracked in: [gluafamichl/Microservices-example#2](https://github.com/gluafamichl/Microservices-example/issues/2)
> Branch: `feat/1-passkey-authentication`
> Erstellt: 2026-11-11

---

## Architektur-Überblick

```
Registrierung (eingeloggter Nutzer)
────────────────────────────────────────────────────────────────
Browser → POST /api/passkey/register/begin
       ← {options: PublicKeyCredentialCreationOptions}
Browser → navigator.credentials.create(options)
Browser → POST /api/passkey/register/finish {credential}
       ← 200 OK + PasskeyInfo

Login (ohne Passwort)
────────────────────────────────────────────────────────────────
Browser → POST /api/passkey/authenticate/begin {username?}
       ← {options: PublicKeyCredentialRequestOptions}
Browser → navigator.credentials.get(options)
Browser → POST /api/passkey/authenticate/finish {assertion}
       ← setTokens(cookies) + redirect /
```

Jeder Gateway-Aufruf delegiert an den `users`-Service via gRPC (`PasskeyService`).
Der JWT-Issuing-Flow (`issueTokens`) bleibt unverändert – Passkey-Authentifizierung
mündet in denselben Access/Refresh-Token wie Passwort-Login.

---

## Layer 1: Proto — `proto/user/v1/user.proto`

Neuer `PasskeyService` mit 6 RPCs. Alles Bestehende bleibt unverändert (OCP).

```protobuf
// ---- Passkeys (WebAuthn) ----

message PasskeyInfo {
  string id         = 1;  // UUID der Credential-Zeile
  string name       = 2;  // Vom Nutzer vergebener Name
  google.protobuf.Timestamp created_at = 3;
}

// Registration: Begin
message PasskeyBeginRegistrationRequest {
  string user_id = 1;  // Muss dem Caller entsprechen (authn.Subject)
}
message PasskeyBeginRegistrationResponse {
  bytes options_json = 1;  // JSON: PublicKeyCredentialCreationOptionsJSON
}

// Registration: Finish
message PasskeyFinishRegistrationRequest {
  string user_id         = 1;
  bytes  credential_json = 2;  // JSON: RegistrationResponseJSON
  string name            = 3;  // Vom Nutzer vergebener Name
}
message PasskeyFinishRegistrationResponse {
  PasskeyInfo passkey = 1;
}

// Authentication: Begin (public)
message PasskeyBeginAuthenticationRequest {
  string username = 1;  // Optional: Usernameless-Flow wenn leer
}
message PasskeyBeginAuthenticationResponse {
  bytes options_json = 1;  // JSON: PublicKeyCredentialRequestOptionsJSON
}

// Authentication: Finish (public)
message PasskeyFinishAuthenticationRequest {
  bytes assertion_json = 1;  // JSON: AuthenticationResponseJSON
}
message PasskeyFinishAuthenticationResponse {
  User   user   = 1;
  Tokens tokens = 2;
}

// Management
message ListPasskeysRequest  { string user_id = 1; }
message ListPasskeysResponse { repeated PasskeyInfo passkeys = 1; }

message DeletePasskeyRequest  { string user_id = 1; string passkey_id = 2; }
message DeletePasskeyResponse {}

service PasskeyService {
  rpc PasskeyBeginRegistration (PasskeyBeginRegistrationRequest)     returns (PasskeyBeginRegistrationResponse);
  rpc PasskeyFinishRegistration(PasskeyFinishRegistrationRequest)    returns (PasskeyFinishRegistrationResponse);
  rpc PasskeyBeginAuthentication (PasskeyBeginAuthenticationRequest) returns (PasskeyBeginAuthenticationResponse);
  rpc PasskeyFinishAuthentication(PasskeyFinishAuthenticationRequest)returns (PasskeyFinishAuthenticationResponse);
  rpc ListPasskeys  (ListPasskeysRequest)   returns (ListPasskeysResponse);
  rpc DeletePasskey (DeletePasskeyRequest)  returns (DeletePasskeyResponse);
}
```

Nach Proto-Änderung: `buf generate` ausführen → `gen/go/user/v1/` und
`services/gateway/src/lib/gen/user/v1/` werden neu generiert.

---

## Layer 2: DB-Migration — `services/users/migrations/00002_add_passkeys.sql`

```sql
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
```

> **Hinweis:** Die Challenge könnte auch In-Memory (sync.Map + TTL-Cleanup) gespeichert
> werden. Die DB-Variante ist replica-safe und konsistent mit dem Projektstil.

---

## Layer 3: Domain-Typen — `services/users/internal/service/types.go`

Anhängen (nichts ändern):

```go
// PasskeyCredential ist ein gespeicherter WebAuthn-Credential.
type PasskeyCredential struct {
    ID           uuid.UUID
    UserID       uuid.UUID
    CredentialID []byte
    PublicKey    []byte
    SignCount    uint32
    Transports   []string
    Name         string
    CreatedAt    time.Time
}

// PasskeyChallenge ist eine kurzlebige serverseitige Challenge.
type PasskeyChallenge struct {
    ChallengeID string     // opaque ID, wird an den Client geschickt
    UserID      *uuid.UUID // nil beim Usernameless Authentication-Flow
    Challenge   []byte
    ExpiresAt   time.Time
    CreatedAt   time.Time
}

// Neue Sentinel-Fehler.
var (
    ErrChallengeExpired  = errors.New("passkey challenge expired or not found")
    ErrCredentialInvalid = errors.New("passkey credential verification failed")
    ErrPasskeyNotFound   = errors.New("passkey not found")
)
```

---

## Layer 4: Store-Interface — `services/users/internal/service/types.go`

Neues **separates Interface** (ISP: das bestehende `Store`-Interface bleibt unberührt):

```go
// PasskeyStore ist der Persistenz-Port für Passkey-Operationen.
// Wird von store.Store gemeinsam mit Store implementiert.
type PasskeyStore interface {
    CreatePasskeyChallenge(ctx context.Context, c PasskeyChallenge) error
    // ConsumePasskeyChallenge markiert die Challenge als verbraucht (single-use).
    // Gibt ErrChallengeExpired zurück wenn unbekannt, abgelaufen oder bereits verwendet.
    ConsumePasskeyChallenge(ctx context.Context, challengeID string, now time.Time) (PasskeyChallenge, error)

    CreatePasskeyCredential(ctx context.Context, c PasskeyCredential) error
    GetPasskeyCredentialByCredentialID(ctx context.Context, credentialID []byte) (PasskeyCredential, error)
    ListPasskeyCredentialsByUser(ctx context.Context, userID uuid.UUID) ([]PasskeyCredential, error)
    UpdatePasskeySignCount(ctx context.Context, id uuid.UUID, signCount uint32) error
    DeletePasskeyCredential(ctx context.Context, id, userID uuid.UUID) error

    // Für den Authentication-Flow: User + seine Credentials über credential_id finden.
    GetUserByPasskeyCredentialID(ctx context.Context, credentialID []byte) (User, error)
}
```

---

## Layer 5: Passkey-Service — `services/users/internal/service/passkey.go`

Neue Datei, neue Struct (SRP + OCP – `Service` wird nicht verändert):

```go
package service

// PasskeyService implementiert user.v1.PasskeyService.
type PasskeyService struct {
    userv1.UnimplementedPasskeyServiceServer

    store     PasskeyStore
    // Minimale Interfaces statt dem vollen Store (ISP + DIP):
    userStore interface {
        GetUser(ctx context.Context, id uuid.UUID) (User, error)
        GetUserByUsername(ctx context.Context, username string) (User, error)
        RecordSuccessfulLogin(ctx context.Context, id uuid.UUID, now time.Time) error
    }
    tokenStore interface {
        CreateRefreshToken(ctx context.Context, t RefreshToken) error
    }
    signer     *authn.Signer
    webauthn   WebAuthnVerifier  // Interface → testbar per Fake
    log        *slog.Logger
    now        func() time.Time
    refreshTTL time.Duration
}

// WebAuthnVerifier ist das Interface zur go-webauthn/webauthn-Library (DIP).
type WebAuthnVerifier interface {
    BeginRegistration(user webauthn.User) (*protocol.CredentialCreation, *webauthn.SessionData, error)
    FinishRegistration(user webauthn.User, session webauthn.SessionData,
        response *protocol.ParsedCredentialCreationData) (*webauthn.Credential, error)
    BeginDiscoverableLogin() (*protocol.CredentialAssertion, *webauthn.SessionData, error)
    FinishDiscoverableLogin(handler webauthn.DiscoverableUserHandler, session webauthn.SessionData,
        response *protocol.ParsedCredentialAssertionData) (*webauthn.Credential, error)
}
```

### Handler-Übersicht

| RPC | Ablauf | Auth |
|---|---|---|
| `PasskeyBeginRegistration` | Auth-Check (sub==user_id) → User laden → `BeginRegistration` → Challenge in DB → Options-JSON | Token erforderlich |
| `PasskeyFinishRegistration` | Auth-Check → Challenge konsumieren → `FinishRegistration` → Credential in DB | Token erforderlich |
| `PasskeyBeginAuthentication` | Optional Username → Credentials laden → `BeginDiscoverableLogin` → Challenge in DB | **Public** |
| `PasskeyFinishAuthentication` | Challenge konsumieren → `FinishDiscoverableLogin` → `UpdateSignCount` → `RecordSuccessfulLogin` → `issueTokens` | **Public** |
| `ListPasskeys` | Auth-Check (self or admin) → `ListPasskeyCredentialsByUser` | Token erforderlich |
| `DeletePasskey` | Auth-Check (self or admin) → `DeletePasskeyCredential` | Token erforderlich |

`issueTokens` aus `auth.go` wird **nicht dupliziert** – `PasskeyService` erhält den
`tokenStore`-Port als minimales Interface und ruft dieselbe Logik über eine geteilte
Hilfsfunktion auf.

---

## Layer 6: Store-Implementierung — `services/users/internal/store/passkey.go`

Neue Datei, neue Methoden auf `*Store` (OCP: `store.go` bleibt unberührt):

```go
package store

var _ service.PasskeyStore = (*Store)(nil)

func (s *Store) CreatePasskeyChallenge(ctx context.Context, c service.PasskeyChallenge) error {
    _, err := s.pool.Exec(ctx,
        `INSERT INTO passkey_challenges
            (challenge_id, user_id, challenge, expires_at, created_at)
         VALUES ($1, $2, $3, $4, $5)`,
        c.ChallengeID, c.UserID, c.Challenge, c.ExpiresAt, c.CreatedAt)
    return err
}

func (s *Store) ConsumePasskeyChallenge(ctx context.Context, challengeID string, now time.Time) (service.PasskeyChallenge, error) {
    // UPDATE … SET consumed_at = $2
    // WHERE challenge_id = $1 AND consumed_at IS NULL AND expires_at > $2
    // RETURNING …
    // → pgxutil.IsNotFound → ErrChallengeExpired
}

func (s *Store) CreatePasskeyCredential(ctx context.Context, c service.PasskeyCredential) error { /* INSERT */ }
func (s *Store) GetPasskeyCredentialByCredentialID(ctx context.Context, credentialID []byte) (service.PasskeyCredential, error) { /* SELECT */ }
func (s *Store) ListPasskeyCredentialsByUser(ctx context.Context, userID uuid.UUID) ([]service.PasskeyCredential, error) { /* SELECT … ORDER BY created_at */ }
func (s *Store) UpdatePasskeySignCount(ctx context.Context, id uuid.UUID, signCount uint32) error { /* UPDATE */ }
func (s *Store) DeletePasskeyCredential(ctx context.Context, id, userID uuid.UUID) error { /* DELETE WHERE id=$1 AND user_id=$2 */ }
func (s *Store) GetUserByPasskeyCredentialID(ctx context.Context, credentialID []byte) (service.User, error) {
    // SELECT userCols FROM users u
    // JOIN passkey_credentials p ON p.user_id = u.id
    // WHERE p.credential_id = $1
}
```

---

## Layer 7: Config — `services/users/internal/config/config.go`

Zwei neue Pflichtfelder:

```go
WebAuthnRPID     string  // WEBAUTHN_RP_ID,     z.B. "localhost"
WebAuthnRPOrigin string  // WEBAUTHN_RP_ORIGIN, z.B. "http://localhost:3000"
```

---

## Layer 8: Wiring — `services/users/cmd/users/main.go`

```go
// Neu in run():
wa, err := webauthn.New(&webauthn.Config{
    RPDisplayName: "Microservices App",
    RPID:          cfg.WebAuthnRPID,
    RPOrigins:     []string{cfg.WebAuthnRPOrigin},
})
if err != nil { return fmt.Errorf("webauthn config: %w", err) }

st := store.New(pool) // implementiert Store + PasskeyStore

passkeySvc := service.NewPasskeyService(service.PasskeyOptions{
    Store:      st,
    UserStore:  st,
    TokenStore: st,
    Signer:     authn.NewSigner(priv, authn.Issuer, authn.Audience, cfg.AccessTTL),
    WebAuthn:   wa,
    RefreshTTL: cfg.RefreshTTL,
    Logger:     logger,
})

// PublicMethods ergänzen:
//   userv1.PasskeyService_PasskeyBeginAuthentication_FullMethodName
//   userv1.PasskeyService_PasskeyFinishAuthentication_FullMethodName

// Registrierung:
userv1.RegisterPasskeyServiceServer(s, passkeySvc)
```

---

## Layer 9: Gateway — neue Routen

### Neue npm-Abhängigkeit

```
@simplewebauthn/browser
```

### Neue Dateien

| Datei | Verantwortung |
|---|---|
| `src/routes/api/passkey/authenticate/begin/+server.ts` | `POST` → `PasskeyBeginAuthentication`, gibt Options-JSON zurück |
| `src/routes/api/passkey/authenticate/finish/+server.ts` | `POST` → `PasskeyFinishAuthentication`, setzt Cookies via `setTokens`, redirect |
| `src/routes/api/passkey/register/begin/+server.ts` | `POST` (authenticated) → `PasskeyBeginRegistration` |
| `src/routes/api/passkey/register/finish/+server.ts` | `POST` (authenticated) → `PasskeyFinishRegistration` |
| `src/routes/(app)/account/passkeys/+page.server.ts` | `load` → `ListPasskeys`; action `delete` → `DeletePasskey` |
| `src/routes/(app)/account/passkeys/+page.svelte` | Passkey-Verwaltung (Liste + Löschen + Registrieren) |

### Erweiterung `src/routes/(auth)/login/+page.svelte`

- Button „Mit Passkey anmelden"
- Ruft `/api/passkey/authenticate/begin` auf
- Übergibt Options an `@simplewebauthn/browser → startAuthentication()`
- Sendet Assertion an `/api/passkey/authenticate/finish`

### Erweiterung `src/lib/server/clients.ts`

```typescript
import { PasskeyService } from '#lib/gen/user/v1/user_pb.js';

// In clients():
passkey: createClient(PasskeyService, transport(USERS_SERVICE_URL, accessToken))
```

---

## Abhängigkeiten

### Go — `go.mod`

```
github.com/go-webauthn/webauthn  v0.11.x
```

### npm — `services/gateway/package.json`

```
@simplewebauthn/browser  ^13.x
```

---

## Tests

### Go

| Datei | Art | Inhalt |
|---|---|---|
| `service/passkey_test.go` | Unit | Alle Handler mit Fake-Store und Fake-WebAuthnVerifier |
| `store/passkey_test.go` | Integration | Postgres-Container (wie bestehende store_test.go) |

### Gateway

- Neue Routen: happy-path und Fehlerfall (ungültige Assertion) im bestehenden Test-Setup

---

## Änderungsübersicht

```
proto/user/v1/user.proto                              ← neuer PasskeyService
gen/go/user/v1/                                       ← neu generieren (buf generate)
services/gateway/src/lib/gen/user/v1/                 ← neu generieren
services/users/migrations/00002_add_passkeys.sql      ← neue Tabellen
services/users/internal/service/types.go              ← neue Typen + PasskeyStore interface
services/users/internal/service/passkey.go            ← NEU: PasskeyService + Handler
services/users/internal/service/passkey_test.go       ← NEU: Unit-Tests
services/users/internal/store/passkey.go              ← NEU: Store-Methoden
services/users/internal/store/passkey_test.go         ← NEU: Integration-Tests
services/users/internal/config/config.go              ← 2 neue Env-Vars
services/users/cmd/users/main.go                      ← Wiring + PublicMethods
services/gateway/package.json                         ← @simplewebauthn/browser
services/gateway/src/lib/server/clients.ts            ← PasskeyService client
services/gateway/src/routes/api/passkey/              ← NEU: 4 API-Endpunkte
services/gateway/src/routes/(app)/account/passkeys/   ← NEU: Verwaltungs-UI
services/gateway/src/routes/(auth)/login/             ← Passkey-Button
go.mod / go.sum                                       ← go-webauthn/webauthn
docker-compose.yml                                    ← WEBAUTHN_RP_ID, WEBAUTHN_RP_ORIGIN
```

---

## SOLID-Prinzipien

| Prinzip | Umsetzung |
|---|---|
| **S** Single Responsibility | `PasskeyService` ist eigene Struct; `store/passkey.go` ist eigene Datei; `WebAuthnVerifier` kapselt die Library |
| **O** Open/Closed | `store.Store` wird durch neue Methoden **erweitert**, nicht verändert; `Service` bleibt unangetastet |
| **L** Liskov | `store.Store` implementiert `service.Store` + `service.PasskeyStore`; beide bleiben vollständig erfüllt |
| **I** Interface Segregation | `PasskeyService` erhält drei minimale Interfaces statt dem vollen `Store` |
| **D** Dependency Inversion | `WebAuthnVerifier`-Interface → go-webauthn ist per Fake austauschbar; Store-Ports sind Interfaces, keine Konkreten |
