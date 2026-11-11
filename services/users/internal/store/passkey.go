package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/francispowlesland/microservices-app-go/internal/platform/pgxutil"
	"github.com/francispowlesland/microservices-app-go/services/users/internal/service"
)

var _ service.PasskeyStore = (*Store)(nil)

// ---- Challenges ----

func (s *Store) CreatePasskeyChallenge(ctx context.Context, c service.PasskeyChallenge) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO passkey_challenges
			(challenge_id, user_id, session_data, expires_at, created_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		c.ChallengeID, c.UserID, c.SessionData, c.ExpiresAt, c.CreatedAt)
	return err
}

// ConsumePasskeyChallenge atomically marks a valid challenge as consumed.
// Returns service.ErrChallengeExpired if unknown, expired, or already consumed.
func (s *Store) ConsumePasskeyChallenge(ctx context.Context, challengeID string, now time.Time) (service.PasskeyChallenge, error) {
	var c service.PasskeyChallenge
	err := s.pool.QueryRow(ctx,
		`UPDATE passkey_challenges
		 SET    consumed_at = $2
		 WHERE  challenge_id = $1
		   AND  consumed_at  IS NULL
		   AND  expires_at   > $2
		 RETURNING challenge_id, user_id, session_data, expires_at, created_at`,
		challengeID, now,
	).Scan(&c.ChallengeID, &c.UserID, &c.SessionData, &c.ExpiresAt, &c.CreatedAt)
	if pgxutil.IsNotFound(err) {
		return service.PasskeyChallenge{}, service.ErrChallengeExpired
	}
	return c, err
}

// ---- Credentials ----

func (s *Store) CreatePasskeyCredential(ctx context.Context, c service.PasskeyCredential) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO passkey_credentials
			(id, user_id, credential_id, public_key, sign_count, transports, name, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		c.ID, c.UserID, c.CredentialID, c.PublicKey, c.SignCount, c.Transports, c.Name, c.CreatedAt)
	return err
}

func (s *Store) GetPasskeyCredentialByCredentialID(ctx context.Context, credentialID []byte) (service.PasskeyCredential, error) {
	return scanPasskeyCredential(s.pool.QueryRow(ctx,
		`SELECT id, user_id, credential_id, public_key, sign_count, transports, name, created_at
		 FROM   passkey_credentials
		 WHERE  credential_id = $1`,
		credentialID))
}

func (s *Store) ListPasskeyCredentialsByUser(ctx context.Context, userID uuid.UUID) ([]service.PasskeyCredential, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, user_id, credential_id, public_key, sign_count, transports, name, created_at
		 FROM   passkey_credentials
		 WHERE  user_id = $1
		 ORDER BY created_at`,
		userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []service.PasskeyCredential
	for rows.Next() {
		c, err := scanPasskeyCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) UpdatePasskeySignCount(ctx context.Context, id uuid.UUID, signCount uint32) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE passkey_credentials SET sign_count = $2 WHERE id = $1`,
		id, signCount)
	return err
}

func (s *Store) DeletePasskeyCredential(ctx context.Context, id, userID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM passkey_credentials WHERE id = $1 AND user_id = $2`,
		id, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return service.ErrPasskeyNotFound
	}
	return nil
}

func (s *Store) GetUserByPasskeyCredentialID(ctx context.Context, credentialID []byte) (service.User, error) {
	return scanUser(s.pool.QueryRow(ctx,
		`SELECT `+prefixed("u.", userCols)+`
		 FROM   users u
		 JOIN   passkey_credentials p ON p.user_id = u.id
		 WHERE  p.credential_id = $1`,
		credentialID))
}

// ---- scanner ----

type passkeyCols interface{ Scan(dest ...any) error }

func scanPasskeyCredential(r passkeyCols) (service.PasskeyCredential, error) {
	var c service.PasskeyCredential
	err := r.Scan(
		&c.ID, &c.UserID, &c.CredentialID, &c.PublicKey,
		&c.SignCount, &c.Transports, &c.Name, &c.CreatedAt,
	)
	if pgxutil.IsNotFound(err) {
		return service.PasskeyCredential{}, service.ErrPasskeyNotFound
	}
	return c, err
}

// pgx.Rows also satisfies rowScanner (Scan method), so we can reuse scanPasskeyCredential.
var _ passkeyCols = pgx.Rows(nil)
