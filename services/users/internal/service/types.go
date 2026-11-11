package service

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	userv1 "github.com/francispowlesland/microservices-app-go/gen/go/user/v1"
)


// Roles.
const (
	RoleAdmin    = "admin"
	RoleCustomer = "customer"
)

// One-time token kinds.
const (
	KindReset  = "reset"
	KindVerify = "verify"
)

// Sentinel errors returned by a Store. The service maps them to gRPC codes.
var (
	ErrNotFound       = errors.New("not found")
	ErrEmailTaken     = errors.New("email already registered")
	ErrUsernameTaken  = errors.New("username already taken")
	ErrLastAdmin      = errors.New("cannot remove the last admin")
	ErrTokenInvalid   = errors.New("token unknown, expired or used")
	ErrTokenReused    = errors.New("refresh token reuse detected")
	ErrUserNotActive  = errors.New("user not active")
	ErrAdminPreexists = errors.New("an admin already exists")

	// Passkey sentinel errors.
	ErrChallengeExpired  = errors.New("passkey challenge expired or not found")
	ErrCredentialInvalid = errors.New("passkey credential verification failed")
	ErrPasskeyNotFound   = errors.New("passkey not found")
)

// User is the stored identity, including credential state.
type User struct {
	ID               uuid.UUID
	Email            string
	Username         string
	Name             string
	PasswordHash     string
	Status           userv1.UserStatus
	EmailVerified    bool
	Roles            []string
	CreatedAt        time.Time
	UpdatedAt        time.Time
	LastLoginAt      *time.Time
	FailedLoginCount int
	LockedUntil      *time.Time
}

func (u User) isAdmin() bool {
	for _, r := range u.Roles {
		if r == RoleAdmin {
			return true
		}
	}
	return false
}

// RefreshToken is a stored (hashed) refresh token.
type RefreshToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	FamilyID  uuid.UUID
	Hash      []byte
	ExpiresAt time.Time
	CreatedAt time.Time
}

// OneTimeToken is a stored (hashed) reset or verification token.
type OneTimeToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	Kind      string
	Hash      []byte
	ExpiresAt time.Time
	CreatedAt time.Time
}

// ListCursor is the keyset position after which to continue. Nil means first page.
type ListCursor struct {
	CreatedAt time.Time
	ID        uuid.UUID
}

// PasskeyCredential is a stored WebAuthn credential.
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

// PasskeyChallenge is a short-lived server-side WebAuthn challenge (TTL ~5 min).
// Challenge is stored as the base64url string produced by go-webauthn SessionData.Challenge.
// UserID is nil for the usernameless authentication flow.
type PasskeyChallenge struct {
	ChallengeID string
	UserID      *uuid.UUID
	Challenge   string // base64url, as-is from webauthn.SessionData.Challenge
	ExpiresAt   time.Time
	CreatedAt   time.Time
}

// PasskeyStore is the persistence port for WebAuthn passkey operations.
// store.Store implements both Store and PasskeyStore.
type PasskeyStore interface {
	// CreatePasskeyChallenge persists a short-lived challenge.
	CreatePasskeyChallenge(ctx context.Context, c PasskeyChallenge) error
	// ConsumePasskeyChallenge atomically marks a valid challenge as consumed (single-use).
	// Returns ErrChallengeExpired if unknown, expired, or already consumed.
	ConsumePasskeyChallenge(ctx context.Context, challengeID string, now time.Time) (PasskeyChallenge, error)

	// CreatePasskeyCredential stores a verified credential after registration.
	CreatePasskeyCredential(ctx context.Context, c PasskeyCredential) error
	// GetPasskeyCredentialByCredentialID returns the credential matching the raw credential ID bytes.
	GetPasskeyCredentialByCredentialID(ctx context.Context, credentialID []byte) (PasskeyCredential, error)
	// ListPasskeyCredentialsByUser returns all credentials for a user, ordered by created_at.
	ListPasskeyCredentialsByUser(ctx context.Context, userID uuid.UUID) ([]PasskeyCredential, error)
	// UpdatePasskeySignCount updates the sign counter after a successful authentication.
	UpdatePasskeySignCount(ctx context.Context, id uuid.UUID, signCount uint32) error
	// DeletePasskeyCredential removes the credential. Returns ErrPasskeyNotFound if missing or wrong owner.
	DeletePasskeyCredential(ctx context.Context, id, userID uuid.UUID) error

	// GetUserByPasskeyCredentialID returns the owner of a given credential.
	GetUserByPasskeyCredentialID(ctx context.Context, credentialID []byte) (User, error)
}

// Store is the persistence port. Implementations must make each method atomic.
type Store interface {
	// CreateUser inserts u and its verification token together.
	// Returns ErrEmailTaken or ErrUsernameTaken (case-insensitive).
	CreateUser(ctx context.Context, u User, verify OneTimeToken) error
	// CreateAdminIfNone inserts u only if no admin exists. Reports whether it did.
	CreateAdminIfNone(ctx context.Context, u User) (bool, error)
	GetUser(ctx context.Context, id uuid.UUID) (User, error)
	GetUserByEmail(ctx context.Context, email string) (User, error)
	GetUserByUsername(ctx context.Context, username string) (User, error)
	// UpdateProfile sets the non-nil fields and bumps updated_at.
	UpdateProfile(ctx context.Context, id uuid.UUID, name, username *string, now time.Time) (User, error)
	// DeleteUser hard-deletes. Returns ErrNotFound or ErrLastAdmin.
	DeleteUser(ctx context.Context, id uuid.UUID) error
	// ListUsers returns up to limit users ordered by (created_at, id) after cur.
	ListUsers(ctx context.Context, cur *ListCursor, limit int) ([]User, error)

	// RecordFailedLogin increments the failure counter (restarting it if a
	// previous lock has expired) and locks the account until lockUntil once
	// the counter reaches maxFailures.
	RecordFailedLogin(ctx context.Context, id uuid.UUID, now time.Time, maxFailures int, lockUntil time.Time) error
	// RecordSuccessfulLogin clears the counter and lock and sets last_login_at.
	RecordSuccessfulLogin(ctx context.Context, id uuid.UUID, now time.Time) error

	CreateRefreshToken(ctx context.Context, t RefreshToken) error
	// RotateRefreshToken atomically revokes the token with oldHash and stores
	// next (UserID and FamilyID are taken from the old token). It returns the
	// user as currently stored. Errors: ErrTokenInvalid (unknown or expired),
	// ErrTokenReused (the family has been revoked), ErrUserNotActive.
	RotateRefreshToken(ctx context.Context, oldHash []byte, next RefreshToken, now time.Time) (User, error)
	// RevokeFamilyByHash revokes the family of the token. Unknown tokens are not an error.
	RevokeFamilyByHash(ctx context.Context, hash []byte, now time.Time) error

	// SetPassword updates the hash and revokes all of the user's refresh tokens.
	SetPassword(ctx context.Context, id uuid.UUID, hash string, now time.Time) error
	// CreateResetToken invalidates earlier unused reset tokens for the user and stores t.
	CreateResetToken(ctx context.Context, t OneTimeToken, now time.Time) error
	// UserByOneTimeToken returns the owner of a valid (unused, unexpired) token.
	UserByOneTimeToken(ctx context.Context, kind string, hash []byte, now time.Time) (User, error)
	// ResetPassword consumes a reset token, sets the hash, revokes all refresh
	// tokens and clears the lockout.
	ResetPassword(ctx context.Context, hash []byte, newPasswordHash string, now time.Time) error
	// VerifyEmail consumes a verify token, sets email_verified and promotes
	// PENDING_VERIFICATION to ACTIVE (SUSPENDED stays suspended).
	VerifyEmail(ctx context.Context, hash []byte, now time.Time) (User, error)
}
