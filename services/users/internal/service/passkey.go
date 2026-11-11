package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	userv1 "github.com/francispowlesland/microservices-app-go/gen/go/user/v1"
	"github.com/francispowlesland/microservices-app-go/internal/platform/authn"
)

const challengeTTL = 5 * time.Minute

// WebAuthnVerifier is the interface wrapping go-webauthn/webauthn (DIP).
// Uses the Validate* variants (parsed JSON) so the interface stays HTTP-free and is easy to fake in tests.
type WebAuthnVerifier interface {
	BeginRegistration(user webauthn.User, opts ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error)
	// ValidateRegistration verifies a parsed registration response.
	ValidateRegistration(user webauthn.User, session webauthn.SessionData, response *protocol.ParsedCredentialCreationData) (*webauthn.Credential, error)
	BeginDiscoverableLogin(opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error)
	// ValidateDiscoverableLogin verifies a parsed assertion response.
	ValidateDiscoverableLogin(handler webauthn.DiscoverableUserHandler, session webauthn.SessionData, response *protocol.ParsedCredentialAssertionData) (*webauthn.Credential, error)
}

// passkeyUser adapts a service.User for go-webauthn.
type passkeyUser struct {
	user        User
	credentials []webauthn.Credential
}

func (p passkeyUser) WebAuthnID() []byte                         { return []byte(p.user.ID.String()) }
func (p passkeyUser) WebAuthnName() string                       { return p.user.Username }
func (p passkeyUser) WebAuthnDisplayName() string                { return p.user.Name }
func (p passkeyUser) WebAuthnCredentials() []webauthn.Credential { return p.credentials }

// PasskeyOptions configure a PasskeyService.
type PasskeyOptions struct {
	Store      PasskeyStore
	UserStore  UserReader
	TokenStore TokenWriter
	Signer     *authn.Signer
	WebAuthn   WebAuthnVerifier
	RefreshTTL time.Duration
	Logger     *slog.Logger
	Now        func() time.Time
}

// UserReader is the minimal Store subset PasskeyService needs for user lookups (ISP).
type UserReader interface {
	GetUser(ctx context.Context, id uuid.UUID) (User, error)
	GetUserByUsername(ctx context.Context, username string) (User, error)
	RecordSuccessfulLogin(ctx context.Context, id uuid.UUID, now time.Time) error
}

// TokenWriter is the minimal Store subset PasskeyService needs for token issuance (ISP).
type TokenWriter interface {
	CreateRefreshToken(ctx context.Context, t RefreshToken) error
}

// PasskeyService implements user.v1.PasskeyService.
// It is intentionally separate from Service (SRP).
type PasskeyService struct {
	userv1.UnimplementedPasskeyServiceServer

	store      PasskeyStore
	userStore  UserReader
	tokenStore TokenWriter
	signer     *authn.Signer
	wa         WebAuthnVerifier
	refreshTTL time.Duration
	log        *slog.Logger
	now        func() time.Time
}

// NewPasskeyService builds a PasskeyService.
func NewPasskeyService(o PasskeyOptions) *PasskeyService {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &PasskeyService{
		store:      o.Store,
		userStore:  o.UserStore,
		tokenStore: o.TokenStore,
		signer:     o.Signer,
		wa:         o.WebAuthn,
		refreshTTL: o.RefreshTTL,
		log:        o.Logger,
		now:        o.Now,
	}
}

func (s *PasskeyService) nowUTC() time.Time { return s.now().UTC().Truncate(time.Microsecond) }

func (s *PasskeyService) internal(ctx context.Context, op string, err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, "request cancelled")
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, "deadline exceeded")
	}
	s.log.ErrorContext(ctx, "passkey operation failed", slog.String("op", op), slog.Any("error", err))
	return status.Error(codes.Internal, "internal error")
}

// PasskeyBeginRegistration generates a WebAuthn registration challenge for an authenticated user.
func (s *PasskeyService) PasskeyBeginRegistration(ctx context.Context, req *userv1.PasskeyBeginRegistrationRequest) (*userv1.PasskeyBeginRegistrationResponse, error) {
	userID, err := parseID(req.GetUserId())
	if err != nil {
		return nil, err
	}
	if authn.MustFromContext(ctx).Subject != userID.String() {
		return nil, status.Error(codes.PermissionDenied, "can only register passkeys for yourself")
	}
	u, err := s.userStore.GetUser(ctx, userID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, s.internal(ctx, "get user for registration", err)
	}

	creation, session, err := s.wa.BeginRegistration(passkeyUser{user: u})
	if err != nil {
		return nil, s.internal(ctx, "begin registration", err)
	}

	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return nil, s.internal(ctx, "marshal registration session", err)
	}

	challengeID, err := newChallengeID()
	if err != nil {
		return nil, s.internal(ctx, "new challenge id", err)
	}

	now := s.nowUTC()
	c := PasskeyChallenge{
		ChallengeID: challengeID,
		UserID:      &userID,
		SessionData: sessionJSON,
		ExpiresAt:   now.Add(challengeTTL),
		CreatedAt:   now,
	}
	if err := s.store.CreatePasskeyChallenge(ctx, c); err != nil {
		return nil, s.internal(ctx, "store registration challenge", err)
	}

	// Prepend the challenge ID so the client can present it in FinishRegistration.
	envelope := map[string]any{
		"challenge_id": challengeID,
		"options":      creation.Response,
	}
	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		return nil, s.internal(ctx, "marshal registration envelope", err)
	}
	return &userv1.PasskeyBeginRegistrationResponse{OptionsJson: envelopeJSON}, nil
}

// PasskeyFinishRegistration verifies the credential and stores it.
func (s *PasskeyService) PasskeyFinishRegistration(ctx context.Context, req *userv1.PasskeyFinishRegistrationRequest) (*userv1.PasskeyFinishRegistrationResponse, error) {
	userID, err := parseID(req.GetUserId())
	if err != nil {
		return nil, err
	}
	if authn.MustFromContext(ctx).Subject != userID.String() {
		return nil, status.Error(codes.PermissionDenied, "can only register passkeys for yourself")
	}

	var envelope struct {
		ChallengeID string          `json:"challenge_id"`
		Credential  json.RawMessage `json:"credential"`
	}
	if err := json.Unmarshal(req.GetCredentialJson(), &envelope); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid credential_json")
	}

	now := s.nowUTC()
	challenge, err := s.store.ConsumePasskeyChallenge(ctx, envelope.ChallengeID, now)
	if errors.Is(err, ErrChallengeExpired) {
		return nil, status.Error(codes.InvalidArgument, "registration challenge expired or not found")
	}
	if err != nil {
		return nil, s.internal(ctx, "consume registration challenge", err)
	}

	u, err := s.userStore.GetUser(ctx, userID)
	if err != nil {
		return nil, s.internal(ctx, "get user for finish registration", err)
	}

	parsedResponse, err := protocol.ParseCredentialCreationResponseBytes(envelope.Credential)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid credential response")
	}

	var session webauthn.SessionData
	if err := json.Unmarshal(challenge.SessionData, &session); err != nil {
		return nil, s.internal(ctx, "unmarshal registration session", err)
	}
	credential, err := s.wa.ValidateRegistration(passkeyUser{user: u}, session, parsedResponse)
	if err != nil {
		s.log.WarnContext(ctx, "passkey registration verification failed", slog.Any("error", err))
		return nil, status.Errorf(codes.InvalidArgument, "passkey registration verification failed: %v", err)
	}

	name := req.GetName()
	if name == "" {
		name = "Passkey"
	}
	pc := PasskeyCredential{
		ID:           uuid.New(),
		UserID:       userID,
		CredentialID: credential.ID,
		PublicKey:    credential.PublicKey,
		SignCount:    credential.Authenticator.SignCount,
		Transports:   transportStrings(credential.Transport),
		Flags: CredentialFlags{
			UserPresent:    credential.Flags.UserPresent,
			UserVerified:   credential.Flags.UserVerified,
			BackupEligible: credential.Flags.BackupEligible,
			BackupState:    credential.Flags.BackupState,
		},
		Name:      name,
		CreatedAt: now,
	}
	if err := s.store.CreatePasskeyCredential(ctx, pc); err != nil {
		return nil, s.internal(ctx, "store credential", err)
	}

	return &userv1.PasskeyFinishRegistrationResponse{
		Passkey: &userv1.PasskeyInfo{
			Id:        pc.ID.String(),
			Name:      pc.Name,
			CreatedAt: timestamppb.New(pc.CreatedAt),
		},
	}, nil
}

// PasskeyBeginAuthentication is public: it generates an assertion challenge.
func (s *PasskeyService) PasskeyBeginAuthentication(ctx context.Context, req *userv1.PasskeyBeginAuthenticationRequest) (*userv1.PasskeyBeginAuthenticationResponse, error) {
	assertion, session, err := s.wa.BeginDiscoverableLogin()
	if err != nil {
		return nil, s.internal(ctx, "begin discoverable login", err)
	}

	challengeID, err := newChallengeID()
	if err != nil {
		return nil, s.internal(ctx, "new challenge id", err)
	}

	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return nil, s.internal(ctx, "marshal authentication session", err)
	}

	now := s.nowUTC()
	c := PasskeyChallenge{
		ChallengeID: challengeID,
		SessionData: sessionJSON,
		ExpiresAt:   now.Add(challengeTTL),
		CreatedAt:   now,
	}
	if err := s.store.CreatePasskeyChallenge(ctx, c); err != nil {
		return nil, s.internal(ctx, "store authentication challenge", err)
	}

	envelope := map[string]any{
		"challenge_id": challengeID,
		"options":      assertion.Response,
	}
	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		return nil, s.internal(ctx, "marshal authentication envelope", err)
	}
	return &userv1.PasskeyBeginAuthenticationResponse{OptionsJson: envelopeJSON}, nil
}

// PasskeyFinishAuthentication is public: it verifies the assertion and issues tokens.
func (s *PasskeyService) PasskeyFinishAuthentication(ctx context.Context, req *userv1.PasskeyFinishAuthenticationRequest) (*userv1.PasskeyFinishAuthenticationResponse, error) {
	var envelope struct {
		ChallengeID string          `json:"challenge_id"`
		Assertion   json.RawMessage `json:"assertion"`
	}
	if err := json.Unmarshal(req.GetAssertionJson(), &envelope); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid assertion_json")
	}

	now := s.nowUTC()
	challenge, err := s.store.ConsumePasskeyChallenge(ctx, envelope.ChallengeID, now)
	if errors.Is(err, ErrChallengeExpired) {
		return nil, status.Error(codes.Unauthenticated, "authentication challenge expired or not found")
	}
	if err != nil {
		return nil, s.internal(ctx, "consume authentication challenge", err)
	}

	parsedAssertion, err := protocol.ParseCredentialRequestResponseBytes(envelope.Assertion)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid assertion response")
	}

	var session webauthn.SessionData
	if err := json.Unmarshal(challenge.SessionData, &session); err != nil {
		return nil, s.internal(ctx, "unmarshal authentication session", err)
	}

	// DiscoverableUserHandler: resolve user by raw credential ID from the store.
	handler := func(rawID, _ []byte) (webauthn.User, error) {
		pc, err := s.store.GetPasskeyCredentialByCredentialID(ctx, rawID)
		if err != nil {
			return nil, err
		}
		u, err := s.userStore.GetUser(ctx, pc.UserID)
		if err != nil {
			return nil, err
		}
		creds := []webauthn.Credential{{
			ID:        pc.CredentialID,
			PublicKey: pc.PublicKey,
			Authenticator: webauthn.Authenticator{SignCount: pc.SignCount},
			Flags: webauthn.CredentialFlags{
				UserPresent:    pc.Flags.UserPresent,
				UserVerified:   pc.Flags.UserVerified,
				BackupEligible: pc.Flags.BackupEligible,
				BackupState:    pc.Flags.BackupState,
			},
		}}
		return passkeyUser{user: u, credentials: creds}, nil
	}

	credential, err := s.wa.ValidateDiscoverableLogin(handler, session, parsedAssertion)
	if err != nil {
		s.log.WarnContext(ctx, "passkey authentication verification failed", slog.Any("error", err))
		return nil, status.Errorf(codes.Unauthenticated, "passkey authentication failed: %v", err)
	}

	// Update sign count to prevent replay attacks.
	pc, err := s.store.GetPasskeyCredentialByCredentialID(ctx, credential.ID)
	if err != nil {
		return nil, s.internal(ctx, "get credential for sign count update", err)
	}
	if err := s.store.UpdatePasskeySignCount(ctx, pc.ID, credential.Authenticator.SignCount); err != nil {
		s.log.WarnContext(ctx, "failed to update passkey sign count", slog.Any("error", err))
	}

	u, err := s.userStore.GetUser(ctx, pc.UserID)
	if err != nil {
		return nil, s.internal(ctx, "get user after authentication", err)
	}
	if u.Status != userv1StatusActive() {
		return nil, status.Error(codes.PermissionDenied, "account not active")
	}

	if err := s.userStore.RecordSuccessfulLogin(ctx, u.ID, now); err != nil {
		return nil, s.internal(ctx, "record successful login", err)
	}

	tokens, err := s.issueTokens(ctx, u, now)
	if err != nil {
		return nil, s.internal(ctx, "issue tokens", err)
	}

	return &userv1.PasskeyFinishAuthenticationResponse{
		User:   toProto(u),
		Tokens: tokens,
	}, nil
}

// ListPasskeys returns all passkeys registered by a user (self or admin).
func (s *PasskeyService) ListPasskeys(ctx context.Context, req *userv1.ListPasskeysRequest) (*userv1.ListPasskeysResponse, error) {
	userID, err := parseID(req.GetUserId())
	if err != nil {
		return nil, err
	}
	claims := authn.MustFromContext(ctx)
	if !claims.IsAdmin() && claims.Subject != userID.String() {
		return nil, status.Error(codes.NotFound, "user not found")
	}

	creds, err := s.store.ListPasskeyCredentialsByUser(ctx, userID)
	if err != nil {
		return nil, s.internal(ctx, "list passkeys", err)
	}
	resp := &userv1.ListPasskeysResponse{}
	for _, c := range creds {
		resp.Passkeys = append(resp.Passkeys, &userv1.PasskeyInfo{
			Id:        c.ID.String(),
			Name:      c.Name,
			CreatedAt: timestamppb.New(c.CreatedAt),
		})
	}
	return resp, nil
}

// DeletePasskey removes a passkey (self or admin).
func (s *PasskeyService) DeletePasskey(ctx context.Context, req *userv1.DeletePasskeyRequest) (*userv1.DeletePasskeyResponse, error) {
	userID, err := parseID(req.GetUserId())
	if err != nil {
		return nil, err
	}
	passkeyID, err := parseID(req.GetPasskeyId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "passkey_id must be a valid UUID")
	}
	claims := authn.MustFromContext(ctx)
	if !claims.IsAdmin() && claims.Subject != userID.String() {
		return nil, status.Error(codes.NotFound, "user not found")
	}

	if err := s.store.DeletePasskeyCredential(ctx, passkeyID, userID); err != nil {
		if errors.Is(err, ErrPasskeyNotFound) {
			return nil, status.Error(codes.NotFound, "passkey not found")
		}
		return nil, s.internal(ctx, "delete passkey", err)
	}
	return &userv1.DeletePasskeyResponse{}, nil
}

// issueTokens signs a new access token and stores a refresh token.
func (s *PasskeyService) issueTokens(ctx context.Context, u User, now time.Time) (*userv1.Tokens, error) {
	access, accessExp, err := s.signer.Sign(u.ID.String(), u.Roles)
	if err != nil {
		return nil, err
	}
	raw, hash, err := newToken()
	if err != nil {
		return nil, err
	}
	rt := RefreshToken{
		ID:        uuid.New(),
		UserID:    u.ID,
		FamilyID:  uuid.New(),
		Hash:      hash,
		ExpiresAt: now.Add(s.refreshTTL),
		CreatedAt: now,
	}
	if err := s.tokenStore.CreateRefreshToken(ctx, rt); err != nil {
		return nil, err
	}
	return &userv1.Tokens{
		AccessToken:           access,
		RefreshToken:          raw,
		AccessTokenExpiresAt:  timestamppb.New(accessExp),
		RefreshTokenExpiresAt: timestamppb.New(rt.ExpiresAt),
	}, nil
}

// ---- helpers ----

func newChallengeID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func transportStrings(tt []protocol.AuthenticatorTransport) []string {
	out := make([]string, len(tt))
	for i, t := range tt {
		out[i] = string(t)
	}
	return out
}

func userv1StatusActive() userv1.UserStatus {
	return userv1.UserStatus_USER_STATUS_ACTIVE
}
