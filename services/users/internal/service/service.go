// Package service implements user.v1.UserService and user.v1.AuthService.
// Business rules and authorisation live here; SQL lives in internal/store.
package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	userv1 "github.com/francispowlesland/microservices-app-go/gen/go/user/v1"
	"github.com/francispowlesland/microservices-app-go/internal/platform/authn"
	"github.com/francispowlesland/microservices-app-go/services/users/internal/password"
)

const (
	maxFailedLogins = 5
	lockDuration    = 15 * time.Minute
	verifyTokenTTL  = 24 * time.Hour
	resetTokenTTL   = time.Hour
	mailQueueSize   = 64
	mailJobTimeout  = 10 * time.Second
)

// Options configure a Service.
type Options struct {
	Store      Store
	Mailer     Mailer
	Signer     *authn.Signer
	Hasher     *password.Hasher
	RefreshTTL time.Duration
	Logger     *slog.Logger
	// Now is overridable for tests. Defaults to time.Now.
	Now func() time.Time
}

// Service implements both gRPC services.
type Service struct {
	userv1.UnimplementedUserServiceServer
	userv1.UnimplementedAuthServiceServer

	store      Store
	mailer     Mailer
	signer     *authn.Signer
	hasher     *password.Hasher
	refreshTTL time.Duration
	log        *slog.Logger
	now        func() time.Time

	// dummyHash is verified against when the login identifier is unknown, so
	// unknown users cost the same as wrong passwords.
	dummyHash string

	jobs       chan func()
	stop       chan struct{}
	workerDone chan struct{}
	closeOnce  sync.Once
}

var (
	_ userv1.UserServiceServer = (*Service)(nil)
	_ userv1.AuthServiceServer = (*Service)(nil)
)

// New builds a Service and starts its mail worker. Call Close on shutdown.
func New(o Options) (*Service, error) {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	dummy, err := o.Hasher.Hash("dummy-password-for-timing-equalisation")
	if err != nil {
		return nil, fmt.Errorf("service: precompute dummy hash: %w", err)
	}
	s := &Service{
		store: o.Store, mailer: o.Mailer, signer: o.Signer, hasher: o.Hasher,
		refreshTTL: o.RefreshTTL, log: o.Logger, now: o.Now, dummyHash: dummy,
		jobs:       make(chan func(), mailQueueSize),
		stop:       make(chan struct{}),
		workerDone: make(chan struct{}),
	}
	go s.worker()
	return s, nil
}

// healthCheckMethod is the unary standard health RPC. grpcx installs the authn
// interceptor on every unary call, including this one, so it must be listed or
// the container healthcheck (and any probe) gets Unauthenticated.
const healthCheckMethod = "/grpc.health.v1.Health/Check"

// PublicMethods are the RPCs that skip authentication. Everything else is
// default-deny in authn.UnaryInterceptor.
func PublicMethods() map[string]bool {
	return map[string]bool{
		healthCheckMethod: true,
		userv1.UserService_CreateUser_FullMethodName:           true,
		userv1.AuthService_Login_FullMethodName:                true,
		userv1.AuthService_RefreshToken_FullMethodName:         true,
		userv1.AuthService_Logout_FullMethodName:               true,
		userv1.AuthService_RequestPasswordReset_FullMethodName: true,
		userv1.AuthService_ResetPassword_FullMethodName:        true,
		userv1.AuthService_VerifyEmail_FullMethodName:          true,
		// Passkey authentication is public (no token required to start a login).
		userv1.PasskeyService_PasskeyBeginAuthentication_FullMethodName:  true,
		userv1.PasskeyService_PasskeyFinishAuthentication_FullMethodName: true,
	}
}

// Close stops the mail worker after draining queued jobs.
func (s *Service) Close() {
	s.closeOnce.Do(func() { close(s.stop) })
	<-s.workerDone
}

func (s *Service) worker() {
	defer close(s.workerDone)
	for {
		select {
		case j := <-s.jobs:
			j()
		case <-s.stop:
			for {
				select {
				case j := <-s.jobs:
					j()
				default:
					return
				}
			}
		}
	}
}

// enqueue never blocks the request: when the queue is full the job is dropped.
func (s *Service) enqueue(name string, job func(ctx context.Context)) {
	wrapped := func() {
		ctx, cancel := context.WithTimeout(context.Background(), mailJobTimeout)
		defer cancel()
		job(ctx)
	}
	select {
	case s.jobs <- wrapped:
	default:
		s.log.Warn("background queue full, dropping job", slog.String("job", name))
	}
}

// flush waits for all jobs queued so far. Tests only.
func (s *Service) flush() {
	done := make(chan struct{})
	s.jobs <- func() { close(done) }
	<-done
}

// ---- helpers ----

func (s *Service) nowUTC() time.Time { return s.now().UTC().Truncate(time.Microsecond) }

// internal logs err and returns the generic Internal status.
func (s *Service) internal(ctx context.Context, op string, err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, "request cancelled")
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, "deadline exceeded")
	}
	s.log.ErrorContext(ctx, "operation failed", slog.String("op", op), slog.Any("error", err))
	return status.Error(codes.Internal, "internal error")
}

func newToken() (raw string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", nil, fmt.Errorf("read random: %w", err)
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	return raw, hashToken(raw), nil
}

func hashToken(raw string) []byte {
	h := sha256.Sum256([]byte(raw))
	return h[:]
}

func toProto(u User) *userv1.User {
	p := &userv1.User{
		Id:            u.ID.String(),
		Email:         u.Email,
		Username:      u.Username,
		Name:          u.Name,
		Status:        u.Status,
		EmailVerified: u.EmailVerified,
		Roles:         append([]string(nil), u.Roles...),
		CreatedAt:     timestamppb.New(u.CreatedAt),
		UpdatedAt:     timestamppb.New(u.UpdatedAt),
	}
	if u.LastLoginAt != nil {
		p.LastLoginAt = timestamppb.New(*u.LastLoginAt)
	}
	return p
}
