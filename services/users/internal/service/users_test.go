package service

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	userv1 "github.com/francispowlesland/microservices-app-go/gen/go/user/v1"
)

func TestRegistrationCoversContract(t *testing.T) {
	h := newHarness(t)
	got := map[string]int{}
	// Use the production registration helpers on a throwaway registrar.
	reg := &fakeRegistrar{}
	userv1.RegisterUserServiceServer(reg, h.svc)
	userv1.RegisterAuthServiceServer(reg, h.svc)
	for _, sd := range reg.descs {
		got[sd.ServiceName] = len(sd.Methods)
	}
	if got["user.v1.UserService"] != 5 || got["user.v1.AuthService"] != 7 {
		t.Fatalf("registered methods = %v", got)
	}
	pub := PublicMethods()
	for _, m := range []string{
		userv1.UserService_CreateUser_FullMethodName, userv1.AuthService_Login_FullMethodName,
		userv1.AuthService_RefreshToken_FullMethodName, userv1.AuthService_Logout_FullMethodName,
		userv1.AuthService_RequestPasswordReset_FullMethodName, userv1.AuthService_ResetPassword_FullMethodName,
		userv1.AuthService_VerifyEmail_FullMethodName, "/grpc.health.v1.Health/Check",
		// Passkey authentication endpoints are public (no token needed to start a login).
		userv1.PasskeyService_PasskeyBeginAuthentication_FullMethodName,
		userv1.PasskeyService_PasskeyFinishAuthentication_FullMethodName,
	} {
		if !pub[m] {
			t.Errorf("%s should be public", m)
		}
	}
	// 7 original + health check + 2 passkey public methods = 10
	if len(pub) != 10 {
		t.Fatalf("public methods = %d, want 10 (9 contract + health check)", len(pub))
	}
}

func TestCreateUser(t *testing.T) {
	good := func() *userv1.CreateUserRequest {
		return &userv1.CreateUserRequest{Email: "  Alice@Example.COM ", Username: "Alice_1", Name: " Alice ", Password: testPassword}
	}
	tests := []struct {
		name string
		mut  func(*userv1.CreateUserRequest)
		want codes.Code
	}{
		{"ok normalises", func(*userv1.CreateUserRequest) {}, codes.OK},
		{"bad email", func(r *userv1.CreateUserRequest) { r.Email = "not-an-email" }, codes.InvalidArgument},
		{"email with display name", func(r *userv1.CreateUserRequest) { r.Email = "A <a@b.co>" }, codes.InvalidArgument},
		{"short username", func(r *userv1.CreateUserRequest) { r.Username = "ab" }, codes.InvalidArgument},
		{"bad username chars", func(r *userv1.CreateUserRequest) { r.Username = "al ice" }, codes.InvalidArgument},
		{"empty name", func(r *userv1.CreateUserRequest) { r.Name = "  " }, codes.InvalidArgument},
		{"long name", func(r *userv1.CreateUserRequest) { r.Name = string(make([]rune, 101)) + "x" }, codes.InvalidArgument},
		{"short password", func(r *userv1.CreateUserRequest) { r.Password = "short" }, codes.InvalidArgument},
		{"long password", func(r *userv1.CreateUserRequest) { r.Password = string(make([]byte, 129)) }, codes.InvalidArgument},
		{"password equals email", func(r *userv1.CreateUserRequest) { r.Email = "longpassword@ex.co"; r.Password = "LongPassword@ex.co" }, codes.InvalidArgument},
		{"password equals username", func(r *userv1.CreateUserRequest) { r.Username = "alice_username"; r.Password = "alice_username" }, codes.InvalidArgument},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			req := good()
			tt.mut(req)
			resp, err := h.svc.CreateUser(context.Background(), req)
			wantCode(t, err, tt.want)
			if tt.want != codes.OK {
				return
			}
			u := resp.User
			if u.Email != "alice@example.com" || u.Username != "alice_1" || u.Name != "Alice" {
				t.Errorf("not normalised: %+v", u)
			}
			if u.Status != userv1.UserStatus_USER_STATUS_PENDING_VERIFICATION || len(u.Roles) != 1 || u.Roles[0] != "customer" || u.EmailVerified {
				t.Errorf("wrong server-assigned fields: %+v", u)
			}
			h.svc.flush()
			if _, ok := h.mailer.last(KindVerify, "alice@example.com"); !ok {
				t.Error("verification mail not sent")
			}
		})
	}
}

func TestCreateUserDuplicates(t *testing.T) {
	h := newHarness(t)
	h.active("taken")
	for name, req := range map[string]*userv1.CreateUserRequest{
		"email, different case":    {Email: "TAKEN@example.com", Username: "other", Name: "x", Password: testPassword},
		"username, different case": {Email: "other@example.com", Username: "TAKEN", Name: "x", Password: testPassword},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := h.svc.CreateUser(context.Background(), req)
			wantCode(t, err, codes.AlreadyExists)
		})
	}
}

func TestCreateUserStoreErrorIsInternalAndOpaque(t *testing.T) {
	h := newHarness(t)
	h.store.failNext = context.DeadlineExceeded // mapped
	_, err := h.svc.CreateUser(context.Background(), &userv1.CreateUserRequest{Email: "a@b.co", Username: "abc", Name: "n", Password: testPassword})
	wantCode(t, err, codes.DeadlineExceeded)

	h.store.failNext = status.Error(codes.Unknown, "pq: relation users secret detail")
	_, err = h.svc.CreateUser(context.Background(), &userv1.CreateUserRequest{Email: "a@b.co", Username: "abc", Name: "n", Password: testPassword})
	wantCode(t, err, codes.Internal)
	if status.Convert(err).Message() != "internal error" {
		t.Fatalf("leaked message: %q", status.Convert(err).Message())
	}
}

func TestGetUserAuthorisationMatrix(t *testing.T) {
	h := newHarness(t)
	alice := h.active("alice")
	bob := h.active("bob")
	admin := h.active("root", RoleAdmin, RoleCustomer)
	tests := []struct {
		name   string
		ctx    context.Context
		target uuid.UUID
		want   codes.Code
	}{
		{"self", as(alice.ID, RoleCustomer), alice.ID, codes.OK},
		{"other customer sees NotFound", as(bob.ID, RoleCustomer), alice.ID, codes.NotFound},
		{"admin any", as(admin.ID, RoleAdmin), alice.ID, codes.OK},
		{"admin missing row", as(admin.ID, RoleAdmin), uuid.New(), codes.NotFound},
		{"non-admin missing row same as other", as(bob.ID, RoleCustomer), uuid.New(), codes.NotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := h.svc.GetUser(tt.ctx, &userv1.GetUserRequest{Id: tt.target.String()})
			wantCode(t, err, tt.want)
		})
	}
	_, err := h.svc.GetUser(as(alice.ID), &userv1.GetUserRequest{Id: "nope"})
	wantCode(t, err, codes.InvalidArgument)
}

func TestUpdateUser(t *testing.T) {
	h := newHarness(t)
	alice := h.active("alice")
	bob := h.active("bob")
	admin := h.active("root", RoleAdmin)
	upd := func(ctx context.Context, id uuid.UUID, u *userv1.User, paths ...string) (*userv1.UpdateUserResponse, error) {
		u.Id = id.String()
		return h.svc.UpdateUser(ctx, &userv1.UpdateUserRequest{User: u, UpdateMask: &fieldmaskpb.FieldMask{Paths: paths}})
	}

	t.Run("self name and username", func(t *testing.T) {
		resp, err := upd(as(alice.ID, RoleCustomer), alice.ID, &userv1.User{Name: " New Name ", Username: "New_Alice"}, "name", "username")
		wantCode(t, err, codes.OK)
		if resp.User.Name != "New Name" || resp.User.Username != "new_alice" {
			t.Fatalf("got %+v", resp.User)
		}
		if !resp.User.UpdatedAt.AsTime().After(alice.UpdatedAt) && !resp.User.UpdatedAt.AsTime().Equal(h.clock.Now()) {
			t.Error("updated_at not bumped")
		}
	})
	t.Run("only masked fields change", func(t *testing.T) {
		resp, err := upd(as(admin.ID, RoleAdmin), bob.ID, &userv1.User{Name: "Only Name", Username: "ignored_value", Email: "x@y.co"}, "name")
		wantCode(t, err, codes.OK)
		if resp.User.Username != "bob" || resp.User.Email != "bob@example.com" {
			t.Fatalf("unmasked fields changed: %+v", resp.User)
		}
	})
	t.Run("other customer NotFound", func(t *testing.T) {
		_, err := upd(as(bob.ID, RoleCustomer), alice.ID, &userv1.User{Name: "x"}, "name")
		wantCode(t, err, codes.NotFound)
	})
	t.Run("username clash", func(t *testing.T) {
		_, err := upd(as(alice.ID), alice.ID, &userv1.User{Username: "BOB"}, "username")
		wantCode(t, err, codes.AlreadyExists)
	})
	t.Run("invalid values", func(t *testing.T) {
		_, err := upd(as(alice.ID), alice.ID, &userv1.User{Name: ""}, "name")
		wantCode(t, err, codes.InvalidArgument)
		_, err = upd(as(alice.ID), alice.ID, &userv1.User{Username: "x"}, "username")
		wantCode(t, err, codes.InvalidArgument)
	})
	t.Run("missing user", func(t *testing.T) {
		_, err := h.svc.UpdateUser(as(alice.ID), &userv1.UpdateUserRequest{UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"name"}}})
		wantCode(t, err, codes.InvalidArgument)
	})
	t.Run("empty and nil mask", func(t *testing.T) {
		_, err := upd(as(alice.ID), alice.ID, &userv1.User{Name: "x"})
		wantCode(t, err, codes.InvalidArgument)
		_, err = h.svc.UpdateUser(as(alice.ID), &userv1.UpdateUserRequest{User: &userv1.User{Id: alice.ID.String(), Name: "x"}})
		wantCode(t, err, codes.InvalidArgument)
	})
	for _, p := range []string{"email", "status", "roles", "id", "email_verified", "created_at", "password", "bogus", "*", "name.first"} {
		t.Run("rejects path "+p, func(t *testing.T) {
			_, err := upd(as(admin.ID, RoleAdmin), alice.ID, &userv1.User{Name: "valid name", Username: "valid_name"}, "name", p)
			wantCode(t, err, codes.InvalidArgument)
			if !contains(status.Convert(err).Message(), `"`+p+`"`) {
				t.Errorf("message %q does not name path %q", status.Convert(err).Message(), p)
			}
		})
	}
	t.Run("mask rejection happens before authorisation", func(t *testing.T) {
		// A non-owner with a bad path learns nothing about the target either way.
		_, err := upd(as(bob.ID, RoleCustomer), alice.ID, &userv1.User{}, "roles")
		wantCode(t, err, codes.InvalidArgument)
	})
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestDeleteUser(t *testing.T) {
	h := newHarness(t)
	alice := h.active("alice")
	bob := h.active("bob")
	carol := h.active("carol")
	admin1 := h.active("root1", RoleAdmin, RoleCustomer)
	admin2 := h.active("root2", RoleAdmin, RoleCustomer)

	del := func(ctx context.Context, id uuid.UUID) error {
		_, err := h.svc.DeleteUser(ctx, &userv1.DeleteUserRequest{Id: id.String()})
		return err
	}
	wantCode(t, del(as(bob.ID, RoleCustomer), alice.ID), codes.NotFound)
	if _, err := h.store.GetUser(context.Background(), alice.ID); err != nil {
		t.Fatal("alice should still exist")
	}
	wantCode(t, del(as(alice.ID, RoleCustomer), alice.ID), codes.OK)
	wantCode(t, del(as(alice.ID, RoleCustomer), alice.ID), codes.NotFound) // repeat on a missing row
	wantCode(t, del(as(admin1.ID, RoleAdmin), carol.ID), codes.OK)
	wantCode(t, del(as(admin1.ID, RoleAdmin), admin2.ID), codes.OK)
	wantCode(t, del(as(admin1.ID, RoleAdmin), admin1.ID), codes.FailedPrecondition) // last admin
	wantCode(t, del(as(admin1.ID, RoleAdmin), uuid.New()), codes.NotFound)
	_, err := h.svc.DeleteUser(as(bob.ID), &userv1.DeleteUserRequest{Id: "x"})
	wantCode(t, err, codes.InvalidArgument)
}

func TestListUsers(t *testing.T) {
	h := newHarness(t)
	admin := h.active("root", RoleAdmin)
	cust := h.active("cust")
	for i := 0; i < 5; i++ {
		h.active("user_" + string(rune('a'+i)))
	}

	t.Run("non-admin denied", func(t *testing.T) {
		_, err := h.svc.ListUsers(as(cust.ID, RoleCustomer), &userv1.ListUsersRequest{})
		wantCode(t, err, codes.PermissionDenied)
	})
	t.Run("bad token", func(t *testing.T) {
		_, err := h.svc.ListUsers(as(admin.ID, RoleAdmin), &userv1.ListUsersRequest{PageToken: "!!"})
		wantCode(t, err, codes.InvalidArgument)
	})
	t.Run("pages cover everyone exactly once in order", func(t *testing.T) {
		var seen []string
		token := ""
		pages := 0
		for {
			resp, err := h.svc.ListUsers(as(admin.ID, RoleAdmin), &userv1.ListUsersRequest{PageSize: 3, PageToken: token})
			wantCode(t, err, codes.OK)
			pages++
			for _, u := range resp.Users {
				seen = append(seen, u.Username)
			}
			if resp.NextPageToken == "" {
				if len(resp.Users) > 3 {
					t.Fatal("page larger than requested")
				}
				break
			}
			if len(resp.Users) != 3 {
				t.Fatalf("non-final page has %d users", len(resp.Users))
			}
			token = resp.NextPageToken
		}
		want := []string{"root", "cust", "user_a", "user_b", "user_c", "user_d", "user_e"}
		if pages != 3 || len(seen) != len(want) {
			t.Fatalf("pages=%d seen=%v", pages, seen)
		}
		for i := range want {
			if seen[i] != want[i] {
				t.Fatalf("order = %v, want %v", seen, want)
			}
		}
	})
	t.Run("exact boundary has no next token", func(t *testing.T) {
		resp, err := h.svc.ListUsers(as(admin.ID, RoleAdmin), &userv1.ListUsersRequest{PageSize: 7})
		wantCode(t, err, codes.OK)
		if len(resp.Users) != 7 || resp.NextPageToken != "" {
			t.Fatalf("got %d users, token %q", len(resp.Users), resp.NextPageToken)
		}
	})
	t.Run("no password material exposed", func(t *testing.T) {
		resp, _ := h.svc.ListUsers(as(admin.ID, RoleAdmin), &userv1.ListUsersRequest{})
		for _, u := range resp.Users {
			if contains(u.String(), "argon2") {
				t.Fatal("hash leaked")
			}
		}
	})
}
