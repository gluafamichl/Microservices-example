// Package config loads the users service configuration from the environment.
package config

import (
	"errors"
	"fmt"
	"time"

	"github.com/francispowlesland/microservices-app-go/internal/platform/config"
)

// Config is the typed users service configuration.
type Config struct {
	GRPCAddr      string
	DatabaseURL   string
	AppEnv        string
	JWTPrivateKey string
	AccessTTL     time.Duration
	RefreshTTL    time.Duration
	Mailer        string

	BootstrapAdminEmail    string
	BootstrapAdminPassword string

	// WebAuthn
	WebAuthnRPID     string
	WebAuthnRPOrigin string
}

// Load reads and validates the configuration.
func Load() (Config, error) {
	var (
		c   Config
		err error
	)
	c.GRPCAddr = config.String("GRPC_ADDR", ":50051")
	c.AppEnv = config.String("APP_ENV", "development")
	c.Mailer = config.String("MAILER", "log")
	c.BootstrapAdminEmail = config.String("BOOTSTRAP_ADMIN_EMAIL", "")
	c.BootstrapAdminPassword = config.String("BOOTSTRAP_ADMIN_PASSWORD", "")

	if c.DatabaseURL, err = config.Required("DATABASE_URL"); err != nil {
		return Config{}, err
	}
	if c.JWTPrivateKey, err = config.Required("JWT_PRIVATE_KEY"); err != nil {
		return Config{}, err
	}
	if c.AccessTTL, err = config.Duration("ACCESS_TOKEN_TTL", 15*time.Minute); err != nil {
		return Config{}, err
	}
	if c.RefreshTTL, err = config.Duration("REFRESH_TOKEN_TTL", 720*time.Hour); err != nil {
		return Config{}, err
	}
	if c.WebAuthnRPID, err = config.Required("WEBAUTHN_RP_ID"); err != nil {
		return Config{}, err
	}
	if c.WebAuthnRPOrigin, err = config.Required("WEBAUTHN_RP_ORIGIN"); err != nil {
		return Config{}, err
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Validate checks cross-field rules.
func (c Config) Validate() error {
	switch c.AppEnv {
	case "development", "production":
	default:
		return fmt.Errorf("APP_ENV must be %q or %q, got %q", "development", "production", c.AppEnv)
	}
	if c.Mailer != "log" {
		return fmt.Errorf("MAILER must be %q (the only implementation), got %q", "log", c.Mailer)
	}
	if c.Mailer == "log" && c.AppEnv == "production" {
		return errors.New("MAILER=log is not allowed when APP_ENV=production: it would write tokens to the log and no real email would be sent; set APP_ENV=development for local runs")
	}
	if c.AccessTTL <= 0 || c.RefreshTTL <= 0 {
		return errors.New("ACCESS_TOKEN_TTL and REFRESH_TOKEN_TTL must be positive")
	}
	if (c.BootstrapAdminEmail == "") != (c.BootstrapAdminPassword == "") {
		return errors.New("BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD must be set together")
	}
	return nil
}
