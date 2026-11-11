package service

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthnAdapter wraps *webauthn.WebAuthn so that *webauthn.WebAuthn satisfies
// WebAuthnVerifier without exposing *http.Request to the service layer.
// This is the production implementation; tests inject their own fakes.
type WebAuthnAdapter struct {
	wa *webauthn.WebAuthn
}

// NewWebAuthnAdapter wraps wa. Use this in main.go instead of passing wa directly.
func NewWebAuthnAdapter(wa *webauthn.WebAuthn) *WebAuthnAdapter {
	return &WebAuthnAdapter{wa: wa}
}

var _ WebAuthnVerifier = (*WebAuthnAdapter)(nil)

func (a *WebAuthnAdapter) BeginRegistration(user webauthn.User, opts ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	return a.wa.BeginRegistration(user, opts...)
}

// ValidateRegistration re-encodes the parsed response to JSON and delegates
// to FinishRegistration via an *http.Request — the only public API in v0.18.
func (a *WebAuthnAdapter) ValidateRegistration(user webauthn.User, session webauthn.SessionData, response *protocol.ParsedCredentialCreationData) (*webauthn.Credential, error) {
	b, err := json.Marshal(response.Raw)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, "/", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return a.wa.FinishRegistration(user, session, req)
}

func (a *WebAuthnAdapter) BeginDiscoverableLogin(opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	return a.wa.BeginDiscoverableLogin(opts...)
}

func (a *WebAuthnAdapter) ValidateDiscoverableLogin(handler webauthn.DiscoverableUserHandler, session webauthn.SessionData, response *protocol.ParsedCredentialAssertionData) (*webauthn.Credential, error) {
	return a.wa.ValidateDiscoverableLogin(handler, session, response)
}
