// Package oktaauth builds a DPoP-aware *http.Client for the Okta OAuth 2.0
// private_key_jwt flow (RFC 7523 + RFC 9449). The returned client is fed into
// both the v2 and v5 Okta SDKs in "Bearer" authorization mode: the RoundTripper
// owns the access token, the DPoP proof JWT, and the use_dpop_nonce dance.
package oktaauth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/conductorone/dpop/integrations/dpop_oauth2"
	"github.com/conductorone/dpop/pkg/dpop"
	"github.com/go-jose/go-jose/v4"
)

const (
	tokenPath          = "/oauth2/v1/token" //nolint:gosec // not a credential; the OAuth 2.0 token endpoint path
	dpopTelemetryUA    = "isDPoP:true"
	authorizationHdr   = "Authorization"
	dpopHdr            = "DPoP"
	dpopNonceHdr       = "DPoP-Nonce"
	wwwAuthenticateHdr = "WWW-Authenticate"
	userAgentExtHdr    = "x-okta-user-agent-extended"
)

type Config struct {
	Domain        string
	ClientID      string
	PrivateKeyPEM string
	PrivateKeyID  string
	Scopes        []string
}

func NewDPoPHTTPClient(ctx context.Context, cfg Config, baseClient *http.Client) (*http.Client, error) {
	if cfg.Domain == "" {
		return nil, errors.New("oktaauth: Domain is required")
	}
	if cfg.ClientID == "" {
		return nil, errors.New("oktaauth: ClientID is required")
	}
	if cfg.PrivateKeyID == "" {
		return nil, errors.New("oktaauth: PrivateKeyID is required")
	}
	if cfg.PrivateKeyPEM == "" {
		return nil, errors.New("oktaauth: PrivateKeyPEM is required")
	}
	if len(cfg.Scopes) == 0 {
		return nil, errors.New("oktaauth: Scopes must be non-empty")
	}

	rsaKey, err := parseRSAPrivateKey(cfg.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("oktaauth: parse private key: %w", err)
	}

	jwk := &jose.JSONWebKey{
		Key:       rsaKey,
		KeyID:     cfg.PrivateKeyID,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}

	proofer, err := dpop.NewProofer(jwk)
	if err != nil {
		return nil, fmt.Errorf("oktaauth: build dpop proofer: %w", err)
	}

	tokenURL := fmt.Sprintf("https://%s%s", strings.TrimSuffix(cfg.Domain, "/"), tokenPath)

	tokenNonceStore := dpop_oauth2.NewNonceStore()
	resourceNonceStore := dpop_oauth2.NewNonceStore()

	inner := transportOrDefault(baseClient)

	ts := newTokenSource(tokenSourceConfig{
		tokenURL:   tokenURL,
		clientID:   cfg.ClientID,
		signingKey: jwk,
		scopes:     cfg.Scopes,
		proofer:    proofer,
		nonceStore: tokenNonceStore,
		httpClient: &http.Client{Transport: inner, Timeout: 30 * time.Second},
		now:        time.Now,
	})

	rt := &dpopRoundTripper{
		inner:              inner,
		proofer:            proofer,
		tokenSource:        ts,
		resourceNonceStore: resourceNonceStore,
	}

	out := &http.Client{Transport: rt}
	if baseClient != nil {
		out.Timeout = baseClient.Timeout
	}
	return out, nil
}

func transportOrDefault(c *http.Client) http.RoundTripper {
	if c == nil || c.Transport == nil {
		return http.DefaultTransport
	}
	return c.Transport
}

func parseRSAPrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("unsupported key type %T: Okta DPoP requires RSA", key)
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
}
