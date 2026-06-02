package oktaauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/conductorone/dpop/integrations/dpop_oauth2"
	"github.com/conductorone/dpop/pkg/dpop"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

// tokenSource issues DPoP-bound access tokens via private_key_jwt. We don't
// reuse dpop_oauth2.NewTokenSource because it hardcodes EdDSA for the client
// assertion and Okta API Services apps use RSA keys.
type tokenSource struct {
	cfg tokenSourceConfig

	mu     sync.Mutex
	cached *oauth2.Token
}

type tokenSourceConfig struct {
	tokenURL   string
	clientID   string
	signingKey *jose.JSONWebKey
	scopes     []string
	proofer    *dpop.Proofer
	nonceStore *dpop_oauth2.NonceStore
	httpClient *http.Client
	now        func() time.Time
}

func newTokenSource(cfg tokenSourceConfig) *tokenSource {
	if cfg.now == nil {
		cfg.now = time.Now
	}
	return &tokenSource{cfg: cfg}
}

const (
	clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	tokenRefreshBuffer  = 60 * time.Second
	tokenTypeDPoP       = "DPoP"
)

func (t *tokenSource) Token() (*oauth2.Token, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.cfg.now()
	if t.cached != nil && t.cached.Expiry.After(now.Add(tokenRefreshBuffer)) {
		return t.cached, nil
	}

	tok, err := t.exchange(context.Background())
	if err != nil {
		return nil, err
	}
	t.cached = tok
	return tok, nil
}

func (t *tokenSource) exchange(ctx context.Context) (*oauth2.Token, error) {
	for attempt := 0; attempt < 2; attempt++ {
		tok, retry, err := t.tryExchange(ctx)
		if err == nil {
			return tok, nil
		}
		if !retry {
			return nil, err
		}
	}
	return nil, errors.New("oktaauth: token endpoint requested nonce retry twice")
}

func (t *tokenSource) tryExchange(ctx context.Context) (*oauth2.Token, bool, error) {
	assertion, err := t.signClientAssertion()
	if err != nil {
		return nil, false, fmt.Errorf("sign client assertion: %w", err)
	}

	proof, err := t.cfg.proofer.CreateProof(ctx, http.MethodPost, t.cfg.tokenURL,
		dpop.WithNonceFunc(t.nonceFunc()),
		dpop.WithProofNowFunc(t.cfg.now),
	)
	if err != nil {
		return nil, false, fmt.Errorf("create dpop proof: %w", err)
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_assertion_type", clientAssertionType)
	form.Set("client_assertion", assertion)
	if len(t.cfg.scopes) > 0 {
		form.Set("scope", strings.Join(t.cfg.scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.cfg.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, false, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set(dpopHdr, proof)

	resp, err := t.cfg.httpClient.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	if nonce := resp.Header.Get(dpopNonceHdr); nonce != "" {
		t.cfg.nonceStore.SetNonce(nonce)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, fmt.Errorf("read token response: %w", err)
	}

	if resp.StatusCode >= 400 {
		if isUseDPoPNonce(body) && resp.Header.Get(dpopNonceHdr) != "" {
			return nil, true, fmt.Errorf("token endpoint requested dpop nonce")
		}
		return nil, false, fmt.Errorf("token endpoint %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var raw struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, false, fmt.Errorf("decode token response: %w", err)
	}
	if raw.AccessToken == "" {
		return nil, false, errors.New("token endpoint returned empty access_token")
	}
	if !strings.EqualFold(raw.TokenType, tokenTypeDPoP) {
		return nil, false, fmt.Errorf("expected DPoP token_type, got %q", raw.TokenType)
	}

	expiresIn := raw.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600
	}
	return &oauth2.Token{
		AccessToken: raw.AccessToken,
		TokenType:   raw.TokenType,
		Expiry:      t.cfg.now().Add(time.Duration(expiresIn) * time.Second),
	}, false, nil
}

func (t *tokenSource) nonceFunc() func() (string, error) {
	return func() (string, error) {
		return t.cfg.nonceStore.GetNonce(), nil
	}
}

func (t *tokenSource) signClientAssertion() (string, error) {
	now := t.cfg.now()
	claims := jwt.Claims{
		Issuer:   t.cfg.clientID,
		Subject:  t.cfg.clientID,
		Audience: jwt.Audience{t.cfg.tokenURL},
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(5 * time.Minute)),
		ID:       uuid.NewString(),
	}

	signerOpts := (&jose.SignerOptions{}).
		WithType("JWT").
		WithHeader("kid", t.cfg.signingKey.KeyID)

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: t.cfg.signingKey.Key}, signerOpts)
	if err != nil {
		return "", err
	}
	return jwt.Signed(signer).Claims(claims).Serialize()
}

func isUseDPoPNonce(body []byte) bool {
	return strings.Contains(string(body), "use_dpop_nonce")
}
