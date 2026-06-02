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
	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// accessToken carries both the secret material and the Authorization scheme
// Okta returned, so the round tripper can pick `DPoP` or `Bearer` per the
// app's actual configuration (Require-DPoP=ON returns DPoP, OFF returns
// Bearer). Fields are immutable after construction.
type accessToken struct {
	value  string
	scheme string
	// expiry is the absolute moment after which the token is no longer accepted.
	expiry time.Time
}

func (t *accessToken) bindsDPoP() bool {
	return t != nil && strings.EqualFold(t.scheme, tokenSchemeDPoP)
}

type tokenGetter interface {
	Token(ctx context.Context) (*accessToken, error)
}

// tokenSource issues access tokens via private_key_jwt. We don't reuse
// dpop_oauth2.NewTokenSource because it hardcodes EdDSA for the client
// assertion and Okta API Services apps use RSA keys.
type tokenSource struct {
	cfg tokenSourceConfig

	mu     sync.Mutex
	cached *accessToken
	group  singleflight.Group
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
	clientAssertionType   = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	tokenRefreshBuffer    = 60 * time.Second
	defaultTokenLifetime  = time.Hour
	clientAssertionExpiry = 5 * time.Minute
	tokenSchemeDPoP       = "DPoP"
	tokenSchemeBearer     = "Bearer"
	useDPoPNonceErrorCode = "use_dpop_nonce"
	refreshTimeout        = 30 * time.Second
	errorBodyExcerptLimit = 200
)

func (t *tokenSource) Token(ctx context.Context) (*accessToken, error) {
	if cached := t.cachedValid(); cached != nil {
		return cached, nil
	}

	// DoChan + select means each caller honours its own ctx. The exchange runs
	// on a detached background ctx so a cancel from any one waiter cannot
	// abort the refresh the others are waiting on.
	ch := t.group.DoChan("refresh", func() (any, error) {
		if cached := t.cachedValid(); cached != nil {
			return cached, nil
		}
		bg, cancel := context.WithTimeout(context.Background(), refreshTimeout)
		defer cancel()
		tok, err := t.exchange(bg)
		if err != nil {
			return nil, err
		}
		t.mu.Lock()
		t.cached = tok
		t.mu.Unlock()
		return tok, nil
	})
	select {
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		return res.Val.(*accessToken), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (t *tokenSource) cachedValid() *accessToken {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cached != nil && t.cached.expiry.After(t.cfg.now().Add(tokenRefreshBuffer)) {
		return t.cached
	}
	return nil
}

func (t *tokenSource) exchange(ctx context.Context) (*accessToken, error) {
	for attempt := 0; attempt < 2; attempt++ {
		tok, retry, err := t.tryExchange(ctx)
		if err == nil {
			return tok, nil
		}
		if !retry {
			return nil, err
		}
	}
	return nil, status.Error(codes.Unavailable, "oktaauth: token endpoint demanded a fresh nonce twice in a row")
}

func (t *tokenSource) tryExchange(ctx context.Context) (*accessToken, bool, error) {
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

	//nolint:gosec // tokenURL fixed at construction from operator-provided Okta domain
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.cfg.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, false, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set(dpopHdr, proof)

	resp, err := t.cfg.httpClient.Do(req) //nolint:gosec // same fixed tokenURL as above
	if err != nil {
		return nil, false, status.Error(codes.Unavailable, fmt.Sprintf("token request: %v", err))
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
		errCode, errDesc := parseTokenError(body)
		if errCode == useDPoPNonceErrorCode {
			if resp.Header.Get(dpopNonceHdr) == "" {
				return nil, false, status.Error(codes.Unavailable, "token endpoint asked for a nonce but didn't supply DPoP-Nonce header")
			}
			return nil, true, errors.New("retry with nonce")
		}
		return nil, false, formatTokenError(resp.StatusCode, resp.Status, errCode, errDesc, body)
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
	scheme := normalizeTokenScheme(raw.TokenType)
	if scheme == "" {
		return nil, false, fmt.Errorf("unsupported token_type %q (expected DPoP or Bearer)", raw.TokenType)
	}

	expiresIn := raw.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = int64(defaultTokenLifetime / time.Second)
	}
	return &accessToken{
		value:  raw.AccessToken,
		scheme: scheme,
		expiry: t.cfg.now().Add(time.Duration(expiresIn) * time.Second),
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
		Expiry:   jwt.NewNumericDate(now.Add(clientAssertionExpiry)),
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

func parseTokenError(body []byte) (string, string) {
	var raw struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return "", ""
	}
	return raw.Error, raw.ErrorDescription
}

func formatTokenError(httpStatusCode int, httpStatus, code, desc string, rawBody []byte) error {
	var msg string
	switch {
	case code != "" && desc != "":
		msg = fmt.Sprintf("token endpoint %s: %s (%s)", httpStatus, code, desc)
	case code != "":
		msg = fmt.Sprintf("token endpoint %s: %s", httpStatus, code)
	default:
		excerpt := strings.TrimSpace(string(rawBody))
		if len(excerpt) > errorBodyExcerptLimit {
			excerpt = excerpt[:errorBodyExcerptLimit] + "..."
		}
		if excerpt != "" {
			msg = fmt.Sprintf("token endpoint %s: %s", httpStatus, excerpt)
		} else {
			msg = fmt.Sprintf("token endpoint %s", httpStatus)
		}
	}
	grpcCode := codes.Unauthenticated
	if httpStatusCode >= 500 {
		grpcCode = codes.Unavailable
	}
	return status.Error(grpcCode, msg)
}

func normalizeTokenScheme(s string) string {
	switch strings.ToLower(s) {
	case "dpop":
		return tokenSchemeDPoP
	case "bearer":
		return tokenSchemeBearer
	}
	return ""
}
