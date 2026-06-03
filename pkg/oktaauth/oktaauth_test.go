package oktaauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/conductorone/dpop/integrations/dpop_oauth2"
	"github.com/conductorone/dpop/pkg/dpop"
	"github.com/go-jose/go-jose/v4"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func generateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa: %v", err)
	}
	return key
}

func pemPKCS1(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	der := x509.MarshalPKCS1PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}))
}

func pemPKCS8(t *testing.T, key any) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("pkcs8 marshal: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func decodeJWTPayload(t *testing.T, jwt string) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 jwt parts, got %d", len(parts))
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return out
}

// tokenHandler is a stub /oauth2/v1/token: returns 400 use_dpop_nonce on the
// listed call numbers, otherwise a token (default token_type=DPoP).
type tokenHandler struct {
	calls          atomic.Int32
	requireNonceOn []int
	nonce          string
	tokenType      string
}

func (h *tokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	call := int(h.calls.Add(1))
	for _, n := range h.requireNonceOn {
		if call == n {
			w.Header().Set("DPoP-Nonce", h.nonce)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"use_dpop_nonce","error_description":"Authorization server requires nonce in DPoP proof."}`))
			return
		}
	}
	tt := h.tokenType
	if tt == "" {
		tt = "DPoP"
	}
	body, _ := json.Marshal(map[string]any{
		"access_token": "abc.def.ghi",
		"token_type":   tt,
		"expires_in":   3600,
		"scope":        "okta.users.read",
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func newTestTokenSource(t *testing.T, server *httptest.Server, key *rsa.PrivateKey, now func() time.Time) *tokenSource {
	t.Helper()
	jwk := &jose.JSONWebKey{Key: key, KeyID: "kid-1", Algorithm: string(jose.RS256), Use: "sig"}
	p, err := dpop.NewProofer(jwk)
	if err != nil {
		t.Fatalf("proofer: %v", err)
	}
	return newTokenSource(tokenSourceConfig{
		tokenURL:   server.URL + "/oauth2/v1/token",
		clientID:   "client-xyz",
		signingKey: jwk,
		scopes:     []string{"okta.users.read"},
		proofer:    p,
		nonceStore: dpop_oauth2.NewNonceStore(),
		httpClient: server.Client(),
		now:        now,
	})
}

func TestTokenSource_NonceRetry(t *testing.T) {
	key := generateRSAKey(t)

	type observed struct{ proofNonce string }
	obs := make([]observed, 0, 2)
	var mu sync.Mutex

	mux := http.NewServeMux()
	h := &tokenHandler{requireNonceOn: []int{1}, nonce: "srv-nonce-1"}
	mux.Handle("/oauth2/v1/token", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proof := r.Header.Get("DPoP")
		var nonce string
		if proof != "" {
			payload := decodeJWTPayload(t, proof)
			if v, ok := payload["nonce"].(string); ok {
				nonce = v
			}
		}
		mu.Lock()
		obs = append(obs, observed{proofNonce: nonce})
		mu.Unlock()
		h.ServeHTTP(w, r)
	}))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ts := newTestTokenSource(t, srv, key, time.Now)
	tok, err := ts.Token(t.Context())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok.value == "" {
		t.Fatal("empty access token")
	}
	if got := h.calls.Load(); got != 2 {
		t.Fatalf("expected 2 token calls, got %d", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if obs[0].proofNonce != "" {
		t.Fatalf("first proof should have empty nonce, got %q", obs[0].proofNonce)
	}
	if obs[1].proofNonce != "srv-nonce-1" {
		t.Fatalf("second proof should carry server nonce, got %q", obs[1].proofNonce)
	}
}

func TestTokenSource_GivesUpAfterTwoNonceChallenges(t *testing.T) {
	key := generateRSAKey(t)
	h := &tokenHandler{requireNonceOn: []int{1, 2}, nonce: "n"}
	srv := httptest.NewServer(h)
	defer srv.Close()

	ts := newTestTokenSource(t, srv, key, time.Now)
	_, err := ts.Token(t.Context())
	if err == nil {
		t.Fatal("expected give-up error after two nonce challenges")
	}
	if !strings.Contains(err.Error(), "twice") {
		t.Fatalf("error should mention 'twice', got: %v", err)
	}
	if got := h.calls.Load(); got != 2 {
		t.Fatalf("expected 2 calls before giving up, got %d", got)
	}
}

func TestTokenSource_RejectsNonRSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen ecdsa: %v", err)
	}
	_, err = NewDPoPHTTPClient(t.Context(), Config{
		Domain:        "example.okta.com",
		ClientID:      "c",
		PrivateKeyID:  "k",
		PrivateKeyPEM: pemPKCS8(t, key),
		Scopes:        []string{"okta.users.read"},
	}, nil)
	if err == nil {
		t.Fatal("expected error for ECDSA key")
	}
	if !strings.Contains(err.Error(), "RSA") {
		t.Fatalf("error should mention RSA: %v", err)
	}
}

func TestTokenSource_BearerTokenAccepted(t *testing.T) {
	key := generateRSAKey(t)
	h := &tokenHandler{tokenType: "Bearer"}
	srv := httptest.NewServer(h)
	defer srv.Close()

	ts := newTestTokenSource(t, srv, key, time.Now)
	tok, err := ts.Token(t.Context())
	if err != nil {
		t.Fatalf("Bearer token should be accepted, got: %v", err)
	}
	if tok.scheme != "Bearer" {
		t.Fatalf("scheme = %q, want Bearer", tok.scheme)
	}
	if tok.bindsDPoP() {
		t.Fatal("Bearer token must not bind DPoP")
	}
}

func TestTokenSource_RejectsUnknownTokenType(t *testing.T) {
	key := generateRSAKey(t)
	h := &tokenHandler{tokenType: "MAC"}
	srv := httptest.NewServer(h)
	defer srv.Close()

	ts := newTestTokenSource(t, srv, key, time.Now)
	_, err := ts.Token(t.Context())
	if err == nil || !strings.Contains(err.Error(), "MAC") {
		t.Fatalf("expected error mentioning MAC, got: %v", err)
	}
}

func TestTokenSource_RejectsEmptyAccessToken(t *testing.T) {
	key := generateRSAKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token_type":"DPoP","expires_in":3600,"access_token":""}`))
	}))
	defer srv.Close()

	ts := newTestTokenSource(t, srv, key, time.Now)
	_, err := ts.Token(t.Context())
	if err == nil || !strings.Contains(err.Error(), "empty access_token") {
		t.Fatalf("expected empty-access_token error, got: %v", err)
	}
}

func TestTokenSource_CachesUntilExpiry(t *testing.T) {
	key := generateRSAKey(t)
	h := &tokenHandler{}
	srv := httptest.NewServer(h)
	defer srv.Close()

	cur := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := func() time.Time { return cur }
	ts := newTestTokenSource(t, srv, key, now)

	tok1, err := ts.Token(t.Context())
	if err != nil {
		t.Fatalf("first Token: %v", err)
	}
	tok2, err := ts.Token(t.Context())
	if err != nil {
		t.Fatalf("second Token: %v", err)
	}
	if tok1 != tok2 {
		t.Fatal("expected cached token reuse, got fresh pointer")
	}
	if got := h.calls.Load(); got != 1 {
		t.Fatalf("expected 1 token call, got %d", got)
	}

	cur = cur.Add(3600*time.Second - 30*time.Second)
	if _, err := ts.Token(t.Context()); err != nil {
		t.Fatalf("third Token (post-refresh): %v", err)
	}
	if got := h.calls.Load(); got != 2 {
		t.Fatalf("expected 2 token calls after expiry, got %d", got)
	}
}

func TestTokenSource_ErrorMessageHidesRawBody(t *testing.T) {
	key := generateRSAKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"bad kid","internal_token":"secretXYZ"}`))
	}))
	defer srv.Close()

	ts := newTestTokenSource(t, srv, key, time.Now)
	_, err := ts.Token(t.Context())
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "secretXYZ") {
		t.Fatalf("error message should not echo raw body, got: %v", err)
	}
	if !strings.Contains(err.Error(), "invalid_client") || !strings.Contains(err.Error(), "bad kid") {
		t.Fatalf("error should include code+description, got: %v", err)
	}
}

func TestParseRSAPrivateKey(t *testing.T) {
	rsaKey := generateRSAKey(t)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	cases := []struct {
		name      string
		pem       string
		wantErr   string
		wantOK    bool
	}{
		{name: "PKCS1", pem: pemPKCS1(t, rsaKey), wantOK: true},
		{name: "PKCS8_RSA", pem: pemPKCS8(t, rsaKey), wantOK: true},
		{name: "PKCS8_ECDSA", pem: pemPKCS8(t, ecKey), wantErr: "Okta DPoP requires RSA"},
		{name: "empty", pem: "", wantErr: "no PEM block found"},
		{name: "garbage", pem: "not-a-pem", wantErr: "no PEM block found"},
		{name: "wrong_type", pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0}})), wantErr: "unsupported PEM block type"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseRSAPrivateKey(c.pem)
			if c.wantOK {
				if err != nil || got == nil {
					t.Fatalf("want ok, got err=%v key=%v", err, got)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("want error containing %q, got: %v", c.wantErr, err)
			}
		})
	}
}

type fakeTokenSource struct{ tok *accessToken }

func (f *fakeTokenSource) Token(context.Context) (*accessToken, error) { return f.tok, nil }

func newRoundTripperForTest(t *testing.T, key *rsa.PrivateKey, tok *accessToken, ns *dpop_oauth2.NonceStore, inner http.RoundTripper) *dpopRoundTripper {
	t.Helper()
	jwk := &jose.JSONWebKey{Key: key, KeyID: "kid-1", Algorithm: string(jose.RS256), Use: "sig"}
	p, err := dpop.NewProofer(jwk)
	if err != nil {
		t.Fatalf("proofer: %v", err)
	}
	return &dpopRoundTripper{
		inner:              inner,
		proofer:            p,
		tokenSource:        &fakeTokenSource{tok: tok},
		resourceNonceStore: ns,
	}
}

func dpopAccessToken(value string) *accessToken {
	return &accessToken{value: value, scheme: "DPoP", expiry: time.Now().Add(time.Hour)}
}

func bearerAccessToken(value string) *accessToken {
	return &accessToken{value: value, scheme: "Bearer", expiry: time.Now().Add(time.Hour)}
}

func TestRoundTripper_AddsAuthAndProof(t *testing.T) {
	key := generateRSAKey(t)
	var captured *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Clone(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rt := newRoundTripperForTest(t, key, dpopAccessToken("tok-A"), dpop_oauth2.NewNonceStore(), http.DefaultTransport)
	c := &http.Client{Transport: rt}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v1/users", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()

	if got := captured.Header.Get("Authorization"); got != "DPoP tok-A" {
		t.Fatalf("Authorization = %q", got)
	}
	if got := captured.Header.Get("DPoP"); got == "" {
		t.Fatal("DPoP header missing")
	}
	if got := captured.Header.Get("x-okta-user-agent-extended"); got != "isDPoP:true" {
		t.Fatalf("telemetry header = %q", got)
	}
}

func TestRoundTripper_BearerTokenSkipsDPoP(t *testing.T) {
	key := generateRSAKey(t)
	var captured *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Clone(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rt := newRoundTripperForTest(t, key, bearerAccessToken("tok-B"), dpop_oauth2.NewNonceStore(), http.DefaultTransport)
	c := &http.Client{Transport: rt}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v1/users", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()

	if got := captured.Header.Get("Authorization"); got != "Bearer tok-B" {
		t.Fatalf("Authorization = %q, want Bearer tok-B", got)
	}
	if got := captured.Header.Get("DPoP"); got != "" {
		t.Fatalf("DPoP header should be absent for Bearer tokens, got: %q", got)
	}
	if got := captured.Header.Get("x-okta-user-agent-extended"); got != "" {
		t.Fatalf("telemetry header should be absent for Bearer, got: %q", got)
	}
}

func TestRoundTripper_ReplacesPreExistingAuthorization(t *testing.T) {
	key := generateRSAKey(t)
	var captured *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Clone(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rt := newRoundTripperForTest(t, key, dpopAccessToken("tok-replace"), dpop_oauth2.NewNonceStore(), http.DefaultTransport)
	c := &http.Client{Transport: rt}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v1/users", nil)
	req.Header.Set("Authorization", "Bearer stale-placeholder")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()

	vals := captured.Header.Values("Authorization")
	if len(vals) != 1 {
		t.Fatalf("expected exactly one Authorization header, got %d: %v", len(vals), vals)
	}
	if vals[0] != "DPoP tok-replace" {
		t.Fatalf("Authorization = %q, want DPoP tok-replace", vals[0])
	}
}

func TestRoundTripper_AthClaim(t *testing.T) {
	key := generateRSAKey(t)
	token := "tok-with-bytes" //nolint:gosec // test fixture
	var proof string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proof = r.Header.Get("DPoP")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rt := newRoundTripperForTest(t, key, dpopAccessToken(token), dpop_oauth2.NewNonceStore(), http.DefaultTransport)
	c := &http.Client{Transport: rt}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v1/users", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()

	payload := decodeJWTPayload(t, proof)
	ath, _ := payload["ath"].(string)
	hash := sha256.Sum256([]byte(token))
	expected := base64.RawURLEncoding.EncodeToString(hash[:])
	if ath != expected {
		t.Fatalf("ath = %q, want %q", ath, expected)
	}
}

func TestRoundTripper_HtmMatchesMethod(t *testing.T) {
	key := generateRSAKey(t)
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			var proof string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				proof = r.Header.Get("DPoP")
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()
			rt := newRoundTripperForTest(t, key, dpopAccessToken("t"), dpop_oauth2.NewNonceStore(), http.DefaultTransport)
			c := &http.Client{Transport: rt}
			req, _ := http.NewRequestWithContext(t.Context(), method, srv.URL+"/api/v1/x", nil)
			resp, err := c.Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			_ = resp.Body.Close()
			payload := decodeJWTPayload(t, proof)
			if got, _ := payload["htm"].(string); got != method {
				t.Fatalf("htm = %q, want %q", got, method)
			}
		})
	}
}

func TestRoundTripper_HtuShape(t *testing.T) {
	key := generateRSAKey(t)
	for _, suffix := range []string{"/api/v1/users?limit=200&filter=foo", "/api/v1/users#frag", "/"} {
		t.Run(suffix, func(t *testing.T) {
			var proof string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				proof = r.Header.Get("DPoP")
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()
			rt := newRoundTripperForTest(t, key, dpopAccessToken("t"), dpop_oauth2.NewNonceStore(), http.DefaultTransport)
			c := &http.Client{Transport: rt}
			req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+suffix, nil)
			resp, err := c.Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			_ = resp.Body.Close()
			payload := decodeJWTPayload(t, proof)
			htu, _ := payload["htu"].(string)
			u, err := url.Parse(htu)
			if err != nil {
				t.Fatalf("parse htu: %v", err)
			}
			if u.RawQuery != "" || u.Fragment != "" {
				t.Fatalf("htu should have no query/fragment: %q", htu)
			}
		})
	}
}

func TestRoundTripper_ResourceNonceRetry(t *testing.T) {
	key := generateRSAKey(t)
	var calls atomic.Int32
	var secondProof string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.Header().Set("DPoP-Nonce", "res-nonce-X")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		secondProof = r.Header.Get("DPoP")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ns := dpop_oauth2.NewNonceStore()
	rt := newRoundTripperForTest(t, key, dpopAccessToken("tok-D"), ns, http.DefaultTransport)
	c := &http.Client{Transport: rt}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v1/groups", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()

	if got := calls.Load(); got != 2 {
		t.Fatalf("expected 2 calls, got %d", got)
	}
	payload := decodeJWTPayload(t, secondProof)
	if got, _ := payload["nonce"].(string); got != "res-nonce-X" {
		t.Fatalf("retry nonce = %q, want %q", got, "res-nonce-X")
	}
	if ns.GetNonce() != "res-nonce-X" {
		t.Fatalf("nonce store should hold last server nonce, got %q", ns.GetNonce())
	}
}

func TestRoundTripper_CapturesNonceOn200(t *testing.T) {
	key := generateRSAKey(t)
	var capturedProof string
	var seq atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := seq.Add(1)
		if n == 1 {
			w.Header().Set("DPoP-Nonce", "from-200")
			w.WriteHeader(http.StatusOK)
			return
		}
		capturedProof = r.Header.Get("DPoP")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ns := dpop_oauth2.NewNonceStore()
	rt := newRoundTripperForTest(t, key, dpopAccessToken("t"), ns, http.DefaultTransport)
	c := &http.Client{Transport: rt}
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v1/users", nil)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("Do[%d]: %v", i, err)
		}
		_ = resp.Body.Close()
	}
	if ns.GetNonce() != "from-200" {
		t.Fatalf("nonce store = %q, want from-200", ns.GetNonce())
	}
	payload := decodeJWTPayload(t, capturedProof)
	if got, _ := payload["nonce"].(string); got != "from-200" {
		t.Fatalf("second proof nonce = %q, want from-200", got)
	}
}

func TestRoundTripper_NoRetryOnNonReplayable(t *testing.T) {
	key := generateRSAKey(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
		w.Header().Set("DPoP-Nonce", "n")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	rt := newRoundTripperForTest(t, key, dpopAccessToken("t"), dpop_oauth2.NewNonceStore(), http.DefaultTransport)
	c := &http.Client{Transport: rt}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/api/v1/users", strings.NewReader(`{"x":1}`))
	req.GetBody = nil
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()

	if got := calls.Load(); got != 1 {
		t.Fatalf("expected 1 call (no retry on non-rewindable POST), got %d", got)
	}
}

func TestRoundTripper_RetryOnRewindablePOST(t *testing.T) {
	key := generateRSAKey(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"x":1}` {
			t.Errorf("body = %q on call %d", string(body), calls.Load()+1)
		}
		n := calls.Add(1)
		if n == 1 {
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.Header().Set("DPoP-Nonce", "n")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rt := newRoundTripperForTest(t, key, dpopAccessToken("t"), dpop_oauth2.NewNonceStore(), http.DefaultTransport)
	c := &http.Client{Transport: rt}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/api/v1/users", strings.NewReader(`{"x":1}`))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()

	if got := calls.Load(); got != 2 {
		t.Fatalf("expected 2 calls (POST with rewindable body), got %d", got)
	}
}

func TestRoundTripper_ReplayableGate(t *testing.T) {
	cases := []struct {
		name    string
		method  string
		body    io.Reader
		nilBody bool
		want    bool
	}{
		{name: "GET", method: http.MethodGet, want: true},
		{name: "HEAD", method: http.MethodHead, want: true},
		{name: "OPTIONS", method: http.MethodOptions, want: true},
		{name: "DELETE", method: http.MethodDelete, want: true},
		{name: "POST_rewindable", method: http.MethodPost, body: strings.NewReader(`{}`), want: true},
		{name: "POST_no_body", method: http.MethodPost, nilBody: true, want: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var req *http.Request
			if c.nilBody {
				req, _ = http.NewRequestWithContext(t.Context(), c.method, "https://x/y", nil)
				req.GetBody = nil
			} else {
				req, _ = http.NewRequestWithContext(t.Context(), c.method, "https://x/y", c.body)
			}
			if got := isReplayable(req); got != c.want {
				t.Fatalf("isReplayable(%s) = %v, want %v", c.method, got, c.want)
			}
		})
	}
}

func TestRoundTripper_JtiUniqueAcrossRetry(t *testing.T) {
	key := generateRSAKey(t)
	var proofs []string
	var mu sync.Mutex
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		proofs = append(proofs, r.Header.Get("DPoP"))
		mu.Unlock()
		if calls.Add(1) == 1 {
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.Header().Set("DPoP-Nonce", "n")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rt := newRoundTripperForTest(t, key, dpopAccessToken("t"), dpop_oauth2.NewNonceStore(), http.DefaultTransport)
	c := &http.Client{Transport: rt}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/x", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(proofs) != 2 {
		t.Fatalf("expected 2 proofs, got %d", len(proofs))
	}
	jti1, _ := decodeJWTPayload(t, proofs[0])["jti"].(string)
	jti2, _ := decodeJWTPayload(t, proofs[1])["jti"].(string)
	if jti1 == "" || jti2 == "" {
		t.Fatalf("jti missing: %q %q", jti1, jti2)
	}
	if jti1 == jti2 {
		t.Fatal("jti must be fresh per proof")
	}
}

func TestTokenSource_NonceStoreIsolation(t *testing.T) {
	// Verifies token-endpoint and resource-server nonces stay in separate stores.
	key := generateRSAKey(t)

	tokenH := &tokenHandler{requireNonceOn: []int{1}, nonce: "tok-nonce"}
	tokenSrv := httptest.NewServer(tokenH)
	defer tokenSrv.Close()

	var resourceProofNonce string
	resourceSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("DPoP-Nonce", "res-nonce")
		proof := r.Header.Get("DPoP")
		if proof != "" {
			if v, ok := decodeJWTPayload(t, proof)["nonce"].(string); ok {
				resourceProofNonce = v
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer resourceSrv.Close()

	ts := newTestTokenSource(t, tokenSrv, key, time.Now)
	tok, err := ts.Token(t.Context())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if ts.cfg.nonceStore.GetNonce() != "tok-nonce" {
		t.Fatalf("token nonce store = %q, want tok-nonce", ts.cfg.nonceStore.GetNonce())
	}

	resNS := dpop_oauth2.NewNonceStore()
	rt := newRoundTripperForTest(t, key, tok, resNS, http.DefaultTransport)
	c := &http.Client{Transport: rt}

	req1, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, resourceSrv.URL+"/x", nil)
	resp1, err := c.Do(req1)
	if err != nil {
		t.Fatalf("Do[1]: %v", err)
	}
	_ = resp1.Body.Close()
	if resourceProofNonce != "" {
		t.Fatalf("first resource proof nonce should be empty, got %q", resourceProofNonce)
	}
	if resNS.GetNonce() != "res-nonce" {
		t.Fatalf("resource nonce store = %q, want res-nonce", resNS.GetNonce())
	}

	req2, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, resourceSrv.URL+"/x", nil)
	resp2, err := c.Do(req2)
	if err != nil {
		t.Fatalf("Do[2]: %v", err)
	}
	_ = resp2.Body.Close()
	if resourceProofNonce != "res-nonce" {
		t.Fatalf("second resource proof nonce = %q, want res-nonce", resourceProofNonce)
	}
	if ts.cfg.nonceStore.GetNonce() == "res-nonce" {
		t.Fatal("token nonce store leaked resource nonce")
	}
}

func TestTokenSource_ClientAssertionExpiry(t *testing.T) {
	key := generateRSAKey(t)
	var capturedAssertion string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil { //nolint:gosec // test fixture; body size bounded by httptest
			t.Fatalf("parse form: %v", err)
		}
		capturedAssertion = r.PostForm.Get("client_assertion")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"x","token_type":"DPoP","expires_in":3600}`))
	}))
	defer srv.Close()

	fixed := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	ts := newTestTokenSource(t, srv, key, func() time.Time { return fixed })
	if _, err := ts.Token(t.Context()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	payload := decodeJWTPayload(t, capturedAssertion)
	iat, _ := payload["iat"].(float64)
	exp, _ := payload["exp"].(float64)
	if delta := exp - iat; delta != 300 {
		t.Fatalf("client assertion exp-iat = %v, want 300", delta)
	}
}

func TestNonceStore_Concurrent(t *testing.T) {
	ns := dpop_oauth2.NewNonceStore()
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ns.SetNonce(fmt.Sprintf("n-%d", i))
			_ = ns.GetNonce()
		}(i)
	}
	wg.Wait()
}

func TestTokenSource_Singleflight(t *testing.T) {
	key := generateRSAKey(t)
	h := &tokenHandler{}
	srv := httptest.NewServer(h)
	defer srv.Close()

	ts := newTestTokenSource(t, srv, key, time.Now)

	var wg sync.WaitGroup
	const N = 32
	tokens := make([]*accessToken, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tok, err := ts.Token(t.Context())
			if err != nil {
				t.Errorf("Token: %v", err)
				return
			}
			tokens[i] = tok
		}(i)
	}
	wg.Wait()
	if got := h.calls.Load(); got != 1 {
		t.Fatalf("expected 1 token call (singleflight), got %d", got)
	}
	for i := 1; i < N; i++ {
		if tokens[i] != tokens[0] {
			t.Fatalf("singleflight should hand the same token pointer to all callers; got differs at index %d", i)
		}
	}
}

func TestTokenSource_Singleflight_ErrorPropagation(t *testing.T) {
	key := generateRSAKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	ts := newTestTokenSource(t, srv, key, time.Now)

	var wg sync.WaitGroup
	const N = 16
	errs := make([]error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = ts.Token(t.Context())
		}(i)
	}
	wg.Wait()
	for i, e := range errs {
		if e == nil {
			t.Fatalf("caller %d expected error, got nil", i)
		}
	}
}

func TestTokenSource_LeaderCancelDoesNotPoisonWaiters(t *testing.T) {
	key := generateRSAKey(t)
	hit := make(chan struct{}, 1)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case hit <- struct{}{}:
		default:
		}
		<-release
		body, _ := json.Marshal(map[string]any{"access_token": "x", "token_type": "DPoP", "expires_in": 3600})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	ts := newTestTokenSource(t, srv, key, time.Now)

	leaderCtx, cancelLeader := context.WithCancel(t.Context())
	leaderDone := make(chan error, 1)
	go func() {
		_, err := ts.Token(leaderCtx)
		leaderDone <- err
	}()
	<-hit

	waiterDone := make(chan error, 1)
	go func() {
		_, err := ts.Token(t.Context())
		waiterDone <- err
	}()

	time.Sleep(20 * time.Millisecond)
	cancelLeader()

	select {
	case err := <-leaderDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("leader err = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("leader did not return")
	}

	close(release)

	select {
	case err := <-waiterDone:
		if err != nil {
			t.Fatalf("waiter should succeed despite leader cancel, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiter did not return")
	}
}

func TestRoundTripper_TokenSchemeChangesBetweenCalls(t *testing.T) {
	key := generateRSAKey(t)
	var captured []*http.Request
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		captured = append(captured, r.Clone(r.Context()))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	switching := &switchingTokenSource{toks: []*accessToken{dpopAccessToken("tok1"), bearerAccessToken("tok2")}}
	jwk := &jose.JSONWebKey{Key: key, KeyID: "kid-1", Algorithm: string(jose.RS256), Use: "sig"}
	p, err := dpop.NewProofer(jwk)
	if err != nil {
		t.Fatalf("proofer: %v", err)
	}
	rt := &dpopRoundTripper{
		inner:              http.DefaultTransport,
		proofer:            p,
		tokenSource:        switching,
		resourceNonceStore: dpop_oauth2.NewNonceStore(),
	}
	c := &http.Client{Transport: rt}
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/x", nil)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("Do[%d]: %v", i, err)
		}
		_ = resp.Body.Close()
	}
	mu.Lock()
	defer mu.Unlock()
	if got := captured[0].Header.Get("Authorization"); got != "DPoP tok1" {
		t.Fatalf("call 0 Authorization = %q, want DPoP tok1", got)
	}
	if got := captured[0].Header.Get("DPoP"); got == "" {
		t.Fatal("call 0 should have DPoP header")
	}
	if got := captured[1].Header.Get("Authorization"); got != "Bearer tok2" {
		t.Fatalf("call 1 Authorization = %q, want Bearer tok2", got)
	}
	if got := captured[1].Header.Get("DPoP"); got != "" {
		t.Fatalf("call 1 should not have DPoP header, got: %q", got)
	}
	if got := captured[1].Header.Get("x-okta-user-agent-extended"); got != "" {
		t.Fatalf("call 1 should not have telemetry header, got: %q", got)
	}
}

type switchingTokenSource struct {
	mu   sync.Mutex
	toks []*accessToken
	idx  int
}

func (s *switchingTokenSource) Token(context.Context) (*accessToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tok := s.toks[s.idx]
	if s.idx < len(s.toks)-1 {
		s.idx++
	}
	return tok, nil
}

func TestTokenSource_429MapsToUnavailable(t *testing.T) {
	key := generateRSAKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"too_many_requests","error_description":"rate limit exceeded"}`))
	}))
	defer srv.Close()

	ts := newTestTokenSource(t, srv, key, time.Now)
	_, err := ts.Token(t.Context())
	if err == nil {
		t.Fatal("expected error")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected status error, got: %v", err)
	}
	if st.Code() != codes.Unavailable {
		t.Fatalf("429 should map to Unavailable, got %v", st.Code())
	}
}

func TestTokenSource_InvalidDPoPProofIncludesProxyHint(t *testing.T) {
	key := generateRSAKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_dpop_proof","error_description":"The DPoP proof JWT header is missing"}`))
	}))
	defer srv.Close()

	ts := newTestTokenSource(t, srv, key, time.Now)
	_, err := ts.Token(t.Context())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "proxy") {
		t.Fatalf("error should hint at proxy, got: %v", err)
	}
}

func TestTokenSource_AcceptsStringExpiresIn(t *testing.T) {
	key := generateRSAKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"x","token_type":"DPoP","expires_in":"3600"}`))
	}))
	defer srv.Close()

	ts := newTestTokenSource(t, srv, key, time.Now)
	tok, err := ts.Token(t.Context())
	if err != nil {
		t.Fatalf("string expires_in should be accepted, got: %v", err)
	}
	if tok.expiry.IsZero() {
		t.Fatal("expiry should be set")
	}
}

func TestNewDPoPHTTPClient_RejectsEmptyScopes(t *testing.T) {
	_, err := NewDPoPHTTPClient(t.Context(), Config{
		Domain:        "example.okta.com",
		ClientID:      "c",
		PrivateKeyID:  "k",
		PrivateKeyPEM: pemPKCS1(t, generateRSAKey(t)),
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "Scopes") {
		t.Fatalf("expected error mentioning Scopes, got: %v", err)
	}
}

func TestTokenSource_InvalidClientIncludesKeyRotationHint(t *testing.T) {
	key := generateRSAKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"Client authentication failed"}`))
	}))
	defer srv.Close()

	ts := newTestTokenSource(t, srv, key, time.Now)
	_, err := ts.Token(t.Context())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "okta-client-id") || !strings.Contains(err.Error(), "PEM") {
		t.Fatalf("error should hint at client-id/PEM rotation, got: %v", err)
	}
}

func TestRoundTripper_ExactlyOneAuthAndDPoPHeader(t *testing.T) {
	key := generateRSAKey(t)
	var captured *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Clone(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rt := newRoundTripperForTest(t, key, dpopAccessToken("tok-X"), dpop_oauth2.NewNonceStore(), http.DefaultTransport)
	c := &http.Client{Transport: rt}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v1/users", nil)
	req.Header.Add("Authorization", "Bearer stale-1")
	req.Header.Add("Authorization", "Bearer stale-2")
	req.Header.Add("DPoP", "stale-proof-1")
	req.Header.Add("DPoP", "stale-proof-2")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()

	authVals := captured.Header.Values("Authorization")
	if len(authVals) != 1 {
		t.Fatalf("expected exactly one Authorization header, got %d: %v", len(authVals), authVals)
	}
	if authVals[0] != "DPoP tok-X" {
		t.Fatalf("Authorization = %q", authVals[0])
	}
	dpopVals := captured.Header.Values("DPoP")
	if len(dpopVals) != 1 {
		t.Fatalf("expected exactly one DPoP header, got %d: %v", len(dpopVals), dpopVals)
	}
	if strings.HasPrefix(dpopVals[0], "stale-proof") {
		t.Fatalf("DPoP header was not replaced: %q", dpopVals[0])
	}
}

func TestTokenSource_RejectsControlCharsInAccessToken(t *testing.T) {
	key := generateRSAKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"bad\ntoken","token_type":"DPoP","expires_in":3600}`))
	}))
	defer srv.Close()

	ts := newTestTokenSource(t, srv, key, time.Now)
	_, err := ts.Token(t.Context())
	if err == nil {
		t.Fatal("expected error for control-char in token")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Unauthenticated {
		t.Fatalf("expected codes.Unauthenticated, got: %v", err)
	}
}
