package oktaauth

import (
	"bytes"
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
	"golang.org/x/oauth2"
)

func generateRSAPEM(t *testing.T) (string, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	return string(pemBytes), key
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

// tokenHandler is a stub /oauth2/v1/token. On the first request it can be
// configured to return 400 use_dpop_nonce; on the second it returns a token.
type tokenHandler struct {
	t              *testing.T
	calls          int32
	requireNonceOn []int
	nonce          string
	tokenType      string
}

func (h *tokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	call := atomic.AddInt32(&h.calls, 1)
	for _, n := range h.requireNonceOn {
		if int(call) == n {
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

func newTestTokenSource(t *testing.T, server *httptest.Server, key *rsa.PrivateKey) *tokenSource {
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
		now:        time.Now,
	})
}

func TestTokenSource_NonceRetry(t *testing.T) {
	pemStr, key := generateRSAPEM(t)
	_ = pemStr

	type observed struct {
		proofNonce string
	}
	obs := make([]observed, 0, 2)
	var mu sync.Mutex

	mux := http.NewServeMux()
	h := &tokenHandler{t: t, requireNonceOn: []int{1}, nonce: "srv-nonce-1"}
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

	ts := newTestTokenSource(t, srv, key)
	tok, err := ts.Token()
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok.AccessToken == "" {
		t.Fatal("empty access token")
	}
	if got := atomic.LoadInt32(&h.calls); got != 2 {
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

func TestTokenSource_RejectsNonRSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen ecdsa: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	_, err = NewDPoPHTTPClient(context.Background(), Config{
		Domain:        "example.okta.com",
		ClientID:      "c",
		PrivateKeyID:  "k",
		PrivateKeyPEM: string(pemBytes),
	}, nil)
	if err == nil {
		t.Fatal("expected error for ECDSA key")
	}
	if !strings.Contains(err.Error(), "RSA") {
		t.Fatalf("error should mention RSA: %v", err)
	}
}

func TestTokenSource_RejectsNonDPoPTokenType(t *testing.T) {
	_, key := generateRSAPEM(t)

	mux := http.NewServeMux()
	h := &tokenHandler{t: t, tokenType: "Bearer"}
	mux.Handle("/oauth2/v1/token", h)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ts := newTestTokenSource(t, srv, key)
	_, err := ts.Token()
	if err == nil {
		t.Fatal("expected error for non-DPoP token_type")
	}
	if !strings.Contains(err.Error(), "DPoP token_type") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseRSAPrivateKey_PKCS8(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa gen: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("pkcs8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	got, err := parseRSAPrivateKey(string(pemBytes))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got == nil {
		t.Fatal("nil key returned")
	}
}

// fakeTokenSource hands out a fixed token without hitting any endpoint.
type fakeTokenSource struct{ tok *oauth2.Token }

func (f *fakeTokenSource) Token() (*oauth2.Token, error) { return f.tok, nil }

func newRoundTripperForTest(t *testing.T, key *rsa.PrivateKey, token string, ns *dpop_oauth2.NonceStore, inner http.RoundTripper) *dpopRoundTripper {
	t.Helper()
	jwk := &jose.JSONWebKey{Key: key, KeyID: "kid-1", Algorithm: string(jose.RS256), Use: "sig"}
	p, err := dpop.NewProofer(jwk)
	if err != nil {
		t.Fatalf("proofer: %v", err)
	}
	return &dpopRoundTripper{
		inner:        inner,
		proofer:      p,
		tokenSource:  &fakeTokenSource{tok: &oauth2.Token{AccessToken: token, TokenType: "DPoP", Expiry: time.Now().Add(time.Hour)}},
		resourceNonc: ns,
	}
}

func TestRoundTripper_AddsAuthAndProof(t *testing.T) {
	_, key := generateRSAPEM(t)

	var captured *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Clone(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rt := newRoundTripperForTest(t, key, "tok-A", dpop_oauth2.NewNonceStore(), http.DefaultTransport)
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

func TestRoundTripper_AthClaim(t *testing.T) {
	_, key := generateRSAPEM(t)
	token := "tok-B-with-some-bytes" //nolint:gosec // test fixture, not a real credential

	var proof string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proof = r.Header.Get("DPoP")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rt := newRoundTripperForTest(t, key, token, dpop_oauth2.NewNonceStore(), http.DefaultTransport)
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

func TestRoundTripper_HtuNoQuery(t *testing.T) {
	_, key := generateRSAPEM(t)

	var proof string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proof = r.Header.Get("DPoP")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rt := newRoundTripperForTest(t, key, "tok-C", dpop_oauth2.NewNonceStore(), http.DefaultTransport)
	c := &http.Client{Transport: rt}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v1/users?limit=200&filter=foo", nil)
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
	if !strings.HasSuffix(u.Path, "/api/v1/users") {
		t.Fatalf("htu path wrong: %q", htu)
	}
}

func TestRoundTripper_ResourceNonceRetry(t *testing.T) {
	_, key := generateRSAPEM(t)

	var (
		calls       int32
		secondProof string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
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
	rt := newRoundTripperForTest(t, key, "tok-D", ns, http.DefaultTransport)
	c := &http.Client{Transport: rt}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v1/groups", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()

	if got := atomic.LoadInt32(&calls); got != 2 {
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

func TestRoundTripper_NoRetryOnNonIdempotent(t *testing.T) {
	_, key := generateRSAPEM(t)

	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
		w.Header().Set("DPoP-Nonce", "n")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	rt := newRoundTripperForTest(t, key, "tok-E", dpop_oauth2.NewNonceStore(), http.DefaultTransport)
	c := &http.Client{Transport: rt}
	body := bytes.NewBufferString(`{"x":1}`)
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/api/v1/users", body)
	req.GetBody = nil
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected 1 call (no retry on non-rewindable POST), got %d", got)
	}
}

func TestRoundTripper_RetryOnRewindablePOST(t *testing.T) {
	_, key := generateRSAPEM(t)

	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"x":1}` {
			t.Errorf("body = %q on call %d", string(body), atomic.LoadInt32(&calls)+1)
		}
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.Header().Set("DPoP-Nonce", "n")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rt := newRoundTripperForTest(t, key, "tok-F", dpop_oauth2.NewNonceStore(), http.DefaultTransport)
	c := &http.Client{Transport: rt}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/api/v1/users", strings.NewReader(`{"x":1}`))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()

	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("expected 2 calls (POST with rewindable body), got %d", got)
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
