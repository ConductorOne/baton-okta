package oktaauth

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"unicode/utf8"

	"github.com/conductorone/dpop/integrations/dpop_oauth2"
	"github.com/okta/okta-sdk-golang/v2/okta"
)

// Okta's resource server can deliver the DPoP nonce challenge as an HTTP 400
// rather than the 401 RoundTrip used to gate on. Unretried, the empty-body 400
// went straight to the caller and failed the sync.
func TestRoundTripper_ResourceNonceRetryOn400(t *testing.T) {
	key := generateRSAKey(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce", error_description="Authorization server requires nonce in DPoP proof"`)
			w.Header().Set("DPoP-Nonce", "res-nonce-400")
			w.WriteHeader(http.StatusBadRequest) // the whole bug: 400, not 401
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ns := dpop_oauth2.NewNonceStore()
	rt := newRoundTripperForTest(t, key, dpopAccessToken("tok"), ns, http.DefaultTransport)
	c := &http.Client{Transport: rt}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v1/groups/00g1/users", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if got := calls.Load(); got != 2 {
		t.Errorf("server calls = %d, want 2 (400 nonce challenge was not retried)", got)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("caller saw status %d, want 200 (the 400 challenge leaked to the caller)", resp.StatusCode)
	}
	// The nonce IS captured even on the unretried failure -- which is why the
	// very next call succeeds and failures look random and never repeat.
	if ns.GetNonce() != "res-nonce-400" {
		t.Errorf("nonce store = %q, want res-nonce-400", ns.GetNonce())
	}
}

// Guard for the fix: a plain 400 with no nonce challenge must never be retried.
func TestRoundTripper_NoRetryOnPlain400(t *testing.T) {
	key := generateRSAKey(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	rt := newRoundTripperForTest(t, key, dpopAccessToken("tok"), dpop_oauth2.NewNonceStore(), http.DefaultTransport)
	c := &http.Client{Transport: rt}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v1/groups", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()
	if got := calls.Load(); got != 1 {
		t.Errorf("server calls = %d, want 1", got)
	}
}

// The retry is now a bounded loop, not single-shot: Okta can rotate the nonce
// again on the retry, and a strictly sequential sync then failed anyway.
func TestRoundTripper_RetriesRepeatedNonceChallenges(t *testing.T) {
	key := generateRSAKey(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n := calls.Add(1); n < int32(maxDPoPRetrySends) {
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.Header().Set("DPoP-Nonce", "rotated")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rt := newRoundTripperForTest(t, key, dpopAccessToken("tok"), dpop_oauth2.NewNonceStore(), http.DefaultTransport)
	c := &http.Client{Transport: rt}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v1/groups", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if got, want := calls.Load(), int32(maxDPoPRetrySends); got != want {
		t.Errorf("server calls = %d, want %d", got, want)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("final status = %d, want 200", resp.StatusCode)
	}
}

// The loop must terminate: an endlessly challenging server gets exactly
// maxDPoPRetrySends attempts, then the response goes to the caller.
func TestRoundTripper_NonceRetryIsBounded(t *testing.T) {
	key := generateRSAKey(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
		w.Header().Set("DPoP-Nonce", "never-good-enough")
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	rt := newRoundTripperForTest(t, key, dpopAccessToken("tok"), dpop_oauth2.NewNonceStore(), http.DefaultTransport)
	c := &http.Client{Transport: rt}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v1/groups", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if got, want := calls.Load(), int32(maxDPoPRetrySends); got != want {
		t.Errorf("server calls = %d, want %d", got, want)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("final status = %d, want 400 handed back to the caller", resp.StatusCode)
	}
}

// A challenge with no DPoP-Nonce header has nothing to retry with; it must not
// spin, and it now logs rather than falling through silently.
func TestRoundTripper_NoRetryOn400ChallengeWithoutNonceHeader(t *testing.T) {
	key := generateRSAKey(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	rt := newRoundTripperForTest(t, key, dpopAccessToken("tok"), dpop_oauth2.NewNonceStore(), http.DefaultTransport)
	c := &http.Client{Transport: rt}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v1/groups", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()
	if got := calls.Load(); got != 1 {
		t.Errorf("server calls = %d, want 1", got)
	}
}

// Okta's own nonce challenge (observed at its token endpoint) sends no
// WWW-Authenticate at all and puts the code in a JSON body. Matching only the
// header would miss it entirely.
func TestRoundTripper_NonceChallengeInBodyWithoutHeader(t *testing.T) {
	key := generateRSAKey(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("DPoP-Nonce", "from-body-challenge")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"use_dpop_nonce","error_description":"Authorization server requires nonce in DPoP proof."}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rt := newRoundTripperForTest(t, key, dpopAccessToken("tok"), dpop_oauth2.NewNonceStore(), http.DefaultTransport)
	c := &http.Client{Transport: rt}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v1/groups", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if got := calls.Load(); got != 2 {
		t.Errorf("server calls = %d, want 2 (body-carried challenge was not retried)", got)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("final status = %d, want 200", resp.StatusCode)
	}
}

// Sniffing the body to look for a challenge must not consume it: a caller that
// declines to retry still has to read the full error payload.
func TestRoundTripper_ErrorBodySurvivesSniff(t *testing.T) {
	key := generateRSAKey(t)
	const payload = `{"errorCode":"E0000006","errorSummary":"You do not have permission to perform the requested action"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `DPoP error="invalid_dpop_proof"`)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	rt := newRoundTripperForTest(t, key, dpopAccessToken("tok"), dpop_oauth2.NewNonceStore(), http.DefaultTransport)
	c := &http.Client{Transport: rt}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v1/groups", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read restored body: %v", err)
	}
	if string(got) != payload {
		t.Errorf("body = %q, want %q", got, payload)
	}
}

// A body larger than the sniff limit must also come back whole.
func TestRoundTripper_LargeErrorBodySurvivesSniff(t *testing.T) {
	key := generateRSAKey(t)
	payload := `{"errorCode":"E0000006","pad":"` + strings.Repeat("x", errorBodySniffLimit*2) + `"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	rt := newRoundTripperForTest(t, key, dpopAccessToken("tok"), dpop_oauth2.NewNonceStore(), http.DefaultTransport)
	c := &http.Client{Transport: rt}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v1/groups", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read restored body: %v", err)
	}
	if len(got) != len(payload) {
		t.Errorf("body length = %d, want %d", len(got), len(payload))
	}
}

// A 200 must never be buffered -- only client errors are sniffed.
func TestRoundTripper_SuccessBodyNotBuffered(t *testing.T) {
	resp := &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}
	if got := sniffClientErrorBody(resp); got != nil {
		t.Errorf("sniffed a 200 body: %q", got)
	}
	if resp.Body != http.NoBody {
		t.Error("sniffClientErrorBody replaced the body of a success response")
	}
}

// The exact challenge Okta returns for a rejected proof, captured live.
const liveReplayChallenge = `DPoP algs="RS256 RS384 RS512 ES256 ES384 ES512", ` +
	`authorization_uri="http://tenant.okta.com/oauth2/v1/authorize", realm="http://tenant.okta.com", ` +
	`scope="okta.users.read.self", error="invalid_dpop_proof", ` +
	`error_description="The DPoP proof JWT has already been used.", resource="/api/v1/users"`

const liveSkewChallenge = `DPoP algs="RS256", error="invalid_dpop_proof", ` +
	`error_description="The DPoP proof JWT is issued more than five minutes in the past.", resource="/api/v1/users"`

// A replayed proof is resent once with a fresh proof: uhttp's transport retries
// with headers untouched, so the same jti can reach Okta twice.
func TestRoundTripper_RetriesProofReplay(t *testing.T) {
	key := generateRSAKey(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("WWW-Authenticate", liveReplayChallenge)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rt := newRoundTripperForTest(t, key, dpopAccessToken("tok"), dpop_oauth2.NewNonceStore(), http.DefaultTransport)
	c := &http.Client{Transport: rt}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v1/users", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if got := calls.Load(); got != 2 {
		t.Errorf("server calls = %d, want 2 (replayed proof was not resent)", got)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("final status = %d, want 200", resp.StatusCode)
	}
}

// A skewed clock is NOT resent -- retrying cannot fix it and would triple traffic.
func TestRoundTripper_DoesNotRetryClockSkewRejection(t *testing.T) {
	key := generateRSAKey(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("WWW-Authenticate", liveSkewChallenge)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	rt := newRoundTripperForTest(t, key, dpopAccessToken("tok"), dpop_oauth2.NewNonceStore(), http.DefaultTransport)
	c := &http.Client{Transport: rt}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v1/users", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if got := calls.Load(); got != 1 {
		t.Errorf("server calls = %d, want 1 (clock skew must not be retried)", got)
	}
}

// The empty-bodied rejection must come back with a body the Okta SDK can decode,
// so the reason reaches the caller instead of "the API returned an unknown error".
func TestRoundTripper_EmptyDPoPErrorGetsDecodableBody(t *testing.T) {
	key := generateRSAKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", liveSkewChallenge)
		w.WriteHeader(http.StatusBadRequest)
		// no body at all, exactly as Okta answers
	}))
	defer srv.Close()

	rt := newRoundTripperForTest(t, key, dpopAccessToken("tok"), dpop_oauth2.NewNonceStore(), http.DefaultTransport)
	c := &http.Client{Transport: rt}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v1/users", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read synthesized body: %v", err)
	}
	var payload struct {
		ErrorSummary string `json:"errorSummary"`
	}
	if err := json.Unmarshal(got, &payload); err != nil {
		t.Fatalf("synthesized body is not JSON (%q): %v", got, err)
	}
	if !strings.Contains(payload.ErrorSummary, "five minutes in the past") {
		t.Errorf("errorSummary = %q, want Okta's reason", payload.ErrorSummary)
	}
	if !strings.Contains(payload.ErrorSummary, "invalid_dpop_proof") {
		t.Errorf("errorSummary = %q, want the error code kept", payload.ErrorSummary)
	}
	if resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q", resp.Header.Get("Content-Type"))
	}
}

// A rejection that already has a body must be left exactly as it arrived.
func TestRoundTripper_NonEmptyBodyNotOverwritten(t *testing.T) {
	key := generateRSAKey(t)
	const original = `{"errorCode":"E0000006","errorSummary":"real okta error"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", liveSkewChallenge)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(original))
	}))
	defer srv.Close()

	rt := newRoundTripperForTest(t, key, dpopAccessToken("tok"), dpop_oauth2.NewNonceStore(), http.DefaultTransport)
	c := &http.Client{Transport: rt}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v1/users", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	got, _ := io.ReadAll(resp.Body)
	if string(got) != original {
		t.Errorf("body = %q, want it untouched (%q)", got, original)
	}
}

// End of the chain: feed the synthesized response to the real Okta SDK and check
// it now renders the reason Okta gave. The baseline assertion pins the bug -- the
// same response without a body yields the ticket's opaque message.
func TestAnnotateEmptyDPoPError_SDKRendersRealReason(t *testing.T) {
	header := http.Header{}
	header.Set(wwwAuthenticateHdr, liveReplayChallenge)

	baseline := okta.CheckResponseForError(&http.Response{
		StatusCode: http.StatusBadRequest,
		Status:     "400 Bad Request",
		Header:     header.Clone(),
		Body:       http.NoBody,
	})
	if baseline == nil || !strings.Contains(baseline.Error(), "the API returned an unknown error") {
		t.Fatalf("baseline should be the opaque SDK error, got %v", baseline)
	}

	resp := &http.Response{
		StatusCode: http.StatusBadRequest,
		Status:     "400 Bad Request",
		Header:     header.Clone(),
		Body:       http.NoBody,
	}
	annotateEmptyDPoPError(resp, nil)

	fixed := okta.CheckResponseForError(resp)
	if fixed == nil {
		t.Fatal("expected an error from the annotated response")
	}
	if strings.Contains(fixed.Error(), "unknown error") {
		t.Errorf("SDK still renders the opaque message: %q", fixed.Error())
	}
	if !strings.Contains(fixed.Error(), "already been used") {
		t.Errorf("SDK error = %q, want Okta's actual reason", fixed.Error())
	}
	t.Logf("before: %v", baseline)
	t.Logf("after:  %v", fixed)
}

// finish() runs for every response and body is only populated for client errors,
// so annotateEmptyDPoPError must range-check the status itself rather than trust
// an empty body argument -- otherwise a real body outside 4xx gets discarded.
func TestAnnotateEmptyDPoPError_OnlyTouchesClientErrors(t *testing.T) {
	for _, statusCode := range []int{http.StatusOK, http.StatusFound, http.StatusInternalServerError} {
		t.Run(http.StatusText(statusCode), func(t *testing.T) {
			const original = `{"real":"payload"}`
			header := http.Header{}
			header.Set(wwwAuthenticateHdr, liveReplayChallenge)
			resp := &http.Response{
				StatusCode: statusCode,
				Header:     header,
				Body:       io.NopCloser(strings.NewReader(original)),
			}
			// nil body, exactly as sniffClientErrorBody returns outside 4xx.
			annotateEmptyDPoPError(resp, nil)

			got, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			if string(got) != original {
				t.Errorf("body = %q, want it untouched (%q)", got, original)
			}
		})
	}
}

// The replay retry keys on two DPoP-specific markers, so a neighbouring Bearer
// challenge in the same header cannot trigger it.
func TestRoundTripper_BearerChallengeDoesNotTriggerProofRetry(t *testing.T) {
	key := generateRSAKey(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("WWW-Authenticate",
			`Bearer error="invalid_token", error_description="the token has already been used"`)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	rt := newRoundTripperForTest(t, key, dpopAccessToken("tok"), dpop_oauth2.NewNonceStore(), http.DefaultTransport)
	c := &http.Client{Transport: rt}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v1/users", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if got := calls.Load(); got != 1 {
		t.Errorf("server calls = %d, want 1 (a Bearer challenge must not be retried)", got)
	}
}

// The challenge is restated verbatim, so a multi-challenge header cannot have one
// scheme's error reported as the other's -- everything the server sent is kept.
func TestAnnotateEmptyDPoPError_KeepsWholeChallenge(t *testing.T) {
	const challenge = `DPoP algs="RS256", error="invalid_dpop_proof", ` +
		`error_description="The DPoP proof JWT has already been used.", ` +
		`Bearer error="invalid_token", error_description="unrelated"`
	header := http.Header{}
	header.Set(wwwAuthenticateHdr, challenge)
	resp := &http.Response{
		StatusCode: http.StatusBadRequest,
		Status:     "400 Bad Request",
		Header:     header,
		Body:       http.NoBody,
	}
	annotateEmptyDPoPError(resp, nil)

	rendered := okta.CheckResponseForError(resp)
	if rendered == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(rendered.Error(), "already been used") {
		t.Errorf("error = %q, want the DPoP reason present", rendered)
	}
	// Nothing is attributed, so the neighbouring challenge survives too rather
	// than being silently swapped in as the DPoP reason.
	if !strings.Contains(rendered.Error(), "invalid_token") {
		t.Errorf("error = %q, want the full challenge preserved", rendered)
	}
}

// nilBodyTransport mimics a RoundTripper that hands back a 4xx with no body.
// net/http never does, but io.Copy on a nil ReadCloser panics, so the drain path
// must not assume one.
type nilBodyTransport struct{ calls atomic.Int32 }

func (t *nilBodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.calls.Add(1)
	header := http.Header{}
	header.Set(wwwAuthenticateHdr, `DPoP error="use_dpop_nonce"`)
	header.Set(dpopNonceHdr, "fresh")
	return &http.Response{
		StatusCode: http.StatusBadRequest,
		Status:     "400 Bad Request",
		Header:     header,
		Body:       nil, // the whole point
		Request:    req,
	}, nil
}

func TestRoundTripper_NilResponseBodyDoesNotPanic(t *testing.T) {
	key := generateRSAKey(t)
	inner := &nilBodyTransport{}
	rt := newRoundTripperForTest(t, key, dpopAccessToken("tok"), dpop_oauth2.NewNonceStore(), inner)
	c := &http.Client{Transport: rt}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://tenant.okta.com/api/v1/users", nil)

	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	// The nonce challenge is retryable, so it drains and resends up to the bound.
	if got := inner.calls.Load(); got != int32(maxDPoPRetrySends) {
		t.Errorf("inner calls = %d, want %d", got, maxDPoPRetrySends)
	}
}

func TestTruncateAtRuneBoundary(t *testing.T) {
	// A three-byte rune so the limit does not divide evenly.
	s := strings.Repeat("€", 10) // 30 bytes
	for _, limit := range []int{29, 28, 27, 20, 1} {
		got := truncateAtRuneBoundary(s, limit)
		if !utf8.ValidString(got) {
			t.Errorf("limit %d: %q is not valid UTF-8", limit, got)
		}
		if len(got) > limit {
			t.Errorf("limit %d: got %d bytes", limit, len(got))
		}
	}
	if got := truncateAtRuneBoundary(s, 30); got != s {
		t.Errorf("exact-length input was truncated to %q", got)
	}
	if got := truncateAtRuneBoundary("abc", 10); got != "abc" {
		t.Errorf("short input = %q, want abc", got)
	}
}

// The replay marker has to be specific enough that a neighbouring challenge in the
// same header cannot trip it: "already been used" alone is plain English.
func TestRoundTripper_MixedChallengeDoesNotTriggerProofRetry(t *testing.T) {
	key := generateRSAKey(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		// DPoP rejects for clock skew; a Bearer challenge separately mentions reuse.
		w.Header().Set("WWW-Authenticate",
			`DPoP error="invalid_dpop_proof", error_description="The DPoP proof JWT is issued in the future.", `+
				`Bearer error="invalid_token", error_description="that token has already been used"`)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	rt := newRoundTripperForTest(t, key, dpopAccessToken("tok"), dpop_oauth2.NewNonceStore(), http.DefaultTransport)
	c := &http.Client{Transport: rt}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v1/users", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if got := calls.Load(); got != 1 {
		t.Errorf("server calls = %d, want 1 (clock skew must not be read as replay)", got)
	}
}

// truncatedBodyTransport returns a body that yields some bytes and then fails, the
// shape a connection dying mid-body produces.
type truncatedBodyTransport struct{ payload string }

func (t truncatedBodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	header := http.Header{}
	header.Set(wwwAuthenticateHdr, liveSkewChallenge)
	return &http.Response{
		StatusCode: http.StatusBadRequest,
		Status:     "400 Bad Request",
		Header:     header,
		Body:       io.NopCloser(iotest.TimeoutReader(strings.NewReader(t.payload))),
		Request:    req,
	}, nil
}

// A partial read must not be reported as an empty body: the bytes that arrived are
// restored onto resp.Body, and claiming empty would let the challenge restatement
// overwrite real content.
func TestRoundTripper_PartialBodyReadIsNotTreatedAsEmpty(t *testing.T) {
	key := generateRSAKey(t)
	const payload = `{"errorCode":"E0000006","errorSummary":"real content"}`
	rt := newRoundTripperForTest(t, key, dpopAccessToken("tok"), dpop_oauth2.NewNonceStore(),
		truncatedBodyTransport{payload: payload})
	c := &http.Client{Transport: rt}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://tenant.okta.com/api/v1/users", nil)

	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	got, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(got), "real content") {
		t.Errorf("body = %q, want the arrived bytes preserved rather than overwritten", got)
	}
}

// The token endpoint's error path excerpts an unparseable body the same way the
// resource path does, so it has to cut on a rune boundary too. Reached when the
// body carries no error/error_description for parseTokenError to pick up.
func TestFormatTokenError_ExcerptStaysValidUTF8(t *testing.T) {
	body := []byte(strings.Repeat("€", errorBodyExcerptLimit))
	err := formatTokenError(http.StatusBadGateway, "502 Bad Gateway", "", "", body)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !utf8.ValidString(err.Error()) {
		t.Errorf("error message is not valid UTF-8: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "502 Bad Gateway") {
		t.Errorf("error = %q, want the status named", err)
	}
	// No error code was supplied, so no hint is appended after the excerpt.
	if !strings.HasSuffix(err.Error(), "...") {
		t.Errorf("error = %q, want the excerpt marked as truncated", err)
	}
}
