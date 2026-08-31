package oktaauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"unicode/utf8"

	"github.com/conductorone/dpop/integrations/dpop_oauth2"
	"github.com/conductorone/dpop/pkg/dpop"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

const (
	// maxDPoPRetrySends bounds how many times one logical request may be sent while
	// Okta keeps rejecting the DPoP layer: the initial send plus retries.
	maxDPoPRetrySends = 3
	// errorBodySniffLimit caps how much of a 4xx body is buffered while looking for
	// a challenge code. Okta's challenge payload is a few hundred bytes.
	errorBodySniffLimit = 4096
	// maxChallengeSummaryLen bounds the challenge text restated as the error body.
	// Okta's runs about 250 bytes.
	maxChallengeSummaryLen = 1024
	// proofReplayDesc is the distinctive part of the error_description Okta returns
	// when a proof's jti has been seen before ("The DPoP proof JWT has already been
	// used."). uhttp's transport retries a failed request with its headers
	// untouched, so a stale-connection retry resends the same proof; minting a
	// fresh one and retrying once clears it. Matched in full rather than on "already
	// been used" alone, which is plain English another scheme's challenge could
	// carry.
	proofReplayDesc = "DPoP proof JWT has already been used"
)

// dpopRetryReason names the DPoP-layer rejections worth resending.
type dpopRetryReason int

const (
	dpopRetryNone dpopRetryReason = iota
	dpopRetryNonce
	dpopRetryProofReplay
)

type dpopRoundTripper struct {
	inner              http.RoundTripper
	proofer            *dpop.Proofer
	tokenSource        tokenGetter
	resourceNonceStore *dpop_oauth2.NonceStore
	// dpopFailureCount drives logarithmic sampling of the DPoP failure log: a
	// skewed clock rejects every request in a sync, so an unsampled line per
	// request would flood the log.
	dpopFailureCount atomic.Int64
}

func (rt *dpopRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	tok, err := rt.tokenSource.Token(req.Context())
	if err != nil {
		return nil, fmt.Errorf("oktaauth: get access token: %w", err)
	}

	resp, err := rt.send(req, tok)
	if err != nil {
		return nil, err
	}

	// Okta rejects the DPoP layer in two resendable ways: a stale nonce, and a
	// replayed proof jti. Both clear on a fresh proof, and either can recur on the
	// retry, so loop -- mirroring the token endpoint's bounded retry in exchange().
	for send := 1; ; send++ {
		body := sniffClientErrorBody(resp)
		reason := retryableDPoPFailure(resp, body)
		if reason == dpopRetryNone || !isReplayable(req) {
			return rt.finish(req, resp, body), nil
		}
		if send >= maxDPoPRetrySends {
			ctxzap.Extract(req.Context()).Warn(
				"oktaauth: dpop rejection persisted across retries"+proxyStripHintResponse,
				zap.Int("status_code", resp.StatusCode),
				zap.String("path", req.URL.Path),
				zap.Int("sends", send),
			)
			return rt.finish(req, resp, body), nil
		}
		if reason == dpopRetryNonce {
			nonce := resp.Header.Get(dpopNonceHdr)
			if nonce == "" {
				ctxzap.Extract(req.Context()).Warn(
					"oktaauth: dpop nonce challenge carried no DPoP-Nonce header; not retrying"+proxyStripHintResponse,
					zap.Int("status_code", resp.StatusCode),
					zap.String("path", req.URL.Path),
				)
				return rt.finish(req, resp, body), nil
			}
			rt.resourceNonceStore.SetNonce(nonce)
		}
		ctxzap.Extract(req.Context()).Debug("oktaauth: retrying after dpop rejection",
			zap.Int("status_code", resp.StatusCode),
			zap.String("path", req.URL.Path),
			zap.Int("send", send),
			zap.Bool("proof_replay", reason == dpopRetryProofReplay),
		)
		// net/http always sets a body, but sniffClientErrorBody and
		// annotateEmptyDPoPError both guard it, and io.Copy on a nil ReadCloser
		// panics -- so guard here too rather than trust the transport.
		if resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		// Refresh: the original token may have expired mid-roundtrip; a stale ath would be rejected.
		freshTok, terr := rt.tokenSource.Token(req.Context())
		if terr != nil {
			return nil, fmt.Errorf("oktaauth: refresh token before dpop retry: %w", terr)
		}
		resp, err = rt.send(req, freshTok)
		if err != nil {
			return nil, err
		}
	}
}

// Concurrent requests can fail with a 401. The retry handles it. Don't add a lock.
func (rt *dpopRoundTripper) send(req *http.Request, tok *accessToken) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, fmt.Errorf("oktaauth: rewind request body: %w", err)
		}
		cloned.Body = body
	}

	cloned.Header.Set(authorizationHdr, tok.scheme+" "+tok.value)

	if tok.bindsDPoP() {
		htu, herr := htuForProof(req)
		if herr != nil {
			return nil, fmt.Errorf("oktaauth: build htu: %w", herr)
		}
		proof, err := rt.proofer.CreateProof(req.Context(), req.Method, htu,
			dpop.WithAccessToken(tok.value),
			dpop.WithNonceFunc(rt.nonceFunc()),
		)
		if err != nil {
			return nil, fmt.Errorf("oktaauth: build dpop proof: %w", err)
		}
		cloned.Header.Set(dpopHdr, proof)
		cloned.Header.Set(userAgentExtHdr, dpopTelemetryUA)
	} else {
		cloned.Header.Del(dpopHdr)
		cloned.Header.Del(userAgentExtHdr)
	}

	resp, err := rt.inner.RoundTrip(cloned)
	if err != nil {
		return nil, err
	}
	if nonce := resp.Header.Get(dpopNonceHdr); nonce != "" {
		rt.resourceNonceStore.SetNonce(nonce)
	}
	return resp, nil
}

func (rt *dpopRoundTripper) nonceFunc() func() (string, error) {
	return func() (string, error) {
		return rt.resourceNonceStore.GetNonce(), nil
	}
}

// htuForProof: Okta rejects DPoP proofs whose htu claim contains query/fragment.
func htuForProof(req *http.Request) (string, error) {
	u := *req.URL
	u.RawQuery = ""
	u.Fragment = ""
	if u.Host == "" {
		u.Host = req.Host
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	if u.Host == "" {
		return "", errors.New("request URL has no host")
	}
	return u.String(), nil
}

// finish is the single exit for a response the DPoP layer will not resend: it
// gives an empty-bodied rejection a decodable body and reports what it saw.
func (rt *dpopRoundTripper) finish(req *http.Request, resp *http.Response, body []byte) *http.Response {
	rt.logDPoPFailure(req.Context(), req, resp, body)
	annotateEmptyDPoPError(resp, body)
	return resp
}

// retryableDPoPFailure classifies a response as a DPoP rejection worth resending
// with a fresh proof, or not worth resending at all. Deliberately narrow: a
// generic invalid_dpop_proof (a skewed clock, say) is not resent, since retrying
// would only triple the requests without changing the outcome.
func retryableDPoPFailure(resp *http.Response, body []byte) dpopRetryReason {
	switch resp.StatusCode {
	case http.StatusBadRequest, http.StatusUnauthorized:
	default:
		return dpopRetryNone
	}
	challenge := resp.Header.Get(wwwAuthenticateHdr)
	if isResourceNonceChallenge(resp, body) {
		return dpopRetryNonce
	}
	// Both markers are DPoP-specific, so finding them anywhere in the header is
	// unambiguous; no need to work out which challenge they belong to.
	if strings.Contains(challenge, invalidDPoPProofErrorCode) && strings.Contains(challenge, proofReplayDesc) {
		return dpopRetryProofReplay
	}
	return dpopRetryNone
}

// isResourceNonceChallenge reports whether resp is Okta demanding a fresh DPoP
// nonce, in either shape RFC 9449 allows: a resource server answers 401 with the
// code in WWW-Authenticate, an authorization server answers 400 with the code in
// a JSON body. Okta's token endpoint was observed using the latter and sending no
// WWW-Authenticate at all, so matching only the header would miss it. body may be
// nil when the response was not a client error.
func isResourceNonceChallenge(resp *http.Response, body []byte) bool {
	switch resp.StatusCode {
	case http.StatusBadRequest, http.StatusUnauthorized:
	default:
		return false
	}
	if strings.Contains(resp.Header.Get(wwwAuthenticateHdr), useDPoPNonceErrorCode) {
		return true
	}
	return jsonErrorCode(body) == useDPoPNonceErrorCode
}

// annotateEmptyDPoPError gives an empty-bodied DPoP rejection a body the Okta SDK
// can decode. Okta answers a bad proof with a 400, an empty body, and the reason
// in a DPoP-scheme WWW-Authenticate; the SDK's CheckResponseForError reads that
// header only for 401/403 responses whose scheme is Bearer, then discards the
// decode failure on the empty body and yields a zero-valued error rendering as
// "the API returned an unknown error". Restating the header as the JSON the SDK
// expects turns that back into the reason Okta actually gave.
func annotateEmptyDPoPError(resp *http.Response, body []byte) {
	// Guard the status range here rather than relying on the caller: body is only
	// populated for client errors, so outside that range an empty body argument
	// says nothing about the real body and rewriting it would discard content.
	if resp.StatusCode < 400 || resp.StatusCode >= 500 {
		return
	}
	if len(bytes.TrimSpace(body)) > 0 {
		return
	}
	challenge := resp.Header.Get(wwwAuthenticateHdr)
	if challenge == "" {
		return
	}
	if len(challenge) > maxChallengeSummaryLen {
		challenge = truncateAtRuneBoundary(challenge, maxChallengeSummaryLen) + "..."
	}
	// Passed through whole rather than parsed into auth-params: RFC 9110 allows
	// several challenges in one header, and attributing a param to the right scheme
	// needs a real parser. Quoting the header drops nothing and cannot misattribute
	// one scheme's error to another.
	payload, err := json.Marshal(struct {
		ErrorSummary string `json:"errorSummary"`
	}{ErrorSummary: challenge})
	if err != nil {
		return
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	resp.Body = io.NopCloser(bytes.NewReader(payload))
	resp.ContentLength = int64(len(payload))
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set("Content-Length", strconv.Itoa(len(payload)))
}

// logDPoPFailure reports a DPoP-related client error while the detail is still
// visible, since the SDK is about to discard the WWW-Authenticate header. Warn per
// the upstream-4xx convention, but logarithmically sampled: a generic
// invalid_dpop_proof is deliberately not retried, so a skewed clock would
// otherwise emit one line per request for a whole sync.
func (rt *dpopRoundTripper) logDPoPFailure(ctx context.Context, req *http.Request, resp *http.Response, body []byte) {
	if resp.StatusCode < 400 || resp.StatusCode >= 500 {
		return
	}
	challenge := resp.Header.Get(wwwAuthenticateHdr)
	errCode := jsonErrorCode(body)
	if !strings.Contains(strings.ToLower(challenge), "dpop") && !strings.Contains(errCode, "dpop") {
		return
	}
	count := rt.dpopFailureCount.Add(1)
	if count != 1 && count != 10 && count != 100 && count%1000 != 0 {
		return
	}
	ctxzap.Extract(ctx).Warn("oktaauth: dpop failure on resource request",
		zap.Int64("total_occurrences", count),
		zap.Int("status_code", resp.StatusCode),
		zap.String("method", req.Method),
		zap.String("path", req.URL.Path),
		zap.String("www_authenticate", challenge),
		zap.String("body_error", errCode),
		zap.Bool("nonce_offered", resp.Header.Get(dpopNonceHdr) != ""),
	)
}

// jsonErrorCode pulls the OAuth-style "error" field out of an error body.
func jsonErrorCode(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var payload struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &payload) != nil {
		return ""
	}
	return payload.Error
}

// truncateAtRuneBoundary cuts s to at most maxBytes without splitting a rune, so
// the result stays valid UTF-8. A raw byte slice can leave a partial rune behind.
func truncateAtRuneBoundary(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// restoredBody re-attaches a peeked prefix ahead of the unread remainder, so a
// body can be inspected and still handed to the caller intact.
type restoredBody struct {
	io.Reader
	io.Closer
}

// sniffClientErrorBody buffers the start of a 4xx body and puts it back. Only
// client errors are buffered, so success responses stream through untouched.
func sniffClientErrorBody(resp *http.Response) []byte {
	if resp.StatusCode < 400 || resp.StatusCode >= 500 || resp.Body == nil {
		return nil
	}
	// The read error is dropped deliberately: whatever arrived is restored onto the
	// body, so the caller will meet the error again when it reads. Reporting nil
	// here would instead claim an empty body, and annotateEmptyDPoPError would
	// overwrite the partial payload that did arrive.
	prefix, _ := io.ReadAll(io.LimitReader(resp.Body, errorBodySniffLimit))
	resp.Body = restoredBody{
		Reader: io.MultiReader(bytes.NewReader(prefix), resp.Body),
		Closer: resp.Body,
	}
	return prefix
}

func isReplayable(req *http.Request) bool {
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodDelete:
		return true
	}
	return req.GetBody != nil
}
