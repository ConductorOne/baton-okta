package oktaauth

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/conductorone/dpop/integrations/dpop_oauth2"
	"github.com/conductorone/dpop/pkg/dpop"
	"golang.org/x/oauth2"
)

// dpopRoundTripper attaches a per-request DPoP proof, rewrites the Authorization
// header to the live access token, and retries once on a 401 use_dpop_nonce
// challenge for idempotent requests.
type dpopRoundTripper struct {
	inner        http.RoundTripper
	proofer      *dpop.Proofer
	tokenSource  oauth2.TokenSource
	resourceNonc *dpop_oauth2.NonceStore
}

func (rt *dpopRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	tok, err := rt.tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("oktaauth: get access token: %w", err)
	}

	resp, err := rt.send(req, tok)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized && isResourceNonceChallenge(resp) && isIdempotent(req) {
		nonce := resp.Header.Get(dpopNonceHdr)
		if nonce != "" {
			rt.resourceNonc.SetNonce(nonce)
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			return rt.send(req, tok)
		}
	}

	return resp, nil
}

func (rt *dpopRoundTripper) send(req *http.Request, tok *oauth2.Token) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, fmt.Errorf("oktaauth: rewind request body: %w", err)
		}
		cloned.Body = body
	}

	htu := canonicalHTU(req)
	proof, err := rt.proofer.CreateProof(req.Context(), req.Method, htu,
		dpop.WithAccessToken(tok.AccessToken),
		dpop.WithNonceFunc(rt.nonceFunc()),
	)
	if err != nil {
		return nil, fmt.Errorf("oktaauth: build dpop proof: %w", err)
	}

	cloned.Header.Set(authorizationHdr, tokenTypeDPoP+" "+tok.AccessToken)
	cloned.Header.Set(dpopHdr, proof)
	cloned.Header.Set(userAgentExtHdr, dpopTelemetryUA)

	resp, err := rt.inner.RoundTrip(cloned)
	if err != nil {
		return nil, err
	}
	if nonce := resp.Header.Get(dpopNonceHdr); nonce != "" {
		rt.resourceNonc.SetNonce(nonce)
	}
	return resp, nil
}

func (rt *dpopRoundTripper) nonceFunc() func() (string, error) {
	return func() (string, error) {
		return rt.resourceNonc.GetNonce(), nil
	}
}

// canonicalHTU: Okta rejects DPoP proofs whose htu claim contains a query string.
func canonicalHTU(req *http.Request) string {
	u := *req.URL
	u.RawQuery = ""
	u.Fragment = ""
	if u.Host == "" {
		u.Host = req.Host
	}
	if u.Scheme == "" {
		if req.TLS != nil {
			u.Scheme = "https"
		} else {
			u.Scheme = "http"
		}
	}
	return u.String()
}

func isResourceNonceChallenge(resp *http.Response) bool {
	wa := resp.Header.Get(wwwAuthenticateHr)
	return strings.Contains(wa, "use_dpop_nonce")
}

// isIdempotent gates the use_dpop_nonce retry: a streaming or non-rewindable
// POST/PATCH body cannot be replayed, and retrying would either send empty
// bytes or duplicate side effects. GET/HEAD/OPTIONS are always safe;
// everything else needs req.GetBody so we can rewind.
func isIdempotent(req *http.Request) bool {
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return req.GetBody != nil
}
