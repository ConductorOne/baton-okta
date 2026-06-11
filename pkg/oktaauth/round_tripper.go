package oktaauth

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/conductorone/dpop/integrations/dpop_oauth2"
	"github.com/conductorone/dpop/pkg/dpop"
)

type dpopRoundTripper struct {
	inner              http.RoundTripper
	proofer            *dpop.Proofer
	tokenSource        tokenGetter
	resourceNonceStore *dpop_oauth2.NonceStore
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

	if resp.StatusCode == http.StatusUnauthorized && isResourceNonceChallenge(resp) && isReplayable(req) {
		nonce := resp.Header.Get(dpopNonceHdr)
		if nonce != "" {
			rt.resourceNonceStore.SetNonce(nonce)
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			// Refresh: the original token may have expired mid-roundtrip; a stale ath would be rejected.
			freshTok, terr := rt.tokenSource.Token(req.Context())
			if terr != nil {
				return nil, fmt.Errorf("oktaauth: refresh token before nonce retry: %w", terr)
			}
			return rt.send(req, freshTok)
		}
	}

	return resp, nil
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

func isResourceNonceChallenge(resp *http.Response) bool {
	return strings.Contains(resp.Header.Get(wwwAuthenticateHdr), "use_dpop_nonce")
}

func isReplayable(req *http.Request) bool {
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodDelete:
		return true
	}
	return req.GetBody != nil
}
