package connector

import (
	"fmt"
	"net/http"
	"os"
	"sync"
)

// requestLogEnvVar names a file to append one "METHOD URL" line per Okta
// API request. Demo instrumentation for the source-cache measurement
// harness (warm-vs-cold request counting); unset (the normal case) means
// no wrapping at all.
const requestLogEnvVar = "BATON_OKTA_REQUEST_LOG"

type countingTransport struct {
	base  http.RoundTripper
	logMu sync.Mutex
	logF  *os.File
}

func (t *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.logMu.Lock()
	_, _ = fmt.Fprintf(t.logF, "%s %s\n", req.Method, req.URL.String())
	t.logMu.Unlock()

	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

// wrapRequestCounting installs the counting transport when
// BATON_OKTA_REQUEST_LOG is set. Returns the client unchanged otherwise.
func wrapRequestCounting(httpClient *http.Client) (*http.Client, error) {
	logPath := os.Getenv(requestLogEnvVar)
	if logPath == "" {
		return httpClient, nil
	}
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644) //nolint:gosec // path comes from the operator's own env var, not untrusted input
	if err != nil {
		return nil, fmt.Errorf("okta-connectorv2: failed to open request log %s: %w", logPath, err)
	}
	wrapped := *httpClient
	wrapped.Transport = &countingTransport{base: httpClient.Transport, logF: f}
	return &wrapped, nil
}
