package connector

import (
	"errors"
	"net/http"
	"testing"

	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"github.com/stretchr/testify/require"
)

func TestWrapListEventsError_FullContext(t *testing.T) {
	// On an Okta SDK error with a non-nil response, the wrapper must surface HTTP status,
	// X-Okta-Request-Id, and the query window — otherwise the inner error reduces to the
	// useless "the API returned an unknown error" sentinel from okta-sdk-golang.
	header := http.Header{}
	header.Set("X-Okta-Request-Id", "req-abc123")
	resp := &okta.Response{Response: &http.Response{StatusCode: 502, Header: header}}
	qp := &query.Params{Since: "2026-05-13T00:00:00Z", After: "0oa1cursor"}
	inner := errors.New("the API returned an unknown error")

	wrapped := wrapListEventsError(qp, resp, inner)
	require.Error(t, wrapped)
	msg := wrapped.Error()
	require.Contains(t, msg, "okta-connectorv2: ListEvents failed")
	require.Contains(t, msg, "status=502")
	require.Contains(t, msg, "request_id=req-abc123")
	require.Contains(t, msg, "since=2026-05-13T00:00:00Z")
	require.Contains(t, msg, "after=0oa1cursor")
	require.ErrorIs(t, wrapped, inner, "wrapper must preserve errors.Is on the inner error")
}

func TestWrapListEventsError_NilResponse(t *testing.T) {
	// On a network failure before any HTTP response is built, the SDK returns nil resp;
	// the wrapper must still produce a usable message anchored to the query window.
	qp := &query.Params{Since: "2026-05-13T00:00:00Z"}
	inner := errors.New("dial tcp: connection refused")

	wrapped := wrapListEventsError(qp, nil, inner)
	msg := wrapped.Error()
	require.Contains(t, msg, "okta-connectorv2: ListEvents failed")
	require.NotContains(t, msg, "status=")
	require.NotContains(t, msg, "request_id=")
	require.Contains(t, msg, "since=2026-05-13T00:00:00Z")
	require.NotContains(t, msg, "after=", "after= must be omitted when not set")
	require.ErrorIs(t, wrapped, inner)
}

func TestWrapListEventsError_MissingRequestIdAndCursor(t *testing.T) {
	// Older Okta deployments or gateway-injected error responses sometimes omit the
	// request-id header; first-page requests have no cursor. Optional fields must be
	// elided cleanly (no empty key=value pairs).
	resp := &okta.Response{Response: &http.Response{StatusCode: 500, Header: http.Header{}}}
	qp := &query.Params{Since: "2026-05-13T00:00:00Z"}
	inner := errors.New("the API returned an unknown error")

	wrapped := wrapListEventsError(qp, resp, inner)
	msg := wrapped.Error()
	require.Contains(t, msg, "status=500")
	require.NotContains(t, msg, "request_id=")
	require.NotContains(t, msg, "after=")
}
