package connector

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/okta/okta-sdk-golang/v2/okta"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// getError's five call sites all return its error verbatim, so it has to carry
// the status and the connector prefix itself. An empty body used to surface as a
// bare "unexpected end of JSON input".
func TestGetError(t *testing.T) {
	t.Parallel()

	oktaResp := func(statusCode int, body string) *okta.Response {
		return &okta.Response{Response: &http.Response{
			StatusCode: statusCode,
			Status:     http.StatusText(statusCode),
			Body:       io.NopCloser(strings.NewReader(body)),
		}}
	}

	t.Run("empty body reports the status", func(t *testing.T) {
		t.Parallel()
		_, err := getError(oktaResp(http.StatusBadRequest, ""))
		if err == nil {
			t.Fatal("expected an error")
		}
		for _, want := range []string{"okta-connectorv2:", http.StatusText(http.StatusBadRequest)} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error = %q, want it to contain %q", err, want)
			}
		}
	})

	t.Run("non-JSON body is excerpted, not dropped", func(t *testing.T) {
		t.Parallel()
		_, err := getError(oktaResp(http.StatusBadGateway, "<html>gateway</html>"))
		if err == nil {
			t.Fatal("expected an error")
		}
		if !strings.Contains(err.Error(), "gateway") {
			t.Errorf("error = %q, want the body excerpt included", err)
		}
	})

	t.Run("decodable body still parses", func(t *testing.T) {
		t.Parallel()
		got, err := getError(oktaResp(http.StatusForbidden, `{"errorCode":"E0000006","errorSummary":"denied"}`))
		if err != nil {
			t.Fatalf("getError: %v", err)
		}
		if got.ErrorCode != AccessDeniedErrorCode {
			t.Errorf("ErrorCode = %q, want %q", got.ErrorCode, AccessDeniedErrorCode)
		}
	})
}

// A fixed byte offset can split a multi-byte rune; the excerpt lands in an error
// message and in log fields, so it has to stay valid UTF-8.
func TestBodyExcerpt_TruncatesOnRuneBoundary(t *testing.T) {
	t.Parallel()

	// A three-byte rune so the byte limit does not divide evenly and the cut lands
	// mid-rune. Two-byte runes would tile it exactly and prove nothing.
	body := strings.Repeat("€", errorBodyExcerptLimit)
	got := bodyExcerpt([]byte(body))

	if !utf8.ValidString(got) {
		t.Errorf("excerpt is not valid UTF-8: %q", got)
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("excerpt = %q, want it marked as truncated", got)
	}
	if short := bodyExcerpt([]byte("€")); short != "€" {
		t.Errorf("short body = %q, want it returned whole", short)
	}
}

// Both getError paths must classify by HTTP status, so the same upstream failure
// gets the same gRPC code whether or not Okta sent a parseable body. The five call
// sites return this error verbatim, so an unparseable body used to reach the sync
// as codes.Unknown while a parseable one became PermissionDenied.
func TestGetError_ClassifiesByHTTPStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
		want       codes.Code
	}{
		{name: "forbidden", statusCode: http.StatusForbidden, want: codes.PermissionDenied},
		{name: "rate limited", statusCode: http.StatusTooManyRequests, want: codes.Unavailable},
		{name: "not found", statusCode: http.StatusNotFound, want: codes.NotFound},
		{name: "bad request", statusCode: http.StatusBadRequest, want: codes.InvalidArgument},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resp := &okta.Response{Response: &http.Response{
				StatusCode: tc.statusCode,
				Status:     http.StatusText(tc.statusCode),
				Body:       io.NopCloser(strings.NewReader("<html>not json</html>")),
			}}
			_, err := getError(resp)
			if status.Code(err) != tc.want {
				t.Errorf("code = %s, want %s (error: %v)", status.Code(err), tc.want, err)
			}
			// The message still has to carry the prefix and status for the logs.
			for _, sub := range []string{"okta-connectorv2:", http.StatusText(tc.statusCode)} {
				if !strings.Contains(err.Error(), sub) {
					t.Errorf("error = %q, want it to contain %q", err, sub)
				}
			}
		})
	}
}
