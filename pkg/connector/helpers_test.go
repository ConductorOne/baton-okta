package connector

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/okta/okta-sdk-golang/v2/okta"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestHandleOktaResponseError(t *testing.T) {
	t.Parallel()

	oktaResp := func(statusCode int) *okta.Response {
		return &okta.Response{
			Response: &http.Response{
				StatusCode: statusCode,
				Status:     http.StatusText(statusCode),
				Header:     make(http.Header),
			},
		}
	}

	tests := []struct {
		name     string
		resp     *okta.Response
		err      error
		wantCode codes.Code
		wantNil  bool
	}{
		{
			name:    "nil error returns nil",
			wantNil: true,
		},
		{
			name:     "E0000006 maps to PermissionDenied",
			err:      &okta.Error{ErrorCode: "E0000006", ErrorSummary: "You do not have permission"},
			wantCode: codes.PermissionDenied,
		},
		{
			name:     "E0000007 maps to NotFound",
			err:      &okta.Error{ErrorCode: "E0000007", ErrorSummary: "Not found: Resource not found"},
			wantCode: codes.NotFound,
		},
		{
			name:     "E0000008 maps to NotFound",
			err:      &okta.Error{ErrorCode: "E0000008", ErrorSummary: "Resource not found"},
			wantCode: codes.NotFound,
		},
		{
			name:     "E0000011 maps to Unauthenticated",
			err:      &okta.Error{ErrorCode: "E0000011", ErrorSummary: "Invalid token provided"},
			wantCode: codes.Unauthenticated,
		},
		{
			name:     "mapped okta code preferred over http status",
			resp:     oktaResp(http.StatusInternalServerError),
			err:      &okta.Error{ErrorCode: "E0000007", ErrorSummary: "Not found"},
			wantCode: codes.NotFound,
		},
		{
			name:     "unmapped okta error falls back to http status",
			resp:     oktaResp(http.StatusForbidden),
			err:      &okta.Error{ErrorCode: "E0000001", ErrorSummary: "Api validation failed"},
			wantCode: codes.PermissionDenied,
		},
		{
			name:     "plain error falls back to http 404",
			resp:     oktaResp(http.StatusNotFound),
			err:      errors.New("request failed"),
			wantCode: codes.NotFound,
		},
		{
			name:     "plain error falls back to http 429",
			resp:     oktaResp(http.StatusTooManyRequests),
			err:      errors.New("rate limited"),
			wantCode: codes.Unavailable,
		},
		{
			name:     "plain error falls back to http 503",
			resp:     oktaResp(http.StatusServiceUnavailable),
			err:      errors.New("unavailable"),
			wantCode: codes.Unavailable,
		},
		{
			name:     "context deadline exceeded",
			err:      context.DeadlineExceeded,
			wantCode: codes.DeadlineExceeded,
		},
		{
			name: "url timeout",
			err: &url.Error{
				Op:  "Get",
				URL: "https://example.okta.com/api/v1/users",
				Err: timeoutErr{},
			},
			wantCode: codes.DeadlineExceeded,
		},
		{
			name:     "unmapped okta error without response is unchanged",
			err:      &okta.Error{ErrorCode: "E0000001", ErrorSummary: "Api validation failed"},
			wantCode: codes.Unknown,
		},
		{
			name:     "plain error without response is unchanged",
			err:      errors.New("something went wrong"),
			wantCode: codes.Unknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := handleOktaResponseError(tt.resp, tt.err)
			if tt.wantNil {
				if got != nil {
					t.Fatalf("handleOktaResponseError() = %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("handleOktaResponseError() = nil, want error")
			}

			if gotCode := status.Code(got); gotCode != tt.wantCode {
				t.Fatalf("status.Code() = %v, want %v (error: %v)", gotCode, tt.wantCode, got)
			}

			var oktaErr *okta.Error
			if errors.As(tt.err, &oktaErr) {
				if _, mapped := oktaErrToGRPCError[oktaErr.ErrorCode]; mapped {
					var gotOktaErr *okta.Error
					if !errors.As(got, &gotOktaErr) {
						t.Fatalf("mapped error should preserve original okta error, got: %v", got)
					}
				}
			}
		})
	}
}
