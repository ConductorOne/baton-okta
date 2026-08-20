package connector

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	testGroupID = "00g1abc2def3GHI4jk5"
	testAppID   = "0oa1abc2def3GHI4jk5"
)

// rateLimitedStep builds a 429 response with the headers the v2 SDK's own retry
// logic requires (Get429BackoffTime); missing/invalid ones make it fail with a
// header-parse error instead of reproducing the "too many requests" sentinel.
func rateLimitedStep(method, path string) oktaRequestStep {
	now := time.Now().UTC()
	return oktaRequestStep{
		method:     method,
		path:       path,
		statusCode: http.StatusTooManyRequests,
		headers: map[string]string{
			"Date":                   now.Format(http.TimeFormat),
			"X-Rate-Limit-Limit":     "20",
			"X-Rate-Limit-Remaining": "0",
			"X-Rate-Limit-Reset":     strconv.FormatInt(now.Add(2*time.Second).Unix(), 10),
		},
		body: `{"errorCode":"E0000047","errorSummary":"API call exceeded rate limit"}`,
	}
}

// testUserPrincipal is the user principal shared by group-membership and app-access tests.
func testUserPrincipal() *v2.Resource {
	return &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeUser.Id, Resource: testOktaUserID}}
}

func groupMembershipEntitlement() *v2.Entitlement {
	return &v2.Entitlement{Resource: &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeGroup.Id, Resource: testGroupID}}}
}

func appGroupPrincipal() *v2.Resource {
	return &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeGroup.Id, Resource: testGroupID}}
}

func appAccessEntitlement() *v2.Entitlement {
	return &v2.Entitlement{Resource: &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeApp.Id, Resource: testAppID}}}
}

func oktaAppUserAssignedResponse() string {
	return `{"id":"` + testOktaUserID + `","status":"ACTIVE","scope":"USER","lastUpdated":"2024-01-01T00:00:00.000Z"}`
}

func oktaAppGroupAssignmentResponse() string {
	return `{"id":"` + testGroupID + `","lastUpdated":"2024-01-01T00:00:00.000Z"}`
}

func newTestAppBuilder(client *okta.Client) *appResourceType {
	return appBuilder("", "", false, nil, client)
}

// TestRateLimitClassification proves the wiring end to end: a 429 exhausting the
// v2 SDK's own retries reaches the connector as codes.Unavailable, not codes.Unknown.
func TestRateLimitClassification(t *testing.T) {
	t.Run("group grant", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			rateLimitedStep(http.MethodPut, "/api/v1/groups/"+testGroupID+"/users/"+testOktaUserID),
		)

		_, err := groupBuilder(&Okta{client: client}).Grant(t.Context(), testUserPrincipal(), groupMembershipEntitlement())
		if status.Code(err) != codes.Unavailable {
			t.Fatalf("Grant() status = %s, want %s (error: %v)", status.Code(err), codes.Unavailable, err)
		}
	})

	t.Run("group revoke", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			rateLimitedStep(http.MethodDelete, "/api/v1/groups/"+testGroupID+"/users/"+testOktaUserID),
		)
		grant := &v2.Grant{Principal: testUserPrincipal(), Entitlement: groupMembershipEntitlement()}

		_, err := groupBuilder(&Okta{client: client}).Revoke(t.Context(), grant)
		if status.Code(err) != codes.Unavailable {
			t.Fatalf("Revoke() status = %s, want %s (error: %v)", status.Code(err), codes.Unavailable, err)
		}
	})

	t.Run("app grant", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			rateLimitedStep(http.MethodGet, "/api/v1/apps/"+testAppID+"/users/"+testOktaUserID),
		)

		_, err := newTestAppBuilder(client).Grant(t.Context(), testUserPrincipal(), appAccessEntitlement())
		if status.Code(err) != codes.Unavailable {
			t.Fatalf("Grant() status = %s, want %s (error: %v)", status.Code(err), codes.Unavailable, err)
		}
	})
}

func TestRevokeIdempotency(t *testing.T) {
	t.Run("app revoke: missing user is already revoked", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/apps/" + testAppID + "/users/" + testOktaUserID, statusCode: http.StatusNotFound, body: oktaNotFoundResponse()},
		)
		grant := &v2.Grant{Principal: testUserPrincipal(), Entitlement: appAccessEntitlement()}

		annos, err := newTestAppBuilder(client).Revoke(t.Context(), grant)
		if err != nil {
			t.Fatalf("Revoke() error: %v", err)
		}
		if !annos.Contains(&v2.GrantAlreadyRevoked{}) {
			t.Fatalf("Revoke() annotations = %v, want GrantAlreadyRevoked", annos)
		}
	})

	t.Run("app revoke: missing group is already revoked", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/apps/" + testAppID + "/groups/" + testGroupID, statusCode: http.StatusNotFound, body: oktaNotFoundResponse()},
		)
		grant := &v2.Grant{Principal: appGroupPrincipal(), Entitlement: appAccessEntitlement()}

		annos, err := newTestAppBuilder(client).Revoke(t.Context(), grant)
		if err != nil {
			t.Fatalf("Revoke() error: %v", err)
		}
		if !annos.Contains(&v2.GrantAlreadyRevoked{}) {
			t.Fatalf("Revoke() annotations = %v, want GrantAlreadyRevoked", annos)
		}
	})

	t.Run("group revoke: missing membership is already revoked", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{method: http.MethodDelete, path: "/api/v1/groups/" + testGroupID + "/users/" + testOktaUserID, statusCode: http.StatusNotFound, body: oktaNotFoundResponse()},
		)
		grant := &v2.Grant{Principal: testUserPrincipal(), Entitlement: groupMembershipEntitlement()}

		annos, err := groupBuilder(&Okta{client: client}).Revoke(t.Context(), grant)
		if err != nil {
			t.Fatalf("Revoke() error: %v", err)
		}
		if !annos.Contains(&v2.GrantAlreadyRevoked{}) {
			t.Fatalf("Revoke() annotations = %v, want GrantAlreadyRevoked", annos)
		}
	})
}

func TestAppGrantIdempotency(t *testing.T) {
	t.Run("missing app user proceeds to assign", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/apps/" + testAppID + "/users/" + testOktaUserID, statusCode: http.StatusNotFound, body: oktaNotFoundResponse()},
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaUserResponse(userStatusActive)},
			oktaRequestStep{method: http.MethodPost, path: "/api/v1/apps/" + testAppID + "/users", statusCode: http.StatusOK, body: oktaAppUserAssignedResponse()},
		)

		if _, err := newTestAppBuilder(client).Grant(t.Context(), testUserPrincipal(), appAccessEntitlement()); err != nil {
			t.Fatalf("Grant() error: %v", err)
		}
	})

	t.Run("already assigned user is a no-op", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/apps/" + testAppID + "/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaAppUserAssignedResponse()},
		)

		annos, err := newTestAppBuilder(client).Grant(t.Context(), testUserPrincipal(), appAccessEntitlement())
		if err != nil {
			t.Fatalf("Grant() error: %v", err)
		}
		if !annos.Contains(&v2.GrantAlreadyExists{}) {
			t.Fatalf("Grant() annotations = %v, want GrantAlreadyExists", annos)
		}
	})

	t.Run("missing app group proceeds to assign", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/apps/" + testAppID + "/groups/" + testGroupID, statusCode: http.StatusNotFound, body: oktaNotFoundResponse()},
			oktaRequestStep{method: http.MethodPut, path: "/api/v1/apps/" + testAppID + "/groups/" + testGroupID, statusCode: http.StatusOK, body: oktaAppGroupAssignmentResponse()},
		)

		if _, err := newTestAppBuilder(client).Grant(t.Context(), appGroupPrincipal(), appAccessEntitlement()); err != nil {
			t.Fatalf("Grant() error: %v", err)
		}
	})
}

// TestHandleOktaResponseErrorClassification is a pure unit test (no server) that
// pins the pre-existing classification behavior alongside the new 429 case, so a
// future change to rate-limit handling can't silently regress the others.
func TestHandleOktaResponseErrorClassification(t *testing.T) {
	tests := []struct {
		name string
		resp *okta.Response
		err  error
		want codes.Code
	}{
		{
			name: "okta not-found error code maps to NotFound",
			resp: &okta.Response{Response: &http.Response{StatusCode: http.StatusNotFound}},
			err:  &okta.Error{ErrorCode: "E0000007"},
			want: codes.NotFound,
		},
		{
			name: "5xx status maps to Unavailable",
			resp: &okta.Response{Response: &http.Response{StatusCode: http.StatusInternalServerError}},
			err:  errors.New("server error"),
			want: codes.Unavailable,
		},
		{
			name: "context deadline exceeded maps to DeadlineExceeded",
			err:  &url.Error{Op: "Put", URL: "https://example.okta.com", Err: context.DeadlineExceeded},
			want: codes.DeadlineExceeded,
		},
		{
			name: "429 status with response maps to Unavailable",
			resp: &okta.Response{Response: &http.Response{StatusCode: http.StatusTooManyRequests}},
			err:  errors.New("unexpected status code: 429"),
			want: codes.Unavailable,
		},
		{
			name: "too many requests sentinel without response maps to Unavailable",
			err:  errors.New("too many requests"),
			want: codes.Unavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handleOktaResponseError(tt.resp, tt.err)
			if got := status.Code(err); got != tt.want {
				t.Errorf("handleOktaResponseError() status = %s, want %s (error: %v)", got, tt.want, err)
			}
		})
	}
}

// TestServerErrorPreservesOktaErrorText proves a 5xx no longer discards the original
// Okta error (and its x-okta-request-id) behind the generic "server error" status.
func TestServerErrorPreservesOktaErrorText(t *testing.T) {
	base := errors.New("server error, x-okta-request-id=test-request-id")
	resp := &okta.Response{Response: &http.Response{StatusCode: http.StatusInternalServerError}}

	err := handleOktaResponseError(resp, base)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("handleOktaResponseError() status = %s, want %s (error: %v)", status.Code(err), codes.Unavailable, err)
	}
	if !errors.Is(err, base) {
		t.Fatalf("handleOktaResponseError() lost the original Okta error: %v", err)
	}
	if !strings.Contains(err.Error(), "x-okta-request-id=test-request-id") {
		t.Fatalf("handleOktaResponseError() error text lost the Okta request id: %v", err)
	}
}

// TestRevokeAcceptsEitherNotFoundSignal proves all three revoke paths treat an HTTP 404
// and a classified codes.NotFound as the same idempotent outcome, even when only one of
// the two signals is present in the response.
func TestRevokeAcceptsEitherNotFoundSignal(t *testing.T) {
	type revoker func(t *testing.T, client *okta.Client) (annotations.Annotations, error)

	appUserRevoke := func(t *testing.T, client *okta.Client) (annotations.Annotations, error) {
		grant := &v2.Grant{Principal: testUserPrincipal(), Entitlement: appAccessEntitlement()}
		return newTestAppBuilder(client).Revoke(t.Context(), grant)
	}
	appGroupRevoke := func(t *testing.T, client *okta.Client) (annotations.Annotations, error) {
		grant := &v2.Grant{Principal: appGroupPrincipal(), Entitlement: appAccessEntitlement()}
		return newTestAppBuilder(client).Revoke(t.Context(), grant)
	}
	groupRevoke := func(t *testing.T, client *okta.Client) (annotations.Annotations, error) {
		grant := &v2.Grant{Principal: testUserPrincipal(), Entitlement: groupMembershipEntitlement()}
		return groupBuilder(&Okta{client: client}).Revoke(t.Context(), grant)
	}

	paths := []struct {
		name   string
		method string
		path   string
		revoke revoker
	}{
		{"app user revoke", http.MethodGet, "/api/v1/apps/" + testAppID + "/users/" + testOktaUserID, appUserRevoke},
		{"app group revoke", http.MethodGet, "/api/v1/apps/" + testAppID + "/groups/" + testGroupID, appGroupRevoke},
		{"group revoke", http.MethodDelete, "/api/v1/groups/" + testGroupID + "/users/" + testOktaUserID, groupRevoke},
	}

	for _, p := range paths {
		t.Run(p.name+": 404 status with an unrelated error body", func(t *testing.T) {
			client := newScriptedOktaClient(t,
				oktaRequestStep{method: p.method, path: p.path, statusCode: http.StatusNotFound, body: oktaLifecycleErrorResponse()},
			)

			annos, err := p.revoke(t, client)
			if err != nil {
				t.Fatalf("Revoke() error: %v", err)
			}
			if !annos.Contains(&v2.GrantAlreadyRevoked{}) {
				t.Fatalf("Revoke() annotations = %v, want GrantAlreadyRevoked", annos)
			}
		})

		t.Run(p.name+": non-404 status with a not-found error body", func(t *testing.T) {
			client := newScriptedOktaClient(t,
				oktaRequestStep{method: p.method, path: p.path, statusCode: http.StatusBadRequest, body: oktaNotFoundResponse()},
			)

			annos, err := p.revoke(t, client)
			if err != nil {
				t.Fatalf("Revoke() error: %v", err)
			}
			if !annos.Contains(&v2.GrantAlreadyRevoked{}) {
				t.Fatalf("Revoke() annotations = %v, want GrantAlreadyRevoked", annos)
			}
		})
	}
}
