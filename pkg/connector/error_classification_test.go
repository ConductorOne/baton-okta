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
	testGroupID  = "00g1abc2def3GHI4jk5"
	testAppID    = "0oa1abc2def3GHI4jk5"
	testRoleType = "SUPER_ADMIN"
)

// rateLimitedStep builds a 429 carrying the headers Get429BackoffTime needs; without
// them the SDK fails on header parsing and never emits the rate-limit error text.
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

func roleAssignedEntitlement() *v2.Entitlement {
	return &v2.Entitlement{Resource: &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeRole.Id, Resource: testRoleType}}}
}

func oktaAppUserAssignedResponse() string {
	return `{"id":"` + testOktaUserID + `","status":"ACTIVE","scope":"USER","lastUpdated":"2024-01-01T00:00:00.000Z"}`
}

func oktaAppGroupAssignmentResponse() string {
	return `{"id":"` + testGroupID + `","lastUpdated":"2024-01-01T00:00:00.000Z"}`
}

func newTestAppBuilder(client *okta.Client) *appResourceType {
	return appBuilder("", "", false, false, nil, client)
}

// TestRateLimitClassification drives the real vendored SDK: a 429 that exhausts its own
// retries must reach the connector as codes.Unavailable, not codes.Unknown.
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

	t.Run("role grant", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			rateLimitedStep(http.MethodPost, "/api/v1/users/"+testOktaUserID+"/roles"),
		)

		_, err := roleBuilder(client, nil).Grant(t.Context(), testUserPrincipal(), roleAssignedEntitlement())
		if status.Code(err) != codes.Unavailable {
			t.Fatalf("Grant() status = %s, want %s (error: %v)", status.Code(err), codes.Unavailable, err)
		}
	})

	t.Run("role revoke", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			rateLimitedStep(http.MethodGet, "/api/v1/users/"+testOktaUserID+"/roles"),
		)
		grant := &v2.Grant{Principal: testUserPrincipal(), Entitlement: roleAssignedEntitlement()}

		_, err := roleBuilder(client, nil).Revoke(t.Context(), grant)
		if status.Code(err) != codes.Unavailable {
			t.Fatalf("Revoke() status = %s, want %s (error: %v)", status.Code(err), codes.Unavailable, err)
		}
	})
}

// TestGrantPrecheckServerErrorClassification guards a Grant pre-check that reads a
// parseable Okta error body off a 5xx: it must classify as codes.Unavailable, not the
// codes.Unknown a bare %v-wrapped error would produce.
func TestGrantPrecheckServerErrorClassification(t *testing.T) {
	serverErrorBody := `{"errorCode":"E0000009","errorSummary":"Internal Server Error"}`

	t.Run("app grant: 5xx on pre-check user lookup", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/apps/" + testAppID + "/users/" + testOktaUserID, statusCode: http.StatusInternalServerError, body: serverErrorBody},
		)

		_, err := newTestAppBuilder(client).Grant(t.Context(), testUserPrincipal(), appAccessEntitlement())
		if status.Code(err) != codes.Unavailable {
			t.Fatalf("Grant() status = %s, want %s (error: %v)", status.Code(err), codes.Unavailable, err)
		}
	})

	t.Run("app grant: 5xx on pre-check group lookup", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/apps/" + testAppID + "/groups/" + testGroupID, statusCode: http.StatusInternalServerError, body: serverErrorBody},
		)

		_, err := newTestAppBuilder(client).Grant(t.Context(), appGroupPrincipal(), appAccessEntitlement())
		if status.Code(err) != codes.Unavailable {
			t.Fatalf("Grant() status = %s, want %s (error: %v)", status.Code(err), codes.Unavailable, err)
		}
	})

	t.Run("role grant: 5xx on assign role to user", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{method: http.MethodPost, path: "/api/v1/users/" + testOktaUserID + "/roles", statusCode: http.StatusInternalServerError, body: serverErrorBody},
		)

		_, err := roleBuilder(client, nil).Grant(t.Context(), testUserPrincipal(), roleAssignedEntitlement())
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

	t.Run("app revoke: user removed between pre-check and delete is already revoked", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/apps/" + testAppID + "/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaAppUserAssignedResponse()},
			oktaRequestStep{method: http.MethodDelete, path: "/api/v1/apps/" + testAppID + "/users/" + testOktaUserID, statusCode: http.StatusNotFound, body: oktaNotFoundResponse()},
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

	t.Run("resource-sets revoke: 404 delete is already revoked", func(t *testing.T) {
		resourceSetId := "iamRSET2pqrstuvwxy"
		customRoleId := "cr2pqrstuvwxyzabcd"
		client := newScriptedOktaClient(t,
			oktaRequestStep{
				method:     http.MethodDelete,
				path:       "/api/v1/iam/resource-sets/" + resourceSetId + "/bindings/" + customRoleId,
				statusCode: http.StatusNotFound,
				body:       oktaNotFoundResponse(),
			},
		)
		grant := &v2.Grant{
			Principal:   &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeCustomRole.Id, Resource: customRoleId}},
			Entitlement: &v2.Entitlement{Resource: &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeResourceSets.Id, Resource: resourceSetId}}},
		}

		annos, err := resourceSetsBuilder("", client, nil).Revoke(t.Context(), grant)
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

func TestRoleGrantIdempotency(t *testing.T) {
	t.Run("role grant to user: already assigned is a no-op", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{
				method:     http.MethodPost,
				path:       "/api/v1/users/" + testOktaUserID + "/roles",
				statusCode: http.StatusBadRequest,
				body:       `{"errorCode":"E0000090","errorSummary":"You have specified a role that is already assigned to the user"}`,
			},
		)

		annos, err := roleBuilder(client, nil).Grant(t.Context(), testUserPrincipal(), roleAssignedEntitlement())
		if err != nil {
			t.Fatalf("Grant() error: %v", err)
		}
		if !annos.Contains(&v2.GrantAlreadyExists{}) {
			t.Fatalf("Grant() annotations = %v, want GrantAlreadyExists", annos)
		}
	})
}

func TestResourceSetBindingGrantIdempotency(t *testing.T) {
	resourceSetId := "iamRSET2pqrstuvwxy"
	customRoleId := "cr2pqrstuvwxyzabcd"
	entitlement := &v2.Entitlement{Resource: &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeResourceSets.Id, Resource: resourceSetId + ":" + customRoleId}}}

	t.Run("409 duplicate member is a no-op", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{
				method:     http.MethodPost,
				path:       "/api/v1/iam/resource-sets/" + resourceSetId + "/bindings",
				statusCode: http.StatusConflict,
				body:       `{"errorCode":"E0000038","errorSummary":"A member specified is already associated with this binding."}`,
			},
		)

		annos, err := resourceSetsBindingsBuilder("", client, nil).Grant(t.Context(), testUserPrincipal(), entitlement)
		if err != nil {
			t.Fatalf("Grant() error: %v", err)
		}
		if !annos.Contains(&v2.GrantAlreadyExists{}) {
			t.Fatalf("Grant() annotations = %v, want GrantAlreadyExists", annos)
		}
	})
}

func TestResourceSetBindingRevokeIdempotency(t *testing.T) {
	resourceSetId := "iamRSET2pqrstuvwxy"
	customRoleId := "cr2pqrstuvwxyzabcd"
	grant := &v2.Grant{
		Principal:   testUserPrincipal(),
		Entitlement: &v2.Entitlement{Resource: &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeResourceSets.Id, Resource: resourceSetId + ":" + customRoleId}}},
	}

	t.Run("404 on member lookup is already revoked", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{
				method:     http.MethodGet,
				path:       "/api/v1/iam/resource-sets/" + resourceSetId + "/bindings/" + customRoleId + "/members",
				statusCode: http.StatusNotFound,
				body:       oktaNotFoundResponse(),
			},
		)

		annos, err := resourceSetsBindingsBuilder("", client, nil).Revoke(t.Context(), grant)
		if err != nil {
			t.Fatalf("Revoke() error: %v", err)
		}
		if !annos.Contains(&v2.GrantAlreadyRevoked{}) {
			t.Fatalf("Revoke() annotations = %v, want GrantAlreadyRevoked", annos)
		}
	})
}

// TestHandleOktaResponseErrorClassification pins the pre-existing classification
// behavior alongside the new 429 case.
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
			// Self-referential: types the same literal the classifier matches, so this
			// pins the mapping, not the SDK's wording.
			name: "rate-limit text without response maps to Unavailable",
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

// TestRateLimitExhaustedCarriesRetryDetail proves the exhausted-429 classification
// attaches a RateLimitDescription the retryer waits on. The SDK already discarded Okta's
// headers, so ResetAt is ExtractRateLimitData's 60s no-headers default, not Okta's window.
func TestRateLimitExhaustedCarriesRetryDetail(t *testing.T) {
	err := handleOktaResponseError(nil, errors.New("too many requests"))
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("handleOktaResponseError() status = %s, want %s (error: %v)", status.Code(err), codes.Unavailable, err)
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("handleOktaResponseError() error is not a gRPC status: %v", err)
	}

	var found *v2.RateLimitDescription
	for _, detail := range st.Details() {
		if rl, ok := detail.(*v2.RateLimitDescription); ok {
			found = rl
			break
		}
	}
	if found == nil {
		t.Fatalf("handleOktaResponseError() status details = %v, want a *v2.RateLimitDescription", st.Details())
	}
	if !found.GetResetAt().AsTime().After(time.Now()) {
		t.Fatalf("RateLimitDescription.ResetAt = %v, want a time in the future", found.GetResetAt().AsTime())
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

// TestRateLimitHeaderParseFailureClassification covers the two 429s that leave the SDK's
// retry loop through Get429BackoffTime instead of the exhausted-retries sentinel. Okta's
// concurrency limit produces the second one by omitting X-Rate-Limit-Reset, and both
// arrive with the response already dropped, so only the error text identifies them.
func TestRateLimitHeaderParseFailureClassification(t *testing.T) {
	path := "/api/v1/groups/" + testGroupID + "/users/" + testOktaUserID
	body := `{"errorCode":"E0000047","errorSummary":"API call exceeded rate limit"}`

	tests := []struct {
		name    string
		headers map[string]string
	}{
		{
			name:    "missing X-Rate-Limit-Reset",
			headers: map[string]string{"Date": time.Now().UTC().Format(http.TimeFormat)},
		},
		{
			name:    "unparseable Date",
			headers: map[string]string{"Date": "not-a-date", "X-Rate-Limit-Reset": "1700000000"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newScriptedOktaClient(t, oktaRequestStep{
				method:     http.MethodPut,
				path:       path,
				statusCode: http.StatusTooManyRequests,
				headers:    tt.headers,
				body:       body,
			})

			_, err := groupBuilder(&Okta{client: client}).Grant(t.Context(), testUserPrincipal(), groupMembershipEntitlement())
			if status.Code(err) != codes.Unavailable {
				t.Fatalf("Grant() status = %s, want %s (error: %v)", status.Code(err), codes.Unavailable, err)
			}
		})
	}
}

// TestSuccessPathReportsRateLimitAnnotations pins the rate-limit reporting the read paths
// already do: a successful provisioning call must hand back what quota is left.
func TestSuccessPathReportsRateLimitAnnotations(t *testing.T) {
	headers := map[string]string{
		"X-Rate-Limit-Limit":     "250",
		"X-Rate-Limit-Remaining": "17",
		"X-Rate-Limit-Reset":     strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10),
	}
	path := "/api/v1/groups/" + testGroupID + "/users/" + testOktaUserID

	assertReportsLimit := func(t *testing.T, annos annotations.Annotations, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		desc := &v2.RateLimitDescription{}
		ok, pickErr := annos.Pick(desc)
		if pickErr != nil {
			t.Fatalf("Pick() error: %v", pickErr)
		}
		if !ok {
			t.Fatalf("annotations = %v, want a RateLimitDescription", annos)
		}
		if desc.GetLimit() != 250 || desc.GetRemaining() != 17 {
			t.Fatalf("rate limit = %d/%d, want 17/250", desc.GetRemaining(), desc.GetLimit())
		}
	}

	t.Run("grant", func(t *testing.T) {
		client := newScriptedOktaClient(t, oktaRequestStep{
			method: http.MethodPut, path: path, statusCode: http.StatusNoContent, headers: headers,
		})

		annos, err := groupBuilder(&Okta{client: client}).Grant(t.Context(), testUserPrincipal(), groupMembershipEntitlement())
		assertReportsLimit(t, annos, err)
	})

	t.Run("revoke", func(t *testing.T) {
		client := newScriptedOktaClient(t, oktaRequestStep{
			method: http.MethodDelete, path: path, statusCode: http.StatusNoContent, headers: headers,
		})
		grant := &v2.Grant{Principal: testUserPrincipal(), Entitlement: groupMembershipEntitlement()}

		annos, err := groupBuilder(&Okta{client: client}).Revoke(t.Context(), grant)
		assertReportsLimit(t, annos, err)
	})
}

// TestGrantPrecheckKeepsOktaRequestID drives the pre-check end to end: the SDK appends
// x-okta-request-id to its own error on a 500 only, so re-reading the body with getError
// yields an error without it. Support triage needs that id, so the returned error has to
// carry the SDK's error too, not just the re-parsed one.
func TestGrantPrecheckKeepsOktaRequestID(t *testing.T) {
	const requestID = "test-okta-request-id"

	client := newScriptedOktaClient(t, oktaRequestStep{
		method:     http.MethodGet,
		path:       "/api/v1/apps/" + testAppID + "/users/" + testOktaUserID,
		statusCode: http.StatusInternalServerError,
		headers:    map[string]string{"x-okta-request-id": requestID},
		body:       `{"errorCode":"E0000009","errorSummary":"Internal Server Error"}`,
	})

	_, err := newTestAppBuilder(client).Grant(t.Context(), testUserPrincipal(), appAccessEntitlement())
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("Grant() status = %s, want %s (error: %v)", status.Code(err), codes.Unavailable, err)
	}
	if !strings.Contains(err.Error(), requestID) {
		t.Fatalf("Grant() error dropped the Okta request id: %v", err)
	}
}
