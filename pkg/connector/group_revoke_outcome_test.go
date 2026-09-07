package connector

import (
	"net/http"
	"net/http/httptest"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	sdkGrant "github.com/conductorone/baton-sdk/pkg/types/grant"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// membershipGrant builds a minimal group-membership grant for revoke tests.
func membershipGrant() *v2.Grant {
	groupRes := &v2.Resource{Id: &v2.ResourceId{ResourceType: "group", Resource: "00g1testgroup"}}
	return sdkGrant.NewGrant(groupRes, "member", &v2.Resource{
		Id: &v2.ResourceId{ResourceType: resourceTypeUser.Id, Resource: testOktaUserID},
	})
}

// TestGroupRevokeQualifiedOutcomes guards qualified absence:
// provider-qualified 404 on RemoveUserFromGroup is an already-revoked outcome
// (GrantAlreadyRevoked annotation, nil error), while a permission failure
// stays an error — an unknown outcome must never be described as a no-op.
// Duplicate adds rely on Okta's native idempotency (204 for an existing
// member) and are not retried or pre-scanned here.
func TestGroupRevokeQualifiedOutcomes(t *testing.T) {
	newRevokeConnector := func(handler http.HandlerFunc) *groupResourceType {
		server := httptest.NewServer(handler)
		t.Cleanup(func() { server.Close() })
		_, client, err := okta.NewClient(
			t.Context(),
			okta.WithOrgUrl(server.URL),
			okta.WithToken("test-token"),
			okta.WithHttpClientPtr(server.Client()),
			okta.WithTestingDisableHttpsCheck(true),
			okta.WithRateLimitMaxRetries(0),
		)
		if err != nil {
			t.Fatalf("create Okta test client: %v", err)
		}
		return &groupResourceType{connector: &Okta{client: client}}
	}

	t.Run("provider-qualified 404 is already-revoked, not failure", func(t *testing.T) {
		g := newRevokeConnector(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodDelete {
				t.Errorf("unexpected method: %s", r.Method)
			}
			writeOktaTestResponse(w, http.StatusNotFound, oktaNotFoundResponse())
		})

		annos, err := g.Revoke(t.Context(), membershipGrant())
		if err != nil {
			t.Fatalf("qualified not-found revoke must succeed, got: %v", err)
		}
		if annos == nil {
			t.Fatalf("expected GrantAlreadyRevoked annotation, got nil")
		}
		if !annos.Contains(&v2.GrantAlreadyRevoked{}) {
			t.Fatalf("expected GrantAlreadyRevoked annotation in %v", annos)
		}
	})

	t.Run("permission failure stays an error, never a no-op", func(t *testing.T) {
		g := newRevokeConnector(func(w http.ResponseWriter, r *http.Request) {
			// A permission failure is an unknown outcome for the revocation:
			// the provider never qualified absence, so it must stay an error.
			writeOktaTestResponse(w, http.StatusForbidden,
				`{"errorCode":"E0000006","errorSummary":"You do not have permission","errorLink":"E0000006","errorId":"test","errorCauses":[]}`)
		})

		annos, err := g.Revoke(t.Context(), membershipGrant())
		if err == nil {
			t.Fatalf("unknown revoke outcome must stay an error, got success with annos %v", annos)
		}
		if status.Code(err) == codes.NotFound {
			t.Fatalf("permission failure must not be classified as qualified absence")
		}
	})
}
