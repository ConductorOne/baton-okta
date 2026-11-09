package connector

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/conductorone/baton-okta/pkg/okta"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGroupRoleProvisioningIdempotency(t *testing.T) {
	t.Run("already assigned", func(t *testing.T) {
		client := newScriptedOktaClient(t, oktaRequestStep{
			method: http.MethodPost, path: "/api/v1/groups/" + testGroupID + "/roles",
			statusCode: http.StatusBadRequest, body: `{"errorCode":"E0000090","errorSummary":"already assigned"}`,
		})
		annos, err := roleBuilder(client, nil).Grant(t.Context(), appGroupPrincipal(), roleAssignedEntitlement())
		require.NoError(t, err)
		require.True(t, annos.Contains(&v2.GrantAlreadyExists{}))
	})
	t.Run("delete races with another removal", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{
				method: http.MethodGet, path: "/api/v1/groups/" + testGroupID + "/roles",
				statusCode: http.StatusOK, body: `[{"id":"assignment1","type":"` + testRoleType + `","status":"ACTIVE"}]`,
			},
			oktaRequestStep{method: http.MethodDelete, path: "/api/v1/groups/" + testGroupID + "/roles/assignment1", statusCode: http.StatusNotFound, body: oktaNotFoundResponse()},
		)
		_, err := roleBuilder(client, nil).Revoke(t.Context(), &v2.Grant{Principal: appGroupPrincipal(), Entitlement: roleAssignedEntitlement()})
		require.Equal(t, codes.NotFound, status.Code(err))
	})
	t.Run("group not found", func(t *testing.T) {
		client := newScriptedOktaClient(t, oktaRequestStep{
			method: http.MethodGet, path: "/api/v1/groups/" + testGroupID + "/roles",
			statusCode: http.StatusNotFound, body: oktaNotFoundResponse(),
		})
		annos, err := roleBuilder(client, nil).Revoke(t.Context(), &v2.Grant{Principal: appGroupPrincipal(), Entitlement: roleAssignedEntitlement()})
		require.NoError(t, err)
		require.True(t, annos.Contains(&v2.GrantAlreadyRevoked{}))
	})
}

func TestGroupRoleRevokeUsesFreshLookup(t *testing.T) {
	var gets, deletes int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodDelete {
			deletes++
			w.WriteHeader(http.StatusNoContent)
			return
		}
		gets++
		if gets == 1 || gets > 2 {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		_, _ = w.Write([]byte(`[{"id":"assignment1","type":"` + testRoleType + `","status":"ACTIVE"}]`))
	}))
	defer server.Close()
	orgURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	client, err := okta.NewClient(okta.Config{OrgURL: orgURL, HTTPClient: server.Client(), CacheEnabled: true})
	require.NoError(t, err)
	_, _, err = client.ListGroupRoles(t.Context(), testGroupID)
	require.NoError(t, err)
	_, err = roleBuilder(client, nil).Revoke(t.Context(), &v2.Grant{Principal: appGroupPrincipal(), Entitlement: roleAssignedEntitlement()})
	require.NoError(t, err)
	require.Equal(t, 2, gets)
	require.Equal(t, 1, deletes)
	roles, _, err := client.ListGroupRoles(t.Context(), testGroupID)
	require.NoError(t, err)
	require.Empty(t, roles)
	require.Equal(t, 3, gets, "the pre-delete list must not remain cached")
}
