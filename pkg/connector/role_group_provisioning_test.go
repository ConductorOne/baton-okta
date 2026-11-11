package connector

import (
	"net/http"
	"testing"

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
