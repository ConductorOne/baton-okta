package connector

import (
	"context"
	"net/http"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	sdkResource "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/stretchr/testify/require"
)

func TestOperationErrorWording(t *testing.T) {
	client := newScriptedOktaClient(t, oktaRequestStep{
		method: http.MethodGet, path: "/api/v1/apps",
		statusCode: http.StatusInternalServerError, body: `{"errorCode":"E0000009","errorSummary":"internal error"}`,
	})
	app := appBuilder("example.com", "", false, false, nil, client)
	_, _, err := app.List(context.Background(), nil, sdkResource.SyncOpAttrs{})
	require.ErrorContains(t, err, "failed to list users")

	role := &roleResourceType{}
	principal := &v2.Resource{Id: &v2.ResourceId{ResourceType: "app", Resource: "app1"}}
	_, err = role.Grant(context.Background(), principal, nil)
	require.ErrorContains(t, err, "repo membership")
	_, err = role.Revoke(context.Background(), &v2.Grant{Principal: principal})
	require.ErrorContains(t, err, "okta-connector:only users or groups")
}
