package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/conductorone/baton-okta/pkg/okta"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	sdkResource "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/stretchr/testify/require"
)

func TestConnectorRequestPathsEscapeIDs(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		if r.URL.RawPath == "/api/v1/groups/%2E%2E/roles" {
			_, _ = w.Write([]byte(`[]`))
		} else {
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer server.Close()
	orgURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	client, err := okta.NewClient(okta.Config{OrgURL: orgURL, HTTPClient: server.Client()})
	require.NoError(t, err)
	ctx := context.Background()
	_, _, err = getUser(ctx, client, "user/a?b")
	require.NoError(t, err)
	_, _, err = listGroupAssignedRoles(ctx, client, "..")
	require.NoError(t, err)
	_, _, err = getOktaIamCustomRole(ctx, client, "role/%2F")
	require.NoError(t, err)
	_, _, err = listBindings(ctx, client, "set/a")
	require.NoError(t, err)
	rsb := &resourceSetsBindingsResourceType{client: client}
	_, err = rsb.unassignMemberFromBinding(ctx, "set/a", "role?b", "member#c")
	require.NoError(t, err)
	require.Equal(t, []string{
		"/api/v1/users/user%2Fa%3Fb",
		"/api/v1/groups/%2E%2E/roles",
		"/api/v1/iam/roles/role%2F%252F",
		"/api/v1/iam/resource-sets/set%2Fa/bindings",
		"/api/v1/iam/resource-sets/set%2Fa/bindings/role%3Fb/members/member%23c",
	}, paths)
}

func TestBindingMemberPathsDecodeOnlySupportedTypes(t *testing.T) {
	members := `{"members":[
		{"id":"m1","_links":{"self":{"href":"https://example.okta.com/api/v1/iam/resource-sets/rs1/bindings/cr1/members/users/00u%2F1"}}},
		{"id":"m2","_links":{"self":{"href":"https://example.okta.com/api/v1/iam/resource-sets/rs1/bindings/cr1/members/apps/%zz"}}},
		{"id":"m3","_links":{"self":{"href":"https://example.okta.com/api/v1/iam/resource-sets/rs1/bindings/cr1/members/groups/00g1"}}}
	]}`
	path := "/api/v1/iam/resource-sets/rs1/bindings/cr1/members"
	client := newScriptedOktaClient(t,
		oktaRequestStep{method: http.MethodGet, path: path, statusCode: http.StatusOK, body: members},
		oktaRequestStep{method: http.MethodGet, path: path, statusCode: http.StatusOK, body: members},
	)
	rsb := resourceSetsBindingsBuilder("example.com", client)
	binding := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeResourceSetsBindings.Id, Resource: "rs1:cr1"}}

	grants, _, err := rsb.Grants(context.Background(), binding, sdkResource.SyncOpAttrs{})
	require.NoError(t, err)
	require.Len(t, grants, 2)
	require.Equal(t, "00u/1", grants[0].GetPrincipal().GetId().GetResource())
	require.Equal(t, "00g1", grants[1].GetPrincipal().GetId().GetResource())

	entitlement := &v2.Entitlement{Resource: binding}
	principal := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeGroup.Id, Resource: "00g9"}}
	_, err = rsb.Revoke(context.Background(), &v2.Grant{Entitlement: entitlement, Principal: principal})
	require.NoError(t, err)
}
