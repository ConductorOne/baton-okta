package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/conductorone/baton-okta/pkg/okta"
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
