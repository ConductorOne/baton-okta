package okta

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRequestPathsEscapeIDs(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, `{}`) })
	client, _ := newTestClient(t, ts)
	_, _, err := client.GetUser(context.Background(), "part/other?filter=bad")
	require.NoError(t, err)
	require.Equal(t, "/api/v1/users/part%2Fother%3Ffilter=bad", ts.requests()[0].uri)
	_, err = client.AddUserToGroup(context.Background(), "group/a", "user?x")
	require.NoError(t, err)
	_, _, err = client.GetApplicationUser(context.Background(), "app#one", "user%2Ftwo")
	require.NoError(t, err)
	_, _, err = client.GetResourceSet(context.Background(), "..")
	require.NoError(t, err)
	_, _, err = client.GetUser(context.Background(), "normal-id")
	require.NoError(t, err)
	requests := ts.requests()
	require.Equal(t, "/api/v1/groups/group%2Fa/users/user%3Fx", requests[1].uri)
	require.Equal(t, "/api/v1/apps/app%23one/users/user%252Ftwo", requests[2].uri)
	require.Equal(t, "/api/v1/iam/resource-sets/%2E%2E", requests[3].uri)
	require.Equal(t, "/api/v1/users/normal-id", requests[4].uri)
}
