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
	require.Equal(t, "/api/v1/users/part/other?filter=bad", ts.requests()[0].uri)
}
