package connector

import (
	"context"
	"net/http"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/stretchr/testify/require"
)

func TestUserGetEmptyResponse(t *testing.T) {
	client := newScriptedOktaClient(t, oktaRequestStep{
		method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID,
		statusCode: http.StatusOK,
	})
	builder := &userResourceType{connector: &Okta{client: client}}
	require.Panics(t, func() {
		_, _, _ = builder.Get(context.Background(), &v2.ResourceId{Resource: testOktaUserID}, nil)
	})
}
