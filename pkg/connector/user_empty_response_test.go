package connector

import (
	"context"
	"net/http"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestUserGetEmptyResponse(t *testing.T) {
	client := newScriptedOktaClient(t, oktaRequestStep{
		method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID,
		statusCode: http.StatusOK,
	})
	builder := &userResourceType{connector: &Okta{client: client}}
	resource, _, err := builder.Get(context.Background(), &v2.ResourceId{Resource: testOktaUserID}, nil)
	require.Nil(t, resource)
	require.Error(t, err)
	require.Equal(t, codes.Unknown, status.Code(err))
}
