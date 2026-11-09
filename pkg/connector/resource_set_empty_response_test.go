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

func TestResourceSetGetEmptyResponse(t *testing.T) {
	client := newScriptedOktaClient(t, oktaRequestStep{
		method: http.MethodGet, path: "/api/v1/iam/resource-sets/rs1",
		statusCode: http.StatusOK,
	})
	builder := resourceSetsBuilder("example.com", client)
	resource, _, err := builder.Get(context.Background(), &v2.ResourceId{Resource: "rs1"}, nil)
	require.Nil(t, resource)
	require.Error(t, err)
	require.Equal(t, codes.Unknown, status.Code(err))
}
