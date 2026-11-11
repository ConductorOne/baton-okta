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

func TestDeleteGroupAlreadyGone(t *testing.T) {
	client := newScriptedOktaClient(t, oktaRequestStep{
		method: http.MethodDelete, path: "/api/v1/groups/gone",
		statusCode: http.StatusNotFound, body: oktaNotFoundResponse(),
	})
	builder := groupBuilder(&Okta{client: client})
	_, err := builder.Delete(context.Background(), &v2.ResourceId{ResourceType: resourceTypeGroup.Id, Resource: "gone"}, nil)
	require.NoError(t, err)
}

func TestDeleteGroupRequiresGroupID(t *testing.T) {
	builder := groupBuilder(&Okta{client: newScriptedOktaClient(t)})
	for _, id := range []*v2.ResourceId{
		nil,
		{ResourceType: resourceTypeGroup.Id},
		{ResourceType: resourceTypeUser.Id, Resource: "00u1"},
	} {
		_, err := builder.Delete(context.Background(), id, nil)
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	}
}
