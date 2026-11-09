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
	_, err := builder.Delete(context.Background(), &v2.ResourceId{Resource: "gone"}, nil)
	require.Equal(t, codes.NotFound, status.Code(err))
}
