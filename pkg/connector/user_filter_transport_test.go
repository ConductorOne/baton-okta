package connector

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type filteredReadTestConnector struct{ user *userResourceType }

func (c *filteredReadTestConnector) Metadata(context.Context) (*v2.ConnectorMetadata, error) {
	return &v2.ConnectorMetadata{DisplayName: "Filtered read fixture"}, nil
}

func (c *filteredReadTestConnector) Validate(context.Context) (annotations.Annotations, error) {
	return nil, nil
}

func (c *filteredReadTestConnector) ResourceSyncers(context.Context) []connectorbuilder.ResourceSyncerV2 {
	return []connectorbuilder.ResourceSyncerV2{c.user}
}

func TestFilteredReadQualifierSurvivesSDKAndGRPC(t *testing.T) {
	var providerMode atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch providerMode.Load() {
		case 1:
			writeOktaTestResponse(w, http.StatusNotFound, oktaNotFoundResponse())
		case 2:
			writeOktaTestResponse(w, http.StatusOK, `{}`)
		default:
			writeOktaTestResponse(w, http.StatusOK, oktaUserFullJSON(userStatusActive, ""))
		}
	}))
	defer provider.Close()
	user := userBuilder(&Okta{client: newCachedOktaTestClient(t, provider), userFilters: &userFilterConfig{includedEmailDomains: []string{"excluded.invalid"}}})
	connector, err := connectorbuilder.NewConnector(t.Context(), &filteredReadTestConnector{user: user})
	require.NoError(t, err)
	listenConfig := net.ListenConfig{}
	listener, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	server := grpc.NewServer()
	v2.RegisterResourceGetterServiceServer(server, connector)
	defer server.Stop()
	go func() { _ = server.Serve(listener) }()
	connection, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer connection.Close()
	client := v2.NewResourceGetterServiceClient(connection)
	request := &v2.ResourceGetterServiceGetResourceRequest{ResourceId: userResourceID()}
	_, err = client.GetResource(t.Context(), request)
	// The SDK syncer skips this code, while point-read consumers retain the qualifier.
	require.Equal(t, codes.NotFound, status.Code(err))
	var filterInfo *errdetails.ErrorInfo
	for _, detail := range status.Convert(err).Details() {
		if info, ok := detail.(*errdetails.ErrorInfo); ok {
			filterInfo = info
		}
	}
	require.NotNil(t, filterInfo)
	require.Equal(t, "RESOURCE_FILTERED", filterInfo.Reason)
	require.Equal(t, "baton-okta", filterInfo.Domain)
	require.Equal(t, testOktaUserID, filterInfo.Metadata["resource_id"])
	providerMode.Store(1)
	_, err = client.GetResource(t.Context(), request)
	require.Equal(t, codes.NotFound, status.Code(err))
	for _, detail := range status.Convert(err).Details() {
		if info, ok := detail.(*errdetails.ErrorInfo); ok {
			require.NotEqual(t, "RESOURCE_FILTERED", info.Reason)
		}
	}
	providerMode.Store(2)
	_, err = client.GetResource(t.Context(), request)
	require.Error(t, err)
	require.NotEqual(t, codes.NotFound, status.Code(err), "malformed success is not absence or a filter skip")
}
