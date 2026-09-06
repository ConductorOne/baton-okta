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

func TestLegacyPasswordChangeQualifierSurvivesCreateAccountGRPC(t *testing.T) {
	for _, source := range []string{"profile", "credential", "both"} {
		t.Run(source, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("POST /api/v1/users", func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "false", r.URL.Query().Get("activate"))
				require.Empty(t, r.URL.Query().Get("nextLogin"), "legacy provider requests stay unchanged")
				writeOktaTestResponse(w, http.StatusOK, oktaUserResponse(userStatusStaged))
			})
			provider := newTestServerClient(t, mux)
			user := userBuilder(&Okta{client: provider.client})
			connector, err := connectorbuilder.NewConnector(t.Context(), &filteredReadTestConnector{user: user})
			require.NoError(t, err)
			listenConfig := net.ListenConfig{}
			listener, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer listener.Close()
			server := grpc.NewServer()
			v2.RegisterAccountManagerServiceServer(server, connector)
			defer server.Stop()
			go func() { _ = server.Serve(listener) }()
			connection, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
			require.NoError(t, err)
			defer connection.Close()
			opts := v2.CredentialOptions_builder{NoPassword: &v2.CredentialOptions_NoPassword{}}.Build()
			flags := map[string]any{"create_inactive": true}
			expected := make(map[string]string)
			if source != "credential" {
				flags[profileFieldPasswordChangeOnLoginRequired] = true
				expected[profileFieldPasswordChangeOnLoginRequired] = "true"
			}
			if source != "profile" {
				opts.SetForceChangeAtNextLogin(true)
				expected["force_change_at_next_login"] = "true"
			}
			response, err := v2.NewAccountManagerServiceClient(connection).CreateAccount(t.Context(), &v2.CreateAccountRequest{
				AccountInfo:       bootstrapAccountInfo(t, flags),
				CredentialOptions: opts,
				ResourceTypeId:    resourceTypeUser.Id,
			})
			require.NoError(t, err)
			require.NotNil(t, response.GetSuccess(), "legacy outcome type must remain unchanged")
			require.Equal(t, testOktaUserID, response.GetSuccess().GetResource().GetId().GetResource())
			info := &errdetails.ErrorInfo{}
			responseAnnotations := annotations.Annotations(response.GetAnnotations())
			found, err := responseAnnotations.Pick(info)
			require.NoError(t, err)
			require.True(t, found, "non-enforcement must be visible to the public SDK caller")
			require.Equal(t, "LEGACY_PASSWORD_CHANGE_NOT_ENFORCED", info.Reason)
			require.Equal(t, "baton-okta", info.Domain)
			require.Equal(t, expected, info.Metadata, "only actually unenforced options, never credentials or unrelated profile data")
			require.Empty(t, response.GetEncryptedData())
			require.Equal(t, int32(1), provider.Requests())
		})
	}
}

func TestLegacyQualifierSurvivesPartialCreateAccountGRPC(t *testing.T) {
	for _, outcome := range []string{"action-required", "in-progress"} {
		t.Run(outcome, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("POST /api/v1/users", func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "false", r.URL.Query().Get("activate"))
				writeOktaTestResponse(w, http.StatusOK, oktaUserResponse(userStatusStaged))
			})
			mux.HandleFunc("POST /api/v1/users/"+testOktaUserID+"/lifecycle/activate", func(w http.ResponseWriter, _ *http.Request) {
				if outcome == "action-required" {
					writeOktaTestResponse(w, http.StatusServiceUnavailable, `{}`)
					return
				}
				writeOktaTestResponse(w, http.StatusOK, `{}`)
			})
			mux.HandleFunc("GET /api/v1/users/"+testOktaUserID, func(w http.ResponseWriter, _ *http.Request) {
				writeOktaTestResponse(w, http.StatusOK, oktaUserFullJSON(userStatusStaged, ""))
			})
			provider := newTestServerClient(t, mux)
			user := userBuilder(&Okta{client: provider.client})
			connector, err := connectorbuilder.NewConnector(t.Context(), &filteredReadTestConnector{user: user})
			require.NoError(t, err)
			listenConfig := net.ListenConfig{}
			listener, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer listener.Close()
			server := grpc.NewServer()
			v2.RegisterAccountManagerServiceServer(server, connector)
			defer server.Stop()
			go func() { _ = server.Serve(listener) }()
			connection, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
			require.NoError(t, err)
			defer connection.Close()
			response, err := v2.NewAccountManagerServiceClient(connection).CreateAccount(t.Context(), &v2.CreateAccountRequest{
				AccountInfo: bootstrapAccountInfo(t, map[string]any{
					"send_activation_email": false, profileFieldPasswordChangeOnLoginRequired: true,
				}),
				CredentialOptions: v2.CredentialOptions_builder{NoPassword: &v2.CredentialOptions_NoPassword{}}.Build(),
				ResourceTypeId:    resourceTypeUser.Id,
			})
			require.NoError(t, err)
			require.Nil(t, response.GetSuccess(), "partial creation must retain its non-success outcome")
			if outcome == "action-required" {
				require.NotNil(t, response.GetActionRequired())
				require.Equal(t, testOktaUserID, response.GetActionRequired().GetResource().GetId().GetResource())
				require.Equal(t, int32(2), provider.Requests(), "unknown activation must not be replayed")
			} else {
				require.NotNil(t, response.GetInProgress())
				require.Equal(t, testOktaUserID, response.GetInProgress().GetResource().GetId().GetResource())
				require.Equal(t, int32(3), provider.Requests())
			}
			responseAnnotations := annotations.Annotations(response.GetAnnotations())
			info := &errdetails.ErrorInfo{}
			found, err := responseAnnotations.Pick(info)
			require.NoError(t, err)
			require.True(t, found, "partial outcomes must retain the non-enforcement qualifier")
			require.Equal(t, "LEGACY_PASSWORD_CHANGE_NOT_ENFORCED", info.Reason)
			require.Equal(t, "baton-okta", info.Domain)
			require.Equal(t, map[string]string{profileFieldPasswordChangeOnLoginRequired: "true"}, info.Metadata)
			require.Empty(t, response.GetEncryptedData())
		})
	}
}
