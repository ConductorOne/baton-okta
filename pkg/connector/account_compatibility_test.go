package connector

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestCreateActivationReadbackIgnoresSyncPopulationFilter(t *testing.T) {
	client := newScriptedOktaClient(t,
		oktaRequestStep{method: http.MethodPost, path: "/api/v1/users", statusCode: http.StatusOK, body: oktaUserResponse(userStatusStaged)},
		oktaRequestStep{method: http.MethodPost, path: "/api/v1/users/" + testOktaUserID + "/lifecycle/activate", statusCode: http.StatusOK, body: `{}`},
		oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaUserResponse(userStatusActive)},
	)
	builder := userBuilder(&Okta{client: client, userFilters: &userFilterConfig{includedEmailDomains: []string{"another.invalid"}}})
	result, _, _, err := builder.CreateAccount(t.Context(), bootstrapAccountInfo(t, map[string]any{"send_activation_email": false}), suppliedPasswordCreds("fixture-only"))
	require.NoError(t, err)
	success, ok := result.(*v2.CreateAccountResponse_SuccessResult)
	require.True(t, ok, "authorized creation readback must not be filtered by sync population")
	require.Equal(t, testOktaUserID, success.GetResource().GetId().GetResource())
}

func TestUnchangedUserGetsHaveStablePersistedProfiles(t *testing.T) {
	client := newScriptedOktaClient(t,
		oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaUserFullJSON(userStatusActive, "")},
		oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaUserFullJSON(userStatusActive, "")},
	)
	builder := userBuilder(&Okta{client: client, userFilters: &userFilterConfig{}})
	first, _, err := builder.Get(t.Context(), userResourceID(), nil)
	require.NoError(t, err)
	second, _, err := builder.Get(t.Context(), userResourceID(), nil)
	require.NoError(t, err)
	require.True(t, proto.Equal(first, second), "read time must not churn persisted resource versions")
}

func TestAccountActivationReturnsActualProviderStatus(t *testing.T) {
	for _, status := range []string{userStatusStaged, userStatusActive} {
		t.Run(status, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("POST /api/v1/users", func(w http.ResponseWriter, _ *http.Request) {
				writeOktaTestResponse(w, http.StatusOK, oktaUserResponse(userStatusStaged))
			})
			mux.HandleFunc("POST /api/v1/users/"+testOktaUserID+"/lifecycle/activate", func(w http.ResponseWriter, _ *http.Request) {
				writeOktaTestResponse(w, http.StatusOK, `{}`)
			})
			mux.HandleFunc("GET /api/v1/users/"+testOktaUserID, func(w http.ResponseWriter, _ *http.Request) {
				writeOktaTestResponse(w, http.StatusOK, oktaUserFullJSON(status, userStatusActive))
			})
			server := newTestServerClient(t, mux)
			result, plaintext, _, err := userBuilder(&Okta{client: server.client}).CreateAccount(t.Context(),
				bootstrapAccountInfo(t, map[string]any{"send_activation_email": false}), randomPasswordCreds(32))
			require.NoError(t, err)
			success, ok := result.(*v2.CreateAccountResponse_SuccessResult)
			require.True(t, ok)
			require.Equal(t, status, success.GetResource().GetStatus().GetDetails())
			require.Len(t, plaintext, 1)
			require.Equal(t, int32(3), server.Requests())
		})
	}
}

func TestFederatedNoPasswordAccountUsesProviderSemantics(t *testing.T) {
	var captured atomic.Value
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		var created okta.CreateUserRequest
		if err := json.NewDecoder(r.Body).Decode(&created); err != nil {
			t.Errorf("decoding request body: %v", err)
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		captured.Store(createRequestSnapshot{body: created, provider: r.URL.Query().Get("provider"), activate: r.URL.Query().Get("activate")})
		writeOktaTestResponse(w, http.StatusOK, oktaUserResponse(userStatusStaged))
	})
	server := newTestServerClient(t, mux)
	opts := v2.LocalCredentialOptions_builder{NoPassword: &v2.LocalCredentialOptions_NoPassword{}}.Build()
	result, plaintext, _, err := userBuilder(&Okta{client: server.client}).CreateAccount(t.Context(),
		bootstrapAccountInfo(t, map[string]any{"provider_type": providerTypeFederation, "create_inactive": true}), opts)
	require.NoError(t, err)
	require.NotNil(t, captured.Load())
	observed := captured.Load().(createRequestSnapshot)
	require.Equal(t, "true", observed.provider, "Okta ignores credentials.provider without this query option")
	require.Equal(t, "false", observed.activate)
	require.NotNil(t, observed.body.Credentials)
	require.NotNil(t, observed.body.Credentials.Provider)
	require.Equal(t, providerTypeFederation, observed.body.Credentials.Provider.Type)
	require.Equal(t, providerTypeFederation, observed.body.Credentials.Provider.Name)
	require.Nil(t, observed.body.Credentials.Password)
	success, ok := result.(*v2.CreateAccountResponse_SuccessResult)
	require.True(t, ok)
	require.Equal(t, testOktaUserID, success.GetResource().GetId().GetResource())
	require.Empty(t, plaintext)
	require.Equal(t, int32(1), server.Requests(), "inactive federation is one create, not create then disable")
}
