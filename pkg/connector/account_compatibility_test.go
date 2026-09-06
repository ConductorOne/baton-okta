package connector

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/protobuf/proto"
)

func TestLegacyCreationPreservesRequestsWithDiagnostics(t *testing.T) {
	for _, mode := range []string{"generated", "no-password"} {
		t.Run(mode, func(t *testing.T) {
			var body okta.CreateUserRequest
			activate := ""
			mux := http.NewServeMux()
			mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
				require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
				activate = r.URL.Query().Get("activate")
				writeOktaTestResponse(w, http.StatusOK, oktaUserResponse(userStatusStaged))
			})
			server := newTestServerClient(t, mux)
			opts := randomPasswordCreds(32)
			flags := map[string]any{"create_inactive": true, "password_change_on_login_required": true}
			if mode == "no-password" {
				opts = v2.LocalCredentialOptions_builder{NoPassword: &v2.LocalCredentialOptions_NoPassword{}, ForceChangeAtNextLogin: true}.Build()
			}
			var logs bytes.Buffer
			logger := zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(&logs), zap.WarnLevel))
			ctx := ctxzap.ToContext(t.Context(), logger)
			result, _, _, err := userBuilder(&Okta{client: server.client}).CreateAccount(ctx, bootstrapAccountInfo(t, flags), opts)
			require.NoError(t, err)
			_, ok := result.(*v2.CreateAccountResponse_SuccessResult)
			require.True(t, ok)
			require.Equal(t, "false", activate)
			require.Equal(t, int32(1), server.Requests())
			require.Contains(t, logs.String(), `"level":"warn"`)
			if mode == "generated" {
				require.Len(t, body.Credentials.Password.Value, 32)
			} else {
				require.Nil(t, body.Credentials)
			}
		})
	}
}

func TestPreviouslyInvalidLegacyCombinationStillRejects(t *testing.T) {
	server := newTestServerClient(t, http.NewServeMux())
	_, _, _, err := userBuilder(&Okta{client: server.client}).CreateAccount(t.Context(),
		bootstrapAccountInfo(t, map[string]any{"send_activation_email": false, "password_change_on_login_required": true}), randomPasswordCreds(32))
	require.Error(t, err)
	require.Zero(t, server.Requests())
}

func TestStrictNoPasswordForceChangeRejectsBeforeProvider(t *testing.T) {
	server := newTestServerClient(t, http.NewServeMux())
	opts := v2.LocalCredentialOptions_builder{NoPassword: &v2.LocalCredentialOptions_NoPassword{}, ForceChangeAtNextLogin: true}.Build()
	_, _, _, err := userBuilder(&Okta{client: server.client, strictAccountCreation: true}).CreateAccount(t.Context(), bootstrapAccountInfo(t, nil), opts)
	require.Error(t, err)
	require.Zero(t, server.Requests())
}

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
	require.NotContains(t, second.GetProfile().GetFields(), "c1_okta_observed_at")
	require.NotContains(t, second.GetProfile().GetFields(), "c1_okta_fresh_observation")
}
