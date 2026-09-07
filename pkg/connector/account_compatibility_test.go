package connector

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/protobuf/proto"
)

func TestLegacyCreationPreservesRequestsWithDiagnostics(t *testing.T) {
	for _, mode := range []string{"generated", "generated-sdk-change", "no-password"} {
		t.Run(mode, func(t *testing.T) {
			var captured atomic.Value
			mux := http.NewServeMux()
			mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
				var body okta.CreateUserRequest
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("decoding request body: %v", err)
					http.Error(w, "invalid request body", http.StatusBadRequest)
					return
				}
				captured.Store(createRequestSnapshot{body: body, activate: r.URL.Query().Get("activate")})
				writeOktaTestResponse(w, http.StatusOK, oktaUserResponse(userStatusStaged))
			})
			server := newTestServerClient(t, mux)
			opts := randomPasswordCreds(32)
			flags := map[string]any{"create_inactive": true, "password_change_on_login_required": true}
			if mode == "no-password" {
				opts = v2.LocalCredentialOptions_builder{NoPassword: &v2.LocalCredentialOptions_NoPassword{}, ForceChangeAtNextLogin: true}.Build()
			}
			if mode == "generated-sdk-change" {
				delete(flags, profileFieldPasswordChangeOnLoginRequired)
				opts.SetForceChangeAtNextLogin(true)
			}
			var logs bytes.Buffer
			logger := zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(&logs), zap.WarnLevel))
			ctx := ctxzap.ToContext(t.Context(), logger)
			result, _, annos, err := userBuilder(&Okta{client: server.client}).CreateAccount(ctx, bootstrapAccountInfo(t, flags), opts)
			require.NoError(t, err)
			require.NotNil(t, captured.Load())
			observed := captured.Load().(createRequestSnapshot)
			_, ok := result.(*v2.CreateAccountResponse_SuccessResult)
			require.True(t, ok)
			require.Equal(t, "false", observed.activate)
			require.Equal(t, int32(1), server.Requests())
			require.Contains(t, logs.String(), `"level":"warn"`)
			info := &errdetails.ErrorInfo{}
			found, err := annos.Pick(info)
			require.NoError(t, err)
			require.True(t, found)
			expected := map[string]string{}
			if mode != "generated-sdk-change" {
				expected[profileFieldPasswordChangeOnLoginRequired] = "true"
			}
			if mode != "generated" {
				expected["force_change_at_next_login"] = "true"
			}
			require.Equal(t, expected, info.Metadata)
			if mode != "no-password" {
				require.Len(t, observed.body.Credentials.Password.Value, 32)
			} else {
				require.Nil(t, observed.body.Credentials)
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

func TestStrictNoPasswordChangeRejectsBeforeProvider(t *testing.T) {
	for _, source := range []string{"profile", "credential"} {
		t.Run(source, func(t *testing.T) {
			server := newTestServerClient(t, http.NewServeMux())
			opts := v2.LocalCredentialOptions_builder{NoPassword: &v2.LocalCredentialOptions_NoPassword{}}.Build()
			flags := map[string]any{}
			if source == "profile" {
				flags["password_change_on_login_required"] = true
			} else {
				opts.SetForceChangeAtNextLogin(true)
			}
			_, _, _, err := userBuilder(&Okta{client: server.client, strictAccountCreation: true}).CreateAccount(
				t.Context(), bootstrapAccountInfo(t, flags), opts)
			require.Error(t, err)
			require.Zero(t, server.Requests())
		})
	}
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

func TestAccountActivationInProgressRetainsFreshResourceAndPassword(t *testing.T) {
	for _, tc := range []struct {
		name, status, transition string
	}{
		{name: "still staged", status: userStatusStaged},
		{name: "transition pending", status: userStatusActive, transition: userStatusActive},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var captured atomic.Value
			mux := http.NewServeMux()
			mux.HandleFunc("POST /api/v1/users", func(w http.ResponseWriter, r *http.Request) {
				var created okta.CreateUserRequest
				if err := json.NewDecoder(r.Body).Decode(&created); err != nil {
					t.Errorf("decoding request body: %v", err)
					http.Error(w, "invalid request body", http.StatusBadRequest)
					return
				}
				captured.Store(createRequestSnapshot{body: created})
				writeOktaTestResponse(w, http.StatusOK, oktaUserResponse(userStatusStaged))
			})
			mux.HandleFunc("POST /api/v1/users/"+testOktaUserID+"/lifecycle/activate", func(w http.ResponseWriter, _ *http.Request) {
				writeOktaTestResponse(w, http.StatusOK, `{}`)
			})
			mux.HandleFunc("GET /api/v1/users/"+testOktaUserID, func(w http.ResponseWriter, _ *http.Request) {
				writeOktaTestResponse(w, http.StatusOK, oktaUserFullJSON(tc.status, tc.transition))
			})
			server := newTestServerClient(t, mux)
			result, plaintext, _, err := userBuilder(&Okta{client: server.client}).CreateAccount(t.Context(),
				bootstrapAccountInfo(t, map[string]any{"send_activation_email": false}), randomPasswordCreds(32))
			require.NoError(t, err)
			require.NotNil(t, captured.Load())
			observed := captured.Load().(createRequestSnapshot)
			pending, ok := result.(*v2.CreateAccountResponse_InProgressResult)
			require.True(t, ok, "acknowledged activation is not necessarily complete")
			require.True(t, pending.IsCreateAccountResult)
			require.Equal(t, testOktaUserID, pending.GetResource().GetId().GetResource())
			require.Equal(t, tc.status, pending.GetResource().GetStatus().GetDetails())
			require.Equal(t, tc.transition, pending.GetResource().GetProfile().GetFields()["c1_okta_transitioning_to_status"].GetStringValue())
			require.Len(t, plaintext, 1)
			require.Equal(t, observed.body.Credentials.Password.Value, string(plaintext[0].Bytes), "pending activation must retain the actual generated bootstrap")
			require.Equal(t, int32(3), server.Requests(), "create, activate, then fresh read; never expire or reset")
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
