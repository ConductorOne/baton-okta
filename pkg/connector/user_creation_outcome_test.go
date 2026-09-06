package connector

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/crypto/providers/jwk"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCreateAccountReadbackKeepsCreatedIdentity(t *testing.T) {
	for _, response := range []string{`null`, `{"id":"different-user","status":"ACTIVE","profile":{"login":"other@example.com"}}`} {
		t.Run(response, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, _ *http.Request) {
				writeOktaTestResponse(w, http.StatusOK, fmt.Sprintf(
					`{"id":%q,"status":"STAGED","profile":{"login":"jfern@example.com"}}`, testOktaUserID))
			})
			mux.HandleFunc("/api/v1/users/"+testOktaUserID+"/lifecycle/activate", func(w http.ResponseWriter, _ *http.Request) {
				writeOktaTestResponse(w, http.StatusOK, `{}`)
			})
			mux.HandleFunc("/api/v1/users/"+testOktaUserID, func(w http.ResponseWriter, _ *http.Request) {
				writeOktaTestResponse(w, http.StatusOK, response)
			})
			server := newTestServerClient(t, mux)
			result, credentials, _, err := userBuilder(&Okta{client: server.client}).CreateAccount(t.Context(),
				bootstrapAccountInfo(t, map[string]any{"send_activation_email": false}), randomPasswordCreds(32))
			require.NoError(t, err)
			partial, ok := result.(*v2.CreateAccountResponse_ActionRequiredResult)
			require.True(t, ok)
			require.Equal(t, testOktaUserID, partial.GetResource().GetId().GetResource())
			require.Len(t, credentials, 1)
		})
	}
}

func TestCreateAccountUnknownActivationDoesNotReplay(t *testing.T) {
	var writes atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, _ *http.Request) {
		writes.Add(1)
		writeOktaTestResponse(w, http.StatusOK, fmt.Sprintf(
			`{"id":%q,"status":"STAGED","profile":{"login":"jfern@example.com"}}`, testOktaUserID))
	})
	mux.HandleFunc("/api/v1/users/"+testOktaUserID+"/lifecycle/activate", func(w http.ResponseWriter, _ *http.Request) {
		writes.Add(1)
		// The provider could have activated the account before its response was lost.
		writeOktaTestResponse(w, http.StatusServiceUnavailable, `{"errorCode":"E0000009","errorSummary":"response unavailable"}`)
	})
	mux.HandleFunc("/api/v1/users/"+testOktaUserID, func(w http.ResponseWriter, _ *http.Request) {
		writeOktaTestResponse(w, http.StatusForbidden, `{"errorCode":"E0000006","errorSummary":"verification denied"}`)
	})
	server := newTestServerClient(t, mux)
	result, credentials, _, err := userBuilder(&Okta{client: server.client}).CreateAccount(t.Context(),
		bootstrapAccountInfo(t, map[string]any{"send_activation_email": false}), randomPasswordCreds(32))
	require.NoError(t, err)
	partial, ok := result.(*v2.CreateAccountResponse_ActionRequiredResult)
	require.True(t, ok)
	require.Equal(t, testOktaUserID, partial.GetResource().GetId().GetResource())
	require.Equal(t, int32(2), writes.Load(), "do not replay an unknown create or activation")
	require.Len(t, credentials, 1)
}

func TestCreateAccountDuplicateLookupCannotAdoptAnotherLogin(t *testing.T) {
	client := newScriptedOktaClient(t,
		oktaRequestStep{
			method: http.MethodPost, path: "/api/v1/users", statusCode: http.StatusBadRequest,
			body: `{"errorCode":"E0000001","errorSummary":"Api validation failed","errorCauses":[{"errorSummary":"login: already exists"}]}`,
		},
		oktaRequestStep{
			method: http.MethodGet, path: "/api/v1/users/jfern@example.com", statusCode: http.StatusOK,
			body: `{"id":"unrelated-user","status":"ACTIVE","profile":{"login":"different@example.com"}}`,
		},
	)
	result, credentials, _, err := userBuilder(&Okta{client: client}).CreateAccount(t.Context(), bootstrapAccountInfo(t, nil), suppliedPasswordCreds("fixture-only"))
	require.NoError(t, err)
	partial, ok := result.(*v2.CreateAccountResponse_ActionRequiredResult)
	require.True(t, ok)
	require.Nil(t, partial.GetResource(), "an unrelated lookup result is not an adopted account")
	require.Empty(t, credentials)
}

func TestCreateAccountInvalidCredentialsDoNotWrite(t *testing.T) {
	for _, test := range []struct {
		name    string
		options *v2.LocalCredentialOptions
		profile map[string]any
	}{
		{"empty supplied", suppliedPasswordCreds(""), nil},
		{"unsupported options", &v2.LocalCredentialOptions{}, nil},
		{"short generated", randomPasswordCreds(4), nil},
		{"federated supplied", suppliedPasswordCreds("fixture-only"), map[string]any{"provider_type": "FEDERATION"}},
		{"federated generated", randomPasswordCreds(32), map[string]any{"provider_type": "FEDERATION"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := newTestServerClient(t, http.NewServeMux())
			_, _, _, err := userBuilder(&Okta{client: server.client}).CreateAccount(t.Context(), bootstrapAccountInfo(t, test.profile), test.options)
			require.Error(t, err)
			require.Equal(t, codes.InvalidArgument, status.Code(err))
			require.Zero(t, server.Requests())
		})
	}
}

func TestSDKCreateAccountPasswordConstraints(t *testing.T) {
	encryptionProvider := &jwk.JWKEncryptionProvider{}
	recipient, privateKey, err := encryptionProvider.GenerateKey(t.Context())
	require.NoError(t, err)
	for _, test := range []struct {
		name        string
		constraints []*v2.PasswordConstraint
		invalid     bool
	}{
		{"positive empty charset", []*v2.PasswordConstraint{{MinCount: 1}}, true},
		{"minimums exceed length", []*v2.PasswordConstraint{{MinCount: 5, CharSet: "A"}, {MinCount: 4, CharSet: "1"}}, true},
		{"exact length boundary", []*v2.PasswordConstraint{{MinCount: 4, CharSet: "A"}, {MinCount: 4, CharSet: "1"}}, false},
		{"zero count empty charset", []*v2.PasswordConstraint{{}}, false},
		{"default constraints", nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var createdPassword string
			mux := http.NewServeMux()
			mux.HandleFunc("POST /api/v1/users", func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					Credentials struct {
						Password struct {
							Value string `json:"value"`
						} `json:"password"`
					} `json:"credentials"`
				}
				require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
				createdPassword = body.Credentials.Password.Value
				writeOktaTestResponse(w, http.StatusOK, oktaUserResponse(userStatusStaged))
			})
			provider := newTestServerClient(t, mux)
			user := userBuilder(&Okta{client: provider.client, strictAccountCreation: true})
			accountManager, err := connectorbuilder.NewConnector(t.Context(), &filteredReadTestConnector{user: user})
			require.NoError(t, err)
			result, err := accountManager.CreateAccount(t.Context(), &v2.CreateAccountRequest{
				AccountInfo: bootstrapAccountInfo(t, map[string]any{"create_inactive": true}),
				CredentialOptions: v2.CredentialOptions_builder{
					RandomPassword: &v2.CredentialOptions_RandomPassword{Length: 8, Constraints: test.constraints},
				}.Build(),
				EncryptionConfigs: []*v2.EncryptionConfig{recipient},
				ResourceTypeId:    resourceTypeUser.Id,
			})
			if test.invalid {
				require.Equal(t, codes.InvalidArgument, status.Code(err))
				require.Nil(t, result)
				require.Zero(t, provider.Requests())
				return
			}
			require.NoError(t, err)
			require.NotNil(t, result.GetSuccess())
			require.Equal(t, testOktaUserID, result.GetSuccess().GetResource().GetId().GetResource())
			require.Equal(t, int32(1), provider.Requests())
			require.Len(t, createdPassword, 8)
			if test.name == "exact length boundary" {
				require.Equal(t, 4, strings.Count(createdPassword, "A"))
				require.Equal(t, 4, strings.Count(createdPassword, "1"))
			}
			require.Len(t, result.GetEncryptedData(), 1)
			recovered, err := encryptionProvider.Decrypt(t.Context(), result.GetEncryptedData()[0], privateKey)
			require.NoError(t, err)
			require.Equal(t, createdPassword, string(recovered.GetBytes()), "caller must recover the generated provider password through SDK encryption")
		})
	}
}
