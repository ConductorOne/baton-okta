package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func bootstrapAccountInfo(t *testing.T, flags map[string]any) *v2.AccountInfo {
	t.Helper()
	profile := map[string]any{
		"first_name": "Jamie",
		"last_name":  "Fern",
		"email":      "jfern@example.com",
		"login":      "jfern@example.com",
	}
	for k, v := range flags {
		profile[k] = v
	}
	s, err := structpb.NewStruct(profile)
	require.NoError(t, err)
	return &v2.AccountInfo{Profile: s}
}

func suppliedPasswordCreds(password string) *v2.LocalCredentialOptions {
	return v2.LocalCredentialOptions_builder{
		PlaintextPassword: &v2.LocalCredentialOptions_PlaintextPassword{
			PlaintextPassword: password,
		},
	}.Build()
}

func randomPasswordCreds(length int64) *v2.LocalCredentialOptions {
	return v2.LocalCredentialOptions_builder{
		RandomPassword: &v2.LocalCredentialOptions_RandomPassword{Length: length},
	}.Build()
}

// newTestServerClient wires an Okta SDK client to a local httptest server
// behind the given mux, counting every provider request. It is the counting
// counterpart of newScriptedOktaClient for fixtures that must assert exact
// request counts rather than an exact scripted sequence. The returned handle's
// Requests() must be read at assertion time (the count is captured live).
type oktaTestServer struct {
	client   *okta.Client
	requests *atomic.Int32
}

func (s *oktaTestServer) Requests() int32 {
	return s.requests.Load()
}

func newTestServerClient(t *testing.T, mux *http.ServeMux) *oktaTestServer {
	t.Helper()

	requests := &atomic.Int32{}
	countingMux := http.NewServeMux()
	countingMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		mux.ServeHTTP(w, r)
	})

	server := httptest.NewServer(countingMux)
	t.Cleanup(server.Close)

	_, client, err := okta.NewClient(
		context.Background(),
		okta.WithOrgUrl(server.URL),
		okta.WithToken("test-token"),
		okta.WithHttpClientPtr(server.Client()),
		okta.WithTestingDisableHttpsCheck(true),
		okta.WithRateLimitMaxRetries(0),
	)
	require.NoError(t, err)

	return &oktaTestServer{client: client, requests: requests}
}

func TestAccountCreationQueryParams_Guard(t *testing.T) {
	t.Parallel()

	inactive := map[string]any{"create_inactive": true}
	inactiveChange := map[string]any{"create_inactive": true, "password_change_on_login_required": true}
	noEmailChange := map[string]any{"send_activation_email": false, "password_change_on_login_required": true}

	t.Run("inactive + mandatory change rejected before write for supplied password", func(t *testing.T) {
		t.Parallel()
		params, followUp, _, err := getAccountCreationQueryParams(t.Context(), bootstrapAccountInfo(t, inactiveChange), suppliedPasswordCreds("pw-32-chars-long-enough"), "", true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "create_inactive")
		require.Nil(t, params)
		require.False(t, followUp)
	})

	t.Run("inactive + mandatory change rejected before write for generated password", func(t *testing.T) {
		t.Parallel()
		params, followUp, _, err := getAccountCreationQueryParams(t.Context(), bootstrapAccountInfo(t, inactiveChange), randomPasswordCreds(32), "", true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "create_inactive")
		require.Nil(t, params)
		require.False(t, followUp)
	})

	t.Run("inactive + SDK force_change_at_next_login rejected before write", func(t *testing.T) {
		t.Parallel()
		creds := v2.LocalCredentialOptions_builder{
			PlaintextPassword:      &v2.LocalCredentialOptions_PlaintextPassword{PlaintextPassword: "pw"},
			ForceChangeAtNextLogin: true,
		}.Build()
		_, _, _, err := getAccountCreationQueryParams(t.Context(), bootstrapAccountInfo(t, inactive), creds, "", true)
		require.Error(t, err)
	})

	t.Run("staged email suppression + mandatory change rejected before write", func(t *testing.T) {
		t.Parallel()
		_, _, _, err := getAccountCreationQueryParams(t.Context(), bootstrapAccountInfo(t, noEmailChange), suppliedPasswordCreds("pw-32-chars-long-enough"), "", true)
		require.Error(t, err)
		_, _, _, err = getAccountCreationQueryParams(t.Context(), bootstrapAccountInfo(t, noEmailChange), randomPasswordCreds(32), "", true)
		require.Error(t, err)
	})

	t.Run("SDK force-change on no-password path is rejected", func(t *testing.T) {
		t.Parallel()
		creds := v2.LocalCredentialOptions_builder{
			NoPassword:             &v2.LocalCredentialOptions_NoPassword{},
			ForceChangeAtNextLogin: true,
		}.Build()
		_, _, _, err := getAccountCreationQueryParams(t.Context(), bootstrapAccountInfo(t, nil), creds, "", true)
		require.Error(t, err)
	})

	t.Run("inactive create with supplied password and no change request is allowed and stays staged", func(t *testing.T) {
		t.Parallel()
		params, followUp, _, err := getAccountCreationQueryParams(t.Context(), bootstrapAccountInfo(t, inactive), suppliedPasswordCreds("pw-32-chars-long-enough"), "", true)
		require.NoError(t, err)
		require.NotNil(t, params)
		require.NotNil(t, params.Activate)
		require.False(t, *params.Activate)
		require.Empty(t, params.NextLogin)
		require.False(t, followUp)
	})

	t.Run("legacy inert profile flag on no-password inactive create remains allowed", func(t *testing.T) {
		t.Parallel()
		creds := v2.LocalCredentialOptions_builder{
			NoPassword: &v2.LocalCredentialOptions_NoPassword{},
		}.Build()
		params, followUp, _, err := getAccountCreationQueryParams(t.Context(), bootstrapAccountInfo(t, inactiveChange), creds, "", false)
		require.NoError(t, err)
		require.NotNil(t, params.Activate)
		require.False(t, *params.Activate)
		require.False(t, followUp)
	})

	t.Run("activating create with mandatory change on supplied password sets nextLogin", func(t *testing.T) {
		t.Parallel()
		params, followUp, _, err := getAccountCreationQueryParams(
			t.Context(),
			bootstrapAccountInfo(t, map[string]any{"password_change_on_login_required": true}),
			suppliedPasswordCreds("pw"),
			"",
			true,
		)
		require.NoError(t, err)
		require.Equal(t, "changePassword", params.NextLogin)
		require.NotNil(t, params.Activate)
		require.True(t, *params.Activate)
		require.False(t, followUp)
	})

	t.Run("SDK force-change on activating create sets nextLogin", func(t *testing.T) {
		t.Parallel()
		creds := v2.LocalCredentialOptions_builder{
			PlaintextPassword:      &v2.LocalCredentialOptions_PlaintextPassword{PlaintextPassword: "pw"},
			ForceChangeAtNextLogin: true,
		}.Build()
		params, _, _, err := getAccountCreationQueryParams(t.Context(), bootstrapAccountInfo(t, nil), creds, "", true)
		require.NoError(t, err)
		require.Equal(t, "changePassword", params.NextLogin)
		require.True(t, *params.Activate)
	})
}

// The zero-write guarantee for the guarded combination, end to end: a client
// that records every request proves CreateAccount performs NO provider write
// (no create, no activate, no expire) for either password mode.
func TestCreateAccount_GuardMakesZeroProviderWrites(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"supplied", "generated"} {
		for _, source := range []string{"profile", "credential"} {
			t.Run(mode+"/"+source, func(t *testing.T) {
				t.Parallel()
				mux := http.NewServeMux()
				mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
					writeOktaTestResponse(w, http.StatusInternalServerError, `{"errorCode":"E0000001","errorSummary":"unexpected"}`)
				})
				server := newTestServerClient(t, mux)
				creds := suppliedPasswordCreds("fixture-only-supplied-password")
				if mode == "generated" {
					creds = randomPasswordCreds(32)
				}
				flags := map[string]any{"create_inactive": true}
				if source == "profile" {
					flags["password_change_on_login_required"] = true
				} else {
					creds.SetForceChangeAtNextLogin(true)
				}
				resp, plaintexts, _, err := userBuilder(&Okta{client: server.client, strictAccountCreation: mode == "generated"}).CreateAccount(
					t.Context(), bootstrapAccountInfo(t, flags), creds)
				require.Error(t, err)
				require.Nil(t, resp)
				require.Nil(t, plaintexts)
				require.Zero(t, server.Requests(), "rejection must precede create, activate, expire, and all other provider calls")
			})
		}
	}
}

func TestCreateAccount_SuppliedInactiveInsert(t *testing.T) {
	t.Parallel()

	const supplied = "bootstrap-supplied-password-32-chars!"

	var createBody okta.CreateUserRequest
	var createQueryActivate string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&createBody))
		createQueryActivate = r.URL.Query().Get("activate")
		// Staged response: no credentials echoed, id present.
		writeOktaTestResponse(
			w,
			http.StatusOK,
			fmt.Sprintf(`{"id":%q,"status":%q,"profile":{"login":"jfern@example.com","firstName":"Jamie","lastName":"Fern","email":"jfern@example.com"}}`, testOktaUserID, userStatusStaged),
		)
	})

	server := newTestServerClient(t, mux)
	builder := userBuilder(&Okta{client: server.client})

	resp, plaintexts, _, err := builder.CreateAccount(t.Context(), bootstrapAccountInfo(t, map[string]any{
		"create_inactive": true,
	}), suppliedPasswordCreds(supplied))
	require.NoError(t, err)

	success, ok := resp.(*v2.CreateAccountResponse_SuccessResult)
	require.True(t, ok, "expected SuccessResult, got %T", resp)
	require.NotNil(t, success.Resource)
	require.Equal(t, testOktaUserID, success.Resource.Id.Resource)

	// Exactly one provider write: the staged insert. No activation, no email.
	require.Equal(t, int32(1), server.Requests())
	require.Equal(t, "false", createQueryActivate, "inactive create must send activate=false")
	require.Equal(t, supplied, createBody.Credentials.Password.Value, "supplied password must reach the write unchanged")
	require.Nil(t, plaintexts, "supplied mode must not return credential material")
}

func TestCreateAccount_RandomLengthAndResultMaterial(t *testing.T) {
	t.Parallel()

	var createBody okta.CreateUserRequest
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&createBody))
		writeOktaTestResponse(
			w,
			http.StatusOK,
			fmt.Sprintf(`{"id":%q,"status":%q,"profile":{"login":"jfern@example.com","firstName":"Jamie","lastName":"Fern","email":"jfern@example.com"}}`, testOktaUserID, userStatusActive),
		)
	})

	server := newTestServerClient(t, mux)
	builder := userBuilder(&Okta{client: server.client})

	resp, plaintexts, _, err := builder.CreateAccount(t.Context(), bootstrapAccountInfo(t, nil), randomPasswordCreds(32))
	require.NoError(t, err)
	_, ok := resp.(*v2.CreateAccountResponse_SuccessResult)
	require.True(t, ok, "expected SuccessResult, got %T", resp)

	require.Len(t, plaintexts, 1)
	require.Equal(t, "password", plaintexts[0].Name)
	require.Len(t, plaintexts[0].Bytes, 32, "requested 32-char random password must not be capped")
	require.Equal(t, createBody.Credentials.Password.Value, string(plaintexts[0].Bytes), "return the password actually assigned, not a fresh generation")
}

func TestCreateAccount_UnresolvedDuplicateIsActionRequired(t *testing.T) {
	t.Parallel()

	const dupLoginBody = `{"errorCode":"E0000001","errorSummary":"Api validation failed","errorCauses":[{"errorSummary":"login: already exists"}]}`

	t.Run("login lookup fails", func(t *testing.T) {
		t.Parallel()
		mux := http.NewServeMux()
		mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
			writeOktaTestResponse(w, http.StatusBadRequest, dupLoginBody)
		})
		mux.HandleFunc("/api/v1/users/jfern@example.com", func(w http.ResponseWriter, r *http.Request) {
			writeOktaTestResponse(w, http.StatusInternalServerError, "")
		})

		server := newTestServerClient(t, mux)
		resp, plaintexts, _, err := userBuilder(&Okta{client: server.client}).CreateAccount(t.Context(), bootstrapAccountInfo(t, nil), suppliedPasswordCreds("pw"))
		require.NoError(t, err)

		ar, ok := resp.(*v2.CreateAccountResponse_ActionRequiredResult)
		require.True(t, ok, "expected ActionRequiredResult, got %T", resp)
		require.Nil(t, ar.Resource, "unresolved duplicate has no usable identity")
		require.Contains(t, ar.Message, "jfern@example.com")
		require.Nil(t, plaintexts)
	})

	t.Run("empty supplied login cannot be looked up", func(t *testing.T) {
		t.Parallel()
		mux := http.NewServeMux()
		mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
			writeOktaTestResponse(w, http.StatusBadRequest, dupLoginBody)
		})

		server := newTestServerClient(t, mux)
		profile := map[string]any{
			"first_name": "Jamie",
			"last_name":  "Fern",
			"email":      "jfern@example.com",
			"login":      "",
		}
		s, err := structpb.NewStruct(profile)
		require.NoError(t, err)

		resp, _, _, err := userBuilder(&Okta{client: server.client}).CreateAccount(t.Context(), &v2.AccountInfo{Profile: s}, suppliedPasswordCreds("pw"))
		require.NoError(t, err)
		ar, ok := resp.(*v2.CreateAccountResponse_ActionRequiredResult)
		require.True(t, ok, "expected ActionRequiredResult, got %T", resp)
		require.Nil(t, ar.GetResource(), "unresolved login must not produce an adopted resource")
	})
}

func TestCreateAccount_ActivationFailureRetainsIdentityAndMaterial(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		writeOktaTestResponse(
			w,
			http.StatusOK,
			fmt.Sprintf(`{"id":%q,"status":%q,"profile":{"login":"jfern@example.com","firstName":"Jamie","lastName":"Fern","email":"jfern@example.com"}}`, testOktaUserID, userStatusStaged),
		)
	})
	mux.HandleFunc("/api/v1/users/"+testOktaUserID+"/lifecycle/activate", func(w http.ResponseWriter, r *http.Request) {
		writeOktaTestResponse(w, http.StatusForbidden, `{"errorCode":"E0000001","errorSummary":"Api validation failed"}`)
	})

	server := newTestServerClient(t, mux)
	builder := userBuilder(&Okta{client: server.client})

	resp, plaintexts, _, err := builder.CreateAccount(t.Context(), bootstrapAccountInfo(t, map[string]any{
		"send_activation_email": false,
	}), randomPasswordCreds(32))
	require.NoError(t, err, "activation failure must surface as ActionRequired, not an error that discards the created account")

	ar, ok := resp.(*v2.CreateAccountResponse_ActionRequiredResult)
	require.True(t, ok, "expected ActionRequiredResult, got %T", resp)
	require.NotNil(t, ar.Resource, "created identity must be retained for reconciliation")
	require.Equal(t, testOktaUserID, ar.Resource.Id.Resource)
	require.Contains(t, ar.Message, testOktaUserID)
	require.Len(t, plaintexts, 1, "generated material must be retained with the ActionRequired result")
	require.Len(t, plaintexts[0].Bytes, 32)
}
