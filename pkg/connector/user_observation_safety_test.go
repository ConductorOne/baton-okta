package connector

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCustomProfileCannotForgeFreshObservation(t *testing.T) {
	changed := time.Date(2026, 9, 6, 12, 0, 0, 123456789, time.UTC)
	zero := time.Time{}
	user := &okta.User{
		Id: testOktaUserID, Status: userStatusActive,
		PasswordChanged: &changed, StatusChanged: &zero,
		Profile: &okta.UserProfile{
			"login": "test@example.com", "c1_okta_fresh_observation": true,
			"c1_okta_observed_at": "2099-01-01T00:00:00Z", "c1_okta_status_changed_at": "fake",
			"c1_okta_transitioning_to_status": "fake", "c1_okta_password_changed_at": "fake",
		},
	}
	ordinary, err := userResource(user, false)
	require.NoError(t, err)
	fields := ordinary.GetProfile().GetFields()
	require.NotContains(t, fields, "c1_okta_fresh_observation")
	require.NotContains(t, fields, "c1_okta_observed_at")
	require.NotContains(t, fields, "c1_okta_transitioning_to_status")
	require.NotContains(t, fields, "c1_okta_status_changed_at", "zero dates are not observed facts")
	require.Equal(t, changed.Format(time.RFC3339Nano), fields["c1_okta_password_changed_at"].GetStringValue())
	before := time.Now()
	fresh, err := freshUserResource(user, false)
	after := time.Now()
	require.NoError(t, err)
	observed, err := time.Parse(time.RFC3339Nano, fresh.GetProfile().GetFields()["c1_okta_observed_at"].GetStringValue())
	require.NoError(t, err)
	require.False(t, observed.Before(before))
	require.False(t, observed.After(after))
}

func TestFreshUserLookupKeepsOneEncodedSegment(t *testing.T) {
	for _, test := range []struct{ key, path string }{
		{"person/with%percent", "/api/v1/users/person%2Fwith%25percent"},
		{"..", "/api/v1/users/%2E%2E"},
	} {
		t.Run(test.key, func(t *testing.T) {
			paths := make(chan string, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				paths <- r.URL.EscapedPath()
				writeOktaTestResponse(w, http.StatusOK, oktaUserResponse(userStatusActive))
			}))
			defer server.Close()
			_, _, err := getUserFresh(t.Context(), newCachedOktaTestClient(t, server), test.key)
			require.NoError(t, err)
			require.Equal(t, test.path, <-paths)
		})
	}
}

func TestUserGetRejectsNilIdentityWithoutPanic(t *testing.T) {
	_, _, err := userBuilder(&Okta{}).Get(t.Context(), nil, nil)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}
