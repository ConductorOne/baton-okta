package connector

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCustomProfileCannotForgeRawStatus(t *testing.T) {
	user := &okta.User{
		Id: testOktaUserID, Status: userStatusActive,
		Profile: &okta.UserProfile{
			"login":                   "test@example.com",
			"c1_okta_raw_user_status": "DEPROVISIONED",
		},
	}
	ordinary, err := userResource(user, false)
	require.NoError(t, err)
	require.Equal(t, userStatusActive, ordinary.GetProfile().GetFields()["c1_okta_raw_user_status"].GetStringValue())
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
