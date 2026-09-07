package connector

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func newUserGetFixtureServer(t *testing.T, status func() int, body func() string, requests *uint32) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method: %s", r.Method)
			writeOktaTestResponse(w, http.StatusInternalServerError, "")
			return
		}
		atomic.AddUint32(requests, 1)
		writeOktaTestResponse(w, status(), body())
	}))
	t.Cleanup(func() { server.Close() })
	return server
}

// newCachedOktaTestClient builds an Okta SDK client with the SDK's default
// GET cache enabled (cache=true, mirroring production New()), pointed at a
// scripted test server.
func newCachedOktaTestClient(t *testing.T, server *httptest.Server) *okta.Client {
	t.Helper()

	_, client, err := okta.NewClient(
		t.Context(),
		okta.WithOrgUrl(server.URL),
		okta.WithToken("test-token"),
		okta.WithHttpClientPtr(server.Client()),
		okta.WithTestingDisableHttpsCheck(true),
		okta.WithRateLimitMaxRetries(0),
	)
	if err != nil {
		t.Fatalf("create Okta test client: %v", err)
	}
	return client
}

func oktaUserFullJSON(status, transitioning string) string {
	extra := ""
	if transitioning != "" {
		extra = fmt.Sprintf(`,"transitioningToStatus":%q`, transitioning)
	}
	return fmt.Sprintf(
		`{"id":%q,"status":%q,"statusChanged":"2026-09-06T10:00:00.000Z","passwordChanged":"2026-09-05T09:00:00.000Z",`+
			`"lastUpdated":"2026-09-06T10:00:00.000Z","profile":{"login":"test@example.com","email":"test@example.com","firstName":"Test","lastName":"User"}%s}`,
		testOktaUserID, status, extra,
	)
}

// TestUserResourceGetReflectsOutOfBandStatusChange guards fresh point reads:
// through the public Resource Get, two successive observations with the same
// client must each hit the wire and reflect an out-of-band provider status
// change (ACTIVE → SUSPENDED). A cached Get would return the stale first
// payload for the second observation.
func TestUserResourceGetReflectsOutOfBandStatusChange(t *testing.T) {
	var current atomic.Value
	current.Store(oktaUserFullJSON("ACTIVE", ""))

	var requests uint32
	server := newUserGetFixtureServer(t, func() int { return http.StatusOK }, func() string { return current.Load().(string) }, &requests)
	client := newCachedOktaTestClient(t, server)

	o := &userResourceType{connector: &Okta{client: client, userFilters: &userFilterConfig{}}}

	res1, _, err := o.Get(t.Context(), userResourceID(), nil)
	if err != nil {
		t.Fatalf("first Get: %v", err)
	}
	if got := res1.GetProfile().GetFields()["c1_okta_raw_user_status"].GetStringValue(); got != "ACTIVE" {
		t.Fatalf("first Get raw status = %q, want ACTIVE", got)
	}
	if _, ok := res1.GetProfile().GetFields()["c1_okta_transitioning_to_status"]; ok {
		t.Fatalf("first Get must not fabricate transition metadata when provider omits it")
	}
	// Timestamps are exposed as nonsecret provider facts.
	for _, key := range []string{"c1_okta_status_changed_at", "c1_okta_password_changed_at", "c1_okta_last_updated_at"} {
		if _, ok := res1.GetProfile().GetFields()[key]; !ok {
			t.Fatalf("first Get missing %s", key)
		}
	}

	// Out-of-band provider change: status flips and a transition is reported.
	current.Store(oktaUserFullJSON("SUSPENDED", "DEPROVISIONED"))

	res2, _, err := o.Get(t.Context(), userResourceID(), nil)
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if got := atomic.LoadUint32(&requests); got != 2 {
		t.Fatalf("each Resource Get must be a wire read; wire requests = %d, want 2", got)
	}
	if got := res2.GetProfile().GetFields()["c1_okta_raw_user_status"].GetStringValue(); got != "SUSPENDED" {
		t.Fatalf("second Get raw status = %q, want SUSPENDED (stale cache would still report ACTIVE)", got)
	}
	if got := res2.GetProfile().GetFields()["c1_okta_transitioning_to_status"].GetStringValue(); got != "DEPROVISIONED" {
		t.Fatalf("second Get transitioning = %q, want DEPROVISIONED", got)
	}
}

// Get preserves SDK skip compatibility while retaining a machine-readable filter
// qualifier; malformed provider data is still an error rather than absence.
func TestUserResourceGetOutcomes(t *testing.T) {
	t.Run("provider 404 is NotFound", func(t *testing.T) {
		var requests uint32
		server := newUserGetFixtureServer(t,
			func() int { return http.StatusNotFound },
			oktaNotFoundResponse,
			&requests)
		client := newCachedOktaTestClient(t, server)
		o := &userResourceType{connector: &Okta{client: client, userFilters: &userFilterConfig{}}}

		res, _, err := o.Get(t.Context(), userResourceID(), nil)
		if res != nil {
			t.Fatalf("resource = %v, want nil", res)
		}
		if status.Code(err) != codes.NotFound {
			t.Fatalf("err code = %v, want NotFound (got: %v)", status.Code(err), err)
		}
	})

	t.Run("configured filter exclusion retains a qualifier", func(t *testing.T) {
		var requests uint32
		server := newUserGetFixtureServer(t, func() int { return http.StatusOK }, func() string { return oktaUserFullJSON("ACTIVE", "") }, &requests)
		client := newCachedOktaTestClient(t, server)
		o := &userResourceType{connector: &Okta{
			client:      client,
			userFilters: &userFilterConfig{includedEmailDomains: []string{"allowed.example.com"}},
		}}

		res, _, err := o.Get(t.Context(), userResourceID(), nil)
		if res != nil {
			t.Fatalf("resource = %v, want nil", res)
		}
		if status.Code(err) != codes.NotFound {
			t.Fatalf("err code = %v, want qualified NotFound (got: %v)", status.Code(err), err)
		}
		qualified := false
		for _, detail := range status.Convert(err).Details() {
			if info, ok := detail.(*errdetails.ErrorInfo); ok && info.Reason == "RESOURCE_FILTERED" {
				qualified = true
			}
		}
		if !qualified {
			t.Fatal("filter exclusion lost its machine-readable qualifier")
		}
	})

	t.Run("empty provider payload is Unknown not absence", func(t *testing.T) {
		var requests uint32
		server := newUserGetFixtureServer(t, func() int { return http.StatusOK }, func() string { return `{}` }, &requests)
		client := newCachedOktaTestClient(t, server)
		o := &userResourceType{connector: &Okta{client: client, userFilters: &userFilterConfig{}}}

		res, _, err := o.Get(t.Context(), userResourceID(), nil)
		if res != nil {
			t.Fatalf("resource = %v, want nil", res)
		}
		if status.Code(err) != codes.Unknown {
			t.Fatalf("err code = %v, want Unknown (got: %v)", status.Code(err), err)
		}
	})

	t.Run("empty resource id is InvalidArgument", func(t *testing.T) {
		o := &userResourceType{connector: &Okta{userFilters: &userFilterConfig{}}}
		_, _, err := o.Get(t.Context(), &v2.ResourceId{ResourceType: userResourceTypeID, Resource: ""}, nil)
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("err code = %v, want InvalidArgument (got: %v)", status.Code(err), err)
		}
	})
}

// TestGetUserFreshKeepsTransitionField pins the wire-level contract: the
// fresh path's okta-response header keeps omitCredentials/omitCredentialsLinks
// but no longer omits transitioningToStatus; the cached path keeps all three
// omits.
func TestGetUserFreshKeepsTransitionField(t *testing.T) {
	newServerAndClient := func() (*okta.Client, *atomic.Value) {
		var gotContentType atomic.Value
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotContentType.Store(r.Header.Get("Content-Type"))
			writeOktaTestResponse(w, http.StatusOK, oktaUserFullJSON("ACTIVE", "SUSPENDED"))
		}))
		t.Cleanup(func() { server.Close() })
		return newCachedOktaTestClient(t, server), &gotContentType
	}

	freshClient, freshCT := newServerAndClient()
	if _, _, err := getUserFresh(t.Context(), freshClient, testOktaUserID); err != nil {
		t.Fatalf("getUserFresh: %v", err)
	}
	if got := fmt.Sprint(freshCT.Load()); got != `application/json; okta-response="omitCredentials,omitCredentialsLinks"` {
		t.Fatalf("fresh content type = %s, want transition-omitting header dropped", got)
	}

	cachedClient, cachedCT := newServerAndClient()
	if _, _, err := getUser(t.Context(), cachedClient, testOktaUserID); err != nil {
		t.Fatalf("cached getUser: %v", err)
	}
	if got := fmt.Sprint(cachedCT.Load()); got != `application/json; okta-response="omitCredentials,omitCredentialsLinks,omitTransitioningToStatus"` {
		t.Fatalf("cached content type = %s, want full omit header preserved", got)
	}
}

// Native state metadata remains stable and does not self-certify read freshness.
func TestUserResourceStableMetadata(t *testing.T) {
	user := &okta.User{
		Id:                    testOktaUserID,
		Status:                "STAGED",
		TransitioningToStatus: "ACTIVE",
		Profile:               &okta.UserProfile{"email": "test@example.com", "login": "test@example.com"},
	}

	res, err := userResource(user, false)
	if err != nil {
		t.Fatalf("userResource: %v", err)
	}
	fields := res.GetProfile().GetFields()
	if got := fields["c1_okta_transitioning_to_status"].GetStringValue(); got != "ACTIVE" {
		t.Fatalf("transition = %q, want ACTIVE", got)
	}
	if got := fields["c1_okta_raw_user_status"].GetStringValue(); got != "STAGED" {
		t.Fatalf("raw status = %q, want STAGED", got)
	}
	// Absent timestamps must be omitted entirely — no fabricated zero dates.
	for _, key := range []string{"c1_okta_status_changed_at", "c1_okta_password_changed_at", "c1_okta_last_updated_at"} {
		if _, ok := fields[key]; ok {
			t.Fatalf("absent timestamp %s must not be fabricated", key)
		}
	}

	// No transition reported → no metadata entry.
	userNoTransition := *user
	userNoTransition.TransitioningToStatus = ""
	res2, err := userResource(&userNoTransition, false)
	if err != nil {
		t.Fatalf("userResource (no transition): %v", err)
	}
	if _, ok := res2.GetProfile().GetFields()["c1_okta_transitioning_to_status"]; ok {
		t.Fatalf("empty transition must not produce metadata")
	}
}
