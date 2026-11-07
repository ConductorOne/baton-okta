package okta

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type seenRequest struct {
	method string
	uri    string
	header http.Header
	body   string
}

type testServer struct {
	*httptest.Server
	mu   sync.Mutex
	seen []seenRequest
}

func newTestServer(t *testing.T, h http.HandlerFunc) *testServer {
	t.Helper()
	ts := &testServer{}
	ts.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ts.mu.Lock()
		ts.seen = append(ts.seen, seenRequest{method: r.Method, uri: r.URL.RequestURI(), header: r.Header.Clone(), body: string(b)})
		ts.mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func (ts *testServer) requests() []seenRequest {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return append([]seenRequest(nil), ts.seen...)
}

type sleepRecorder struct {
	mu    sync.Mutex
	slept []time.Duration
}

func (s *sleepRecorder) sleep(_ context.Context, d time.Duration) error {
	s.mu.Lock()
	s.slept = append(s.slept, d)
	s.mu.Unlock()
	return nil
}

func newTestClient(t *testing.T, ts *testServer, mods ...func(*Config)) (*Client, *sleepRecorder) {
	t.Helper()
	u, err := url.Parse(ts.URL)
	require.NoError(t, err)
	cfg := Config{OrgURL: u, HTTPClient: ts.Client(), APIToken: "tok"}
	for _, m := range mods {
		m(&cfg)
	}
	c, err := NewClient(cfg)
	require.NoError(t, err)
	rec := &sleepRecorder{}
	c.sleep = rec.sleep
	return c, rec
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func TestNewClientValidation(t *testing.T) {
	_, err := NewClient(Config{HTTPClient: http.DefaultClient})
	require.Error(t, err)
	_, err = NewClient(Config{OrgURL: &url.URL{Scheme: "https", Host: "x.okta.com"}})
	require.Error(t, err)
}

func TestAuthAndContentHeaders(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, `{"id":"g1"}`) })
	c, _ := newTestClient(t, ts)
	ctx := context.Background()

	_, _, err := c.GetGroup(ctx, "g1", nil)
	require.NoError(t, err)
	_, _, err = c.CreateGroup(ctx, Group{Profile: &GroupProfile{Name: "n"}})
	require.NoError(t, err)
	_, _, err = c.GetUser(ctx, "u1", WithContentType(OmitCredentialsContentType))
	require.NoError(t, err)

	reqs := ts.requests()
	require.Len(t, reqs, 3)
	require.Equal(t, "SSWS tok", reqs[0].header.Get("Authorization"))
	require.Equal(t, "application/json", reqs[0].header.Get("Accept"))
	require.Empty(t, reqs[0].header.Get("Content-Type"), "bodiless request carries no Content-Type")
	require.Equal(t, "application/json", reqs[1].header.Get("Content-Type"))
	require.JSONEq(t, `{"profile":{"name":"n","description":""}}`, reqs[1].body)
	require.Equal(t, OmitCredentialsContentType, reqs[2].header.Get("Content-Type"))
}

func TestNoAuthorizationWithoutToken(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, `{}`) })
	c, _ := newTestClient(t, ts, func(c *Config) { c.APIToken = "" })
	_, _, err := c.GetOrgSettings(context.Background())
	require.NoError(t, err)
	require.Empty(t, ts.requests()[0].header.Get("Authorization"), "the auth transport owns Authorization in OAuth mode")
}

func TestEndpointRequestShapes(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path == "/api/v1/users" || r.URL.Path == "/api/v1/groups" || r.URL.Path == "/api/v1/apps" ||
			r.URL.Path == "/api/v1/logs" || r.URL.Path == "/api/v1/devices" || r.URL.Path == "/api/v1/api-tokens" ||
			r.URL.Path == "/api/v1/users/u1/roles" || r.URL.Path == "/api/v1/groups/g1/roles" && r.Method == http.MethodGet ||
			r.URL.Path == "/api/v1/groups/g1/users" || r.URL.Path == "/api/v1/apps/a1/users" && r.Method == http.MethodGet ||
			r.URL.Path == "/api/v1/apps/a1/groups" {
			if r.Method == http.MethodGet {
				writeJSON(w, 200, `[]`)
				return
			}
		}
		writeJSON(w, 200, `{}`)
	})
	c, _ := newTestClient(t, ts, func(c *Config) { c.CacheEnabled = true })
	ctx := context.Background()
	qp := &QueryParams{Limit: 2, After: "c1", Search: "status pr", Filter: `status eq "ACTIVE"`, Expand: "stats"}

	calls := []struct {
		name string
		call func() error
		want string
	}{
		{"org", func() error { _, _, e := c.GetOrgSettings(ctx); return e }, "GET /api/v1/org"},
		{"get user", func() error { _, _, e := c.GetUser(ctx, "u1"); return e }, "GET /api/v1/users/u1"},
		{"create user", func() error {
			_, _, e := c.CreateUser(ctx, CreateUserRequest{}, &QueryParams{Activate: Bool(false), Provider: Bool(true), NextLogin: "changePassword"})
			return e
		}, "POST /api/v1/users?activate=false&nextLogin=changePassword&provider=true"},
		{"partial update", func() error { _, _, e := c.PartialUpdateUser(ctx, "u1", User{}); return e }, "POST /api/v1/users/u1"},
		{"activate", func() error { _, e := c.ActivateUser(ctx, "u1", &QueryParams{SendEmail: Bool(false)}); return e }, "POST /api/v1/users/u1/lifecycle/activate?sendEmail=false"},
		{"deactivate", func() error { _, e := c.DeactivateUser(ctx, "u1", &QueryParams{SendEmail: Bool(false)}); return e }, "POST /api/v1/users/u1/lifecycle/deactivate?sendEmail=false"},
		{"suspend", func() error { _, e := c.SuspendUser(ctx, "u1"); return e }, "POST /api/v1/users/u1/lifecycle/suspend"},
		{"unsuspend", func() error { _, e := c.UnsuspendUser(ctx, "u1"); return e }, "POST /api/v1/users/u1/lifecycle/unsuspend"},
		{"delete user", func() error { _, e := c.DeleteUser(ctx, "u1"); return e }, "DELETE /api/v1/users/u1"},
		{"user roles", func() error { _, _, e := c.ListUserRoles(ctx, "u1"); return e }, "GET /api/v1/users/u1/roles"},
		{"assign user role", func() error { _, _, e := c.AssignRoleToUser(ctx, "u1", AssignRoleRequest{Type: "ORG_ADMIN"}); return e }, "POST /api/v1/users/u1/roles"},
		{"remove user role", func() error { _, e := c.RemoveRoleFromUser(ctx, "u1", "ra1"); return e }, "DELETE /api/v1/users/u1/roles/ra1"},
		{"list groups", func() error { _, _, e := c.ListGroups(ctx, qp); return e }, "GET /api/v1/groups?after=c1&expand=stats&filter=status+eq+%22ACTIVE%22&limit=2&search=status+pr"},
		{"get group", func() error { _, _, e := c.GetGroup(ctx, "g1", &QueryParams{Expand: "stats,app"}); return e }, "GET /api/v1/groups/g1?expand=stats%2Capp"},
		{"create group", func() error { _, _, e := c.CreateGroup(ctx, Group{}); return e }, "POST /api/v1/groups"},
		{"update group", func() error { _, _, e := c.UpdateGroup(ctx, "g1", Group{}); return e }, "PUT /api/v1/groups/g1"},
		{"delete group", func() error { _, e := c.DeleteGroup(ctx, "g1"); return e }, "DELETE /api/v1/groups/g1"},
		{"group users", func() error { _, _, e := c.ListGroupUsers(ctx, "g1", &QueryParams{Limit: 5}); return e }, "GET /api/v1/groups/g1/users?limit=5"},
		{"add member", func() error { _, e := c.AddUserToGroup(ctx, "g1", "u1"); return e }, "PUT /api/v1/groups/g1/users/u1"},
		{"remove member", func() error { _, e := c.RemoveUserFromGroup(ctx, "g1", "u1"); return e }, "DELETE /api/v1/groups/g1/users/u1"},
		{"group roles", func() error { _, _, e := c.ListGroupRoles(ctx, "g1"); return e }, "GET /api/v1/groups/g1/roles"},
		{"assign group role", func() error { _, _, e := c.AssignRoleToGroup(ctx, "g1", AssignRoleRequest{}); return e }, "POST /api/v1/groups/g1/roles"},
		{"remove group role", func() error { _, e := c.RemoveRoleFromGroup(ctx, "g1", "ra1"); return e }, "DELETE /api/v1/groups/g1/roles/ra1"},
		{"list apps", func() error { _, _, e := c.ListApplications(ctx, &QueryParams{Limit: 1}); return e }, "GET /api/v1/apps?limit=1"},
		{"get app", func() error { _, _, e := c.GetApplication(ctx, "a1"); return e }, "GET /api/v1/apps/a1"},
		{"app users", func() error { _, _, e := c.ListApplicationUsers(ctx, "a1", nil); return e }, "GET /api/v1/apps/a1/users"},
		{"app user", func() error { _, _, e := c.GetApplicationUser(ctx, "a1", "u1"); return e }, "GET /api/v1/apps/a1/users/u1"},
		{"assign app user", func() error { _, _, e := c.AssignUserToApplication(ctx, "a1", AppUser{Id: "u1"}); return e }, "POST /api/v1/apps/a1/users"},
		{"delete app user", func() error { _, e := c.DeleteApplicationUser(ctx, "a1", "u1"); return e }, "DELETE /api/v1/apps/a1/users/u1"},
		{"app groups", func() error { _, _, e := c.ListApplicationGroupAssignments(ctx, "a1", nil); return e }, "GET /api/v1/apps/a1/groups"},
		{"app group", func() error { _, _, e := c.GetApplicationGroupAssignment(ctx, "a1", "g1"); return e }, "GET /api/v1/apps/a1/groups/g1"},
		{"assign app group", func() error {
			_, _, e := c.CreateApplicationGroupAssignment(ctx, "a1", "g1", ApplicationGroupAssignment{})
			return e
		}, "PUT /api/v1/apps/a1/groups/g1"},
		{"delete app group", func() error { _, e := c.DeleteApplicationGroupAssignment(ctx, "a1", "g1"); return e }, "DELETE /api/v1/apps/a1/groups/g1"},
		{"logs", func() error {
			_, _, e := c.ListLogEvents(ctx, &QueryParams{Since: "2024-01-01T00:00:00Z", SortOrder: "ASCENDING"})
			return e
		}, "GET /api/v1/logs?since=2024-01-01T00%3A00%3A00Z&sortOrder=ASCENDING"},
		{"devices", func() error { _, _, e := c.ListDevices(ctx, 200, ""); return e }, "GET /api/v1/devices?limit=200"},
		{"devices next", func() error { _, _, e := c.ListDevices(ctx, 200, "/api/v1/devices?after=x&limit=200"); return e }, "GET /api/v1/devices?after=x&limit=200"},
		{"api tokens", func() error { _, _, e := c.ListAPITokens(ctx, ""); return e }, "GET /api/v1/api-tokens"},
		{"api token", func() error { _, _, e := c.GetAPIToken(ctx, "00T1"); return e }, "GET /api/v1/api-tokens/00T1"},
		{"resource set", func() error { _, _, e := c.GetResourceSet(ctx, "iam1"); return e }, "GET /api/v1/iam/resource-sets/iam1"},
		{"binding", func() error { _, _, e := c.GetResourceSetBinding(ctx, "iam1", "cr0"); return e }, "GET /api/v1/iam/resource-sets/iam1/bindings/cr0"},
	}
	for i, tc := range calls {
		require.NoError(t, tc.call(), tc.name)
		reqs := ts.requests()
		require.Len(t, reqs, i+1, tc.name)
		got := reqs[i].method + " " + reqs[i].uri
		require.Equal(t, tc.want, got, tc.name)
	}
}

func TestLinkPagination(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Link", `<https://elsewhere.example/api/v1/users?limit=2>; rel="self"`)
		w.Header().Add("Link", `<https://elsewhere.example/api/v1/users?after=abc&limit=2>; rel="next"`)
		writeJSON(w, 200, `[{"id":"u1"}]`)
	})
	c, _ := newTestClient(t, ts)
	var users []*User
	resp, err := c.Do(context.Background(), http.MethodGet, "/api/v1/users?limit=2&search=status+pr", nil, &users)
	require.NoError(t, err)
	require.Len(t, users, 1)
	require.True(t, resp.HasNextPage())
	// Scheme and host are dropped; the request's own parameters carry over.
	require.Equal(t, "/api/v1/users?after=abc&limit=2&search=status+pr", resp.NextPage)
	require.Equal(t, "/api/v1/users?limit=2&search=status+pr", resp.Self)
	require.Equal(t, "abc", resp.NextAfter())

	var nilResp *Response
	require.False(t, nilResp.HasNextPage())
	require.Empty(t, nilResp.NextAfter())
}

func TestLastPageHasNoNext(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Link", `<https://x/api/v1/users?limit=2>; rel="self"`)
		w.Header().Add("Link", `malformed-without-params`)
		writeJSON(w, 200, `[]`)
	})
	c, _ := newTestClient(t, ts)
	_, resp, err := c.ListGroups(context.Background(), nil)
	require.NoError(t, err)
	require.False(t, resp.HasNextPage())
	require.Empty(t, resp.NextAfter())
}

func rateLimited(w http.ResponseWriter, resetIn int) {
	now := time.Now().UTC()
	w.Header().Set("Date", now.Format("Mon, 02 Jan 2006 15:04:05 GMT"))
	w.Header().Set("X-Rate-Limit-Reset", strconv.FormatInt(now.Unix()+int64(resetIn), 10))
	w.Header().Set("X-Okta-Request-Id", "req-429")
	writeJSON(w, http.StatusTooManyRequests, `{"errorCode":"E0000047","errorSummary":"API call exceeded rate limit due to too many requests."}`)
}

func TestRetries429ThenSucceeds(t *testing.T) {
	var n int
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		n++
		if n <= 2 {
			rateLimited(w, 4)
			return
		}
		writeJSON(w, 200, `{"id":"g1"}`)
	})
	c, sleeps := newTestClient(t, ts)
	_, _, err := c.CreateGroup(context.Background(), Group{Profile: &GroupProfile{Name: "x"}})
	require.NoError(t, err)

	reqs := ts.requests()
	require.Len(t, reqs, 3)
	require.Equal(t, []time.Duration{5 * time.Second, 5 * time.Second}, sleeps.slept)
	require.Empty(t, reqs[0].header.Get("X-Okta-Retry-Count"))
	require.Equal(t, []string{"1"}, reqs[1].header.Values("X-Okta-Retry-Count"))
	require.Equal(t, []string{"1", "2"}, reqs[2].header.Values("X-Okta-Retry-Count"))
	require.Equal(t, []string{"req-429", "req-429"}, reqs[2].header.Values("X-Okta-Retry-For"))
	// The body is replayed on every attempt.
	require.Equal(t, reqs[0].body, reqs[2].body)
}

func TestRetries429BackoffCapped(t *testing.T) {
	var n int
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		n++
		if n == 1 {
			rateLimited(w, 600)
			return
		}
		writeJSON(w, 200, `{}`)
	})
	c, sleeps := newTestClient(t, ts)
	_, _, err := c.GetOrgSettings(context.Background())
	require.NoError(t, err)
	require.Equal(t, []time.Duration{30 * time.Second}, sleeps.slept)
}

func TestRetries429Exhausted(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) { rateLimited(w, 0) })
	c, sleeps := newTestClient(t, ts)

	_, resp, err := c.GetOrgSettings(context.Background())
	require.Nil(t, resp, "an exhausted retry loop returns no response")
	require.EqualError(t, err, "too many requests")
	require.Len(t, ts.requests(), 3)
	require.Len(t, sleeps.slept, 2)

	// Status-line endpoints give up on the first 429 and wrap the failure.
	_, resp, err = c.ListDevices(context.Background(), 10, "")
	require.Nil(t, resp)
	var gerr *GenericError
	require.ErrorAs(t, err, &gerr)
	require.Equal(t, "too many requests", gerr.Error())
	require.Len(t, ts.requests(), 4)
	require.Len(t, sleeps.slept, 2)
}

func TestRetries429BadHeaders(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/org" {
			w.Header().Set("X-Rate-Limit-Reset", "1")
			w.Header().Set("Date", "not-a-date")
			writeJSON(w, http.StatusTooManyRequests, `{}`)
			return
		}
		w.Header().Set("Date", time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))
		writeJSON(w, http.StatusTooManyRequests, `{}`)
	})
	c, sleeps := newTestClient(t, ts)
	_, _, err := c.GetOrgSettings(context.Background())
	require.ErrorContains(t, err, "date header is missing or invalid")
	_, _, err = c.GetGroup(context.Background(), "g1", nil)
	require.ErrorContains(t, err, "X-Rate-Limit-Reset header is missing or invalid")
	require.Empty(t, sleeps.slept)
}

func TestRetrySleepHonorsContext(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) { rateLimited(w, 5) })
	c, _ := newTestClient(t, ts)
	c.sleep = sleepContext
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := c.GetOrgSettings(ctx)
	require.ErrorIs(t, err, context.Canceled)
}

func TestOktaErrors(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/users/missing":
			writeJSON(w, 404, `{"errorCode":"E0000007","errorSummary":"Not found: Resource not found: missing (User)","errorLink":"E0000007","errorId":"oae1","errorCauses":[]}`)
		case "/api/v1/users":
			writeJSON(w, 400, `{"errorCode":"E0000001","errorSummary":"Api validation failed: login",`+
				`"errorCauses":[{"errorSummary":"login: An object with this field already exists in the current organization"}]}`)
		case "/api/v1/groups":
			w.Header().Set("X-Okta-Request-Id", "rid-500")
			writeJSON(w, 500, `{"errorCode":"E0000009","errorSummary":"Internal Server Error"}`)
		case "/api/v1/apps":
			w.Header().Set("WWW-Authenticate", `Bearer authorization_uri="https://x/oauth2/v1/authorize", realm="IdpMyAccountAPI", `+
				`scope="okta.apps.read", error="insufficient_scope", `+
				`error_description="The access token provided does not contain the required scopes.", resource="/api/v1/apps"`)
			writeJSON(w, 403, ``)
		case "/api/v1/logs":
			w.Header().Set("WWW-Authenticate", `Bearer error_description=not-quoted`)
			writeJSON(w, 401, ``)
		case "/api/v1/org":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, "bad gateway")
		}
	})
	c, _ := newTestClient(t, ts)
	ctx := context.Background()

	_, resp, err := c.GetUser(ctx, "missing")
	require.NotNil(t, resp)
	require.Equal(t, 404, resp.StatusCode)
	var oerr *Error
	require.ErrorAs(t, err, &oerr)
	require.Equal(t, "E0000007", oerr.ErrorCode)
	require.Equal(t, "the API returned an error: Not found: Resource not found: missing (User)", err.Error())
	body, _ := io.ReadAll(resp.Body)
	require.Contains(t, string(body), "E0000007", "the error body stays readable")

	_, _, err = c.CreateUser(ctx, CreateUserRequest{}, nil)
	require.ErrorAs(t, err, &oerr)
	require.Len(t, oerr.ErrorCauses, 1)
	require.Equal(t, "the API returned an error: Api validation failed: login. Causes: errorSummary: login: An object with this field already exists in the current organization", err.Error())

	_, _, err = c.ListGroups(ctx, nil)
	require.EqualError(t, err, "the API returned an error: Internal Server Error, x-okta-request-id=rid-500")

	_, _, err = c.ListApplications(ctx, nil)
	require.EqualError(t, err, "the API returned an error: The access token provided does not contain the required scopes.")

	_, _, err = c.ListLogEvents(ctx, nil)
	require.EqualError(t, err, "the API returned an error: unauthorized")

	_, resp, err = c.GetOrgSettings(ctx)
	require.EqualError(t, err, "the API returned an unknown error")
	require.Equal(t, 502, resp.StatusCode)
}

func TestCheckResponseForError(t *testing.T) {
	ok := &http.Response{StatusCode: http.StatusFound}
	ok.Body = http.NoBody
	require.NoError(t, CheckResponseForError(ok))

	resp := &http.Response{
		StatusCode: http.StatusBadRequest,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(`{"error":"invalid_dpop_proof","error_description":"DPoP proof is invalid"}`)),
	}
	err := CheckResponseForError(resp)
	require.EqualError(t, err, "the API returned an error: DPoP proof is invalid")
	again, _ := io.ReadAll(resp.Body)
	require.Contains(t, string(again), "invalid_dpop_proof")
}

func TestGenericErrors(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/api-tokens/forbidden":
			writeJSON(w, 403, `{"errorCode":"E0000006","errorSummary":"You do not have permission to perform the requested action"}`)
		case "/api/v1/api-tokens/badjson":
			writeJSON(w, 404, `{not json`)
		case "/api/v1/api-tokens/html":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, "<html/>")
		case "/api/v1/api-tokens/boom":
			writeJSON(w, 500, `{"errorCode":"E0000009"}`)
		case "/api/v1/api-tokens/redirect":
			w.WriteHeader(http.StatusNotModified)
		case "/api/v1/api-tokens/badbody":
			writeJSON(w, 200, `{"id": 5}`)
		case "/api/v1/api-tokens/text":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "hi")
		}
	})
	c, _ := newTestClient(t, ts)
	ctx := context.Background()

	_, resp, err := c.GetAPIToken(ctx, "forbidden")
	var gerr *GenericError
	require.ErrorAs(t, err, &gerr)
	require.Equal(t, "403 Forbidden", err.Error())
	require.Equal(t, "E0000006", gerr.Model.ErrorCode)
	require.Equal(t, 403, resp.StatusCode)

	_, _, err = c.GetAPIToken(ctx, "badjson")
	require.ErrorContains(t, err, "invalid character")

	_, _, err = c.GetAPIToken(ctx, "html")
	require.EqualError(t, err, "undefined response type")

	_, _, err = c.GetAPIToken(ctx, "boom")
	require.EqualError(t, err, "500 Internal Server Error")

	_, _, err = c.GetAPIToken(ctx, "redirect")
	require.EqualError(t, err, "304 Not Modified")

	_, resp, err = c.GetAPIToken(ctx, "badbody")
	require.ErrorAs(t, err, &gerr)
	require.NotNil(t, resp)

	_, _, err = c.GetAPIToken(ctx, "text")
	require.EqualError(t, err, "undefined response type")
}

func TestNonJSONSuccessBody(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html/>")
	})
	c, _ := newTestClient(t, ts)
	_, _, err := c.GetOrgSettings(context.Background())
	require.EqualError(t, err, "could not build a response for type: text/html")
	_, err = c.SuspendUser(context.Background(), "u1")
	require.EqualError(t, err, "could not build a response for type: text/html")
}

func TestResponseCache(t *testing.T) {
	var hits int
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Method != http.MethodGet {
			writeJSON(w, 200, `{}`)
			return
		}
		w.Header().Set("X-Rate-Limit-Remaining", strconv.Itoa(hits))
		writeJSON(w, 200, fmt.Sprintf(`{"id":"u1","status":"S%d"}`, hits))
	})
	c, _ := newTestClient(t, ts, func(c *Config) { c.CacheEnabled = true; c.CacheTTL = time.Minute })
	now := time.Unix(1_700_000_000, 0)
	c.cache.now = func() time.Time { return now }
	ctx := context.Background()

	u, _, err := c.GetUser(ctx, "u1")
	require.NoError(t, err)
	require.Equal(t, "S1", u.Status)

	u, resp, err := c.GetUser(ctx, "u1")
	require.NoError(t, err)
	require.Equal(t, "S1", u.Status, "served from cache")
	require.Equal(t, "1", resp.Header.Get("X-Rate-Limit-Remaining"), "cached headers replay too")
	require.Equal(t, 1, hits)

	u, _, err = c.GetUser(ctx, "u1", WithFreshRead())
	require.NoError(t, err)
	require.Equal(t, "S2", u.Status)
	u, _, _ = c.GetUser(ctx, "u1")
	require.Equal(t, "S2", u.Status, "a fresh read refreshes the cache")

	// A mutation of the same URL evicts it.
	_, _, err = c.PartialUpdateUser(ctx, "u1", User{})
	require.NoError(t, err)
	u, _, _ = c.GetUser(ctx, "u1")
	require.Equal(t, "S4", u.Status)

	now = now.Add(2 * time.Minute)
	u, _, _ = c.GetUser(ctx, "u1")
	require.Equal(t, "S5", u.Status, "expired entries are refetched")

	// Error responses are never cached.
	require.Equal(t, 5, hits)
}

func TestResponseCacheNoTTLAndDisabled(t *testing.T) {
	var hits int
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) { hits++; writeJSON(w, 200, `{}`) })
	c, _ := newTestClient(t, ts, func(c *Config) { c.CacheEnabled = true })
	c.cache.now = func() time.Time { return time.Unix(1<<40, 0) }
	_, _, _ = c.GetOrgSettings(context.Background())
	_, _, _ = c.GetOrgSettings(context.Background())
	require.Equal(t, 1, hits, "a zero TTL never expires")

	c2, _ := newTestClient(t, ts)
	_, _, _ = c2.GetOrgSettings(context.Background())
	_, _, _ = c2.GetOrgSettings(context.Background())
	require.Equal(t, 3, hits, "no cache when disabled")
}

func TestRateLimitPrevention(t *testing.T) {
	var n int
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		n++
		now := time.Now().UTC()
		w.Header().Set("Date", now.Format("Mon, 02 Jan 2006 15:04:05 GMT"))
		w.Header().Set("X-Rate-Limit-Limit", "100")
		w.Header().Set("X-Rate-Limit-Remaining", "0")
		w.Header().Set("X-Rate-Limit-Reset", strconv.FormatInt(now.Unix()+9, 10))
		writeJSON(w, 200, `[]`)
	})
	c, sleeps := newTestClient(t, ts)
	ctx := context.Background()

	_, _, err := c.ListGroups(ctx, nil)
	require.NoError(t, err)
	_, _, err = c.ListGroups(ctx, nil)
	require.NoError(t, err)
	require.Empty(t, sleeps.slept, "ordinary endpoints do not wait pre-emptively")

	_, _, err = c.ListDevices(ctx, 5, "")
	require.NoError(t, err)
	require.Empty(t, sleeps.slept)
	_, _, err = c.ListAPITokens(ctx, "")
	require.NoError(t, err)
	require.Equal(t, []time.Duration{10 * time.Second}, sleeps.slept)
}

type eofOnce struct {
	mu    sync.Mutex
	fails int
	next  http.RoundTripper
}

func (e *eofOnce) RoundTrip(r *http.Request) (*http.Response, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fails > 0 {
		e.fails--
		return nil, &url.Error{Op: "Get", URL: r.URL.String(), Err: io.EOF}
	}
	return e.next.RoundTrip(r)
}

func TestTransportErrors(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, `{}`) })
	c, _ := newTestClient(t, ts)
	rt := &eofOnce{fails: 1, next: ts.Client().Transport}
	c.httpClient = &http.Client{Transport: rt}

	_, _, err := c.GetOrgSettings(context.Background())
	require.NoError(t, err, "a dropped connection is retried")

	rt.fails = 10
	_, _, err = c.GetOrgSettings(context.Background())
	require.ErrorIs(t, err, io.EOF)
	require.ErrorContains(t, err, "network error")

	rt.fails = 1
	_, _, err = c.ListAPITokens(context.Background(), "")
	var gerr *GenericError
	require.ErrorAs(t, err, &gerr, "status-line endpoints do not retry a dropped connection")

	ts.Close()
	c.httpClient = ts.Client()
	_, resp, err := c.GetOrgSettings(context.Background())
	require.Nil(t, resp)
	var uerr *url.Error
	require.True(t, errors.As(err, &uerr), "other transport failures surface unchanged")
}

func TestQueryParamsEncoding(t *testing.T) {
	var nilQP *QueryParams
	require.Empty(t, nilQP.String())
	require.Empty(t, (&QueryParams{}).String())
	qp := &QueryParams{Search: "status pr", Limit: 1000, After: "00u1"}
	require.Equal(t, "?after=00u1&limit=1000&search=status+pr", qp.String())
}

func TestDeviceGetters(t *testing.T) {
	var d *Device
	require.Empty(t, d.GetId())
	id, model := "guo1", "MacBook"
	d = &Device{Id: &id, Profile: &DeviceProfile{DisplayName: "Laptop", Platform: "MACOS", Model: &model}}
	require.Equal(t, "guo1", d.GetId())
	require.Equal(t, "MacBook", d.Profile.GetModel())
	require.Empty(t, d.Profile.GetSerialNumber())
	var p *DeviceProfile
	require.Empty(t, p.GetDisplayName())
	require.Empty(t, p.GetPlatform())

	var rs *ResourceSet
	require.Empty(t, rs.GetId())
	require.Empty(t, rs.GetLabel())
	require.Empty(t, rs.GetDescription())
	rs = &ResourceSet{}
	rs.SetId("iam1")
	require.Equal(t, "iam1", rs.GetId())
}

func TestResponseCachePurgesExpiredEntries(t *testing.T) {
	cache := newResponseCache(time.Minute, 30*time.Second)
	now := time.Unix(1_700_000_000, 0)
	cache.now = func() time.Time { return now }
	resp := &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: http.Header{}}

	cache.set("a", resp, []byte("a"))
	cache.set("b", resp, []byte("b"))
	require.Equal(t, 2, cache.len())

	// Both entries expire, but nothing reads them again.
	now = now.Add(2 * time.Minute)
	cache.set("c", resp, []byte("c"))
	require.Equal(t, 1, cache.len(), "the write after the cleanup interval purges expired entries")

	// The next interval has elapsed too, so c is purged as well.
	now = now.Add(2 * time.Minute)
	cache.set("d", resp, []byte("d"))
	require.Equal(t, 1, cache.len(), "c expired and was purged on this write")
	_, ok := cache.get("d")
	require.True(t, ok)

	noCleanup := newResponseCache(time.Minute, 0)
	noCleanup.now = cache.now
	noCleanup.set("x", resp, nil)
	now = now.Add(time.Hour)
	noCleanup.set("y", resp, nil)
	require.Equal(t, 2, noCleanup.len(), "a zero cleanup interval never purges")
}
