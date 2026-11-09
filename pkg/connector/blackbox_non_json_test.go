package connector_test

// Black-box tests for 2xx responses whose body is not JSON on the device and
// API-token endpoints. They pin the error each such response produces on a
// first request and on a follow-up page. See blackbox_harness_test.go.

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/conductorone/baton-sdk/pkg/cli"

	cfg "github.com/conductorone/baton-okta/pkg/config"
)

// nonJSONPages serves firstPage as JSON with a rel="next" link on the first
// request, then a 200 text/plain body for the next page.
func nonJSONPages(f *fakeOkta, path, firstPage string) {
	f.Handle(http.MethodGet, path, func(w http.ResponseWriter, r *http.Request, _ []string) {
		if r.URL.Query().Get("after") == "" {
			next := *r.URL
			q := next.Query()
			q.Set("after", "cursor1")
			next.RawQuery = q.Encode()
			w.Header().Add("Link", fmt.Sprintf(`<%s>; rel="next"`, f.URL(next.RequestURI())))
			writeJSON(w, http.StatusOK, firstPage)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	})
}

func nonJSON(f *fakeOkta, path string) {
	f.Handle(http.MethodGet, path, func(w http.ResponseWriter, r *http.Request, _ []string) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	})
}

func TestBlackboxNonJSONDevices(t *testing.T) {
	t.Run("first page", func(t *testing.T) {
		f := newFakeOkta(t)
		nonJSON(f, "/api/v1/devices")
		srv := newServer(t, f, appsVia(t, f), withConfig(appsNoCache))
		g := newGolden(t, f)
		listAllResources(t, g, srv, "device", nil, 2)
		g.Check()
	})
	t.Run("next page", func(t *testing.T) {
		f := newFakeOkta(t)
		nonJSONPages(f, "/api/v1/devices", fixture(t, "apps_devices_page1.json"))
		srv := newServer(t, f, appsVia(t, f), withConfig(appsNoCache))
		g := newGolden(t, f)
		listAllResources(t, g, srv, "device", nil, 2)
		g.Check()
	})
}

func TestBlackboxNonJSONApiTokens(t *testing.T) {
	opts := func(t *testing.T, f *fakeOkta) []connOpt {
		return []connOpt{appsVia(t, f), withConfig(appsNoCache),
			withCLIOpts(&cli.ConnectorOpts{}), withConfig(func(c *cfg.Okta) { c.SyncSecrets = true })}
	}
	t.Run("get", func(t *testing.T) {
		f := newFakeOkta(t)
		nonJSON(f, "/api/v1/api-tokens/00Tabcdef0123456789a")
		srv := newServer(t, f, opts(t, f)...)
		g := newGolden(t, f)
		appsGetCall(g, srv, "GetResource api-token", "api-token", "00Tabcdef0123456789a")
		g.Check()
	})
	t.Run("first page", func(t *testing.T) {
		f := newFakeOkta(t)
		nonJSON(f, "/api/v1/api-tokens")
		srv := newServer(t, f, opts(t, f)...)
		g := newGolden(t, f)
		listAllResources(t, g, srv, "api-token", nil, 2)
		g.Check()
	})
	t.Run("next page", func(t *testing.T) {
		f := newFakeOkta(t)
		nonJSONPages(f, "/api/v1/api-tokens", fixture(t, "apps_api_tokens_page1.json"))
		srv := newServer(t, f, opts(t, f)...)
		g := newGolden(t, f)
		listAllResources(t, g, srv, "api-token", nil, 2)
		g.Check()
	})
}

// A follow-up device page that fails with a non-2xx status other than 403, 404
// or 429 is an error carrying the status line. The previous client ignored
// those statuses on follow-up pages: an empty-bodied 5xx ended the listing as
// if it were complete, and any other body failed to decode as a page.
func TestBlackboxFollowUpPageServerErrors(t *testing.T) {
	for _, tc := range []struct {
		name, ct, body string
		status         int
	}{
		{"502 empty", "", "", http.StatusBadGateway},
		{"500 json", "application/json", `{"errorCode":"E0000009","errorSummary":"Internal Server Error"}`, http.StatusInternalServerError},
		{"503 html", "text/html", "<html>down</html>", http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeOkta(t)
			page1 := fixture(t, "apps_devices_page1.json")
			f.Handle(http.MethodGet, "/api/v1/devices", func(w http.ResponseWriter, r *http.Request, _ []string) {
				if r.URL.Query().Get("after") == "" {
					next := *r.URL
					q := next.Query()
					q.Set("after", "cursor1")
					next.RawQuery = q.Encode()
					w.Header().Add("Link", fmt.Sprintf(`<%s>; rel="next"`, f.URL(next.RequestURI())))
					writeJSON(w, http.StatusOK, page1)
					return
				}
				if tc.ct != "" {
					w.Header().Set("Content-Type", tc.ct)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			srv := newServer(t, f, appsVia(t, f), withConfig(appsNoCache))
			g := newGolden(t, f)
			listAllResources(t, g, srv, "device", nil, 2)
			g.Check()
		})
	}
}
