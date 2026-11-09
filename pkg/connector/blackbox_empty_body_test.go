package connector_test

// Black-box tests for single-object lookups that Okta answers with 200 and an
// empty body or a JSON null. They pin what GetResource and Validate do with
// such a response for each lookup that can be reached without a panic.
// User, group, custom-role and resource-set lookups panic on these bodies and
// are not covered here.
// See blackbox_harness_test.go.

import (
	"net/http"
	"testing"

	cfg "github.com/conductorone/baton-okta/pkg/config"
)

// emptyBodies are the two "nothing there" 200 responses.
var emptyBodies = []struct{ name, body string }{
	{"empty", ""},
	{"null", "null"},
}

// emptyBodyGet serves body for path and records GetResource(rt, id). opts
// builds extra connector options for the fake org each case runs against.
func emptyBodyGet(t *testing.T, path, rt, id string, opts func(t *testing.T, f *fakeOkta) []connOpt) {
	t.Helper()
	for _, b := range emptyBodies {
		t.Run(b.name, func(t *testing.T) {
			f := newFakeOkta(t)
			f.JSON(http.MethodGet, path, http.StatusOK, b.body)
			conn := []connOpt{withConfig(appsNoCache)}
			if opts != nil {
				conn = append(conn, opts(t, f)...)
			}
			srv := newServer(t, f, conn...)
			g := newGolden(t, f)
			appsGetCall(g, srv, "GetResource "+rt, rt, id)
			g.Check()
		})
	}
}

func TestBlackboxEmptyBodyApiTokenGet(t *testing.T) {
	emptyBodyGet(t, "/api/v1/api-tokens/00Tabcdef0123456789a", "api-token", "00Tabcdef0123456789a",
		func(t *testing.T, f *fakeOkta) []connOpt {
			return []connOpt{appsVia(t, f), withConfig(func(c *cfg.Okta) { c.SyncSecrets = true })}
		})
}

func TestBlackboxEmptyBodyResourceSetBindingGet(t *testing.T) {
	emptyBodyGet(t, "/api/v1/iam/resource-sets/"+appsRS1+"/bindings/"+appsRole1, "resourceset-binding", appsRS1+":"+appsRole1,
		func(t *testing.T, f *fakeOkta) []connOpt {
			f.Fixture(http.MethodGet, "/api/v1/iam/resource-sets/"+appsRS1, "apps_resource_set_get.json")
			return []connOpt{appsVia(t, f), withConfig(appsCustomRoles)}
		})
}

// With inactive apps excluded, an app lookup that returns nothing is NotFound.
func TestBlackboxEmptyBodyAppGet(t *testing.T) {
	emptyBodyGet(t, "/api/v1/apps/"+appsSAMLID, "app", appsSAMLID, nil)
}

// With inactive apps synced, an app lookup that returns nothing yields an app
// resource with an empty ID.
func TestBlackboxEmptyBodyAppGetSyncInactive(t *testing.T) {
	emptyBodyGet(t, "/api/v1/apps/"+appsSAMLID, "app", appsSAMLID,
		func(*testing.T, *fakeOkta) []connOpt {
			return []connOpt{withConfig(func(c *cfg.Okta) { c.SyncInactiveApps = true })}
		})
}

func TestBlackboxEmptyBodyValidateOrgSettings(t *testing.T) {
	for _, b := range emptyBodies {
		t.Run(b.name, func(t *testing.T) {
			f := newFakeOkta(t)
			f.JSON(http.MethodGet, "/api/v1/org", http.StatusOK, b.body)
			srv := newServer(t, f)
			g := newGolden(t, f)
			opsValidate(t, g, srv, "Validate")
			g.Check()
		})
	}
}
