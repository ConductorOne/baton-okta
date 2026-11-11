package connector_test

// Black-box regression tests for apps, resource sets, resource-set bindings,
// API tokens and devices. See blackbox_harness_test.go.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	cfg "github.com/conductorone/baton-okta/pkg/config"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/cli"
	"github.com/conductorone/baton-sdk/pkg/types"
	"github.com/stretchr/testify/require"
)

const (
	appsSAMLID  = "0oa1gjh63g214q0Hq0g4"
	appsUserID  = "00u5erin000000005"
	appsGroupID = "00g4newgroup000004"
	appsRS1     = "iam1abcdefghijklmn01"
	appsRS3     = "iam3abcdefghijklmn03"
	appsRole1   = "cr0adminrole00000001"
)

// ---- helpers ---------------------------------------------------------------

func appsErrBody(code, summary string) string {
	return fmt.Sprintf(`{"errorCode":%q,"errorSummary":%q,"errorLink":%q,"errorId":"oaeBlackbox","errorCauses":[]}`, code, summary, code)
}

// appsErrorCases are the Okta error shapes driven through each error test.
var appsErrorCases = []struct {
	name   string
	status int
	code   string
	text   string
}{
	{"401", http.StatusUnauthorized, "E0000011", "Invalid token provided"},
	{"403", http.StatusForbidden, "E0000006", "You do not have permission to perform the requested action"},
	{"404", http.StatusNotFound, "E0000007", "Not found: Resource not found: x (Application)"},
	{"500", http.StatusInternalServerError, "E0000009", "Internal Server Error"},
}

func appsActiveOnly(t *testing.T, body string) string {
	t.Helper()
	var items []map[string]any
	require.NoError(t, json.Unmarshal([]byte(body), &items))
	kept := []map[string]any{}
	for _, it := range items {
		if it["status"] == "ACTIVE" {
			kept = append(kept, it)
		}
	}
	out, err := json.Marshal(kept)
	require.NoError(t, err)
	return string(out)
}

// appsRegisterApps serves the app list fixtures, filtering INACTIVE apps the way
// Okta does for the filter the connector sends.
func appsRegisterApps(t *testing.T, f *fakeOkta, activeOnly bool) {
	t.Helper()
	b1, b2 := fixture(t, "apps_list_page1.json"), fixture(t, "apps_list_page2.json")
	if activeOnly {
		b1, b2 = appsActiveOnly(t, b1), appsActiveOnly(t, b2)
	}
	f.Pages("/api/v1/apps", b1, b2)
}

func appsRes(id, label string) *v2.Resource {
	return &v2.Resource{Id: &v2.ResourceId{ResourceType: "app", Resource: id}, DisplayName: label}
}

func appsPrincipal(rt, id string) *v2.Resource {
	return &v2.Resource{Id: &v2.ResourceId{ResourceType: rt, Resource: id}}
}

func appsEnt(res *v2.Resource, slug string) *v2.Entitlement {
	return &v2.Entitlement{
		Id:       fmt.Sprintf("%s:%s:%s", res.GetId().GetResourceType(), res.GetId().GetResource(), slug),
		Resource: res,
		Slug:     slug,
	}
}

func appsGrantCall(g *golden, srv types.ConnectorServer, name string, ent *v2.Entitlement, principal *v2.Resource) {
	resp, err := srv.Grant(context.Background(), &v2.GrantManagerServiceGrantRequest{Entitlement: ent, Principal: principal})
	g.Step(name, stripSessionUsage(resp), err)
}

func appsRevokeCall(g *golden, srv types.ConnectorServer, name string, ent *v2.Entitlement, principal *v2.Resource) {
	resp, err := srv.Revoke(context.Background(), &v2.GrantManagerServiceRevokeRequest{
		Grant: &v2.Grant{Id: ent.GetId() + ":" + principal.GetId().GetResource(), Entitlement: ent, Principal: principal},
	})
	g.Step(name, stripSessionUsage(resp), err)
}

func appsGetCall(g *golden, srv types.ConnectorServer, name, rt, id string) {
	resp, err := srv.GetResource(context.Background(), &v2.ResourceGetterServiceGetResourceRequest{
		ResourceId:   &v2.ResourceId{ResourceType: rt, Resource: id},
		ActiveSyncId: testSyncID,
	})
	g.Step(name, stripSessionUsage(resp), err)
}

// appsRateLimitOnce makes the handler answer 429 once (with the headers the Okta
// client's retry loop parses), then fall through to ok.
func appsRateLimitOnce(f *fakeOkta, method, pattern string, ok func(w http.ResponseWriter, r *http.Request, m []string)) {
	var n int
	f.Handle(method, pattern, func(w http.ResponseWriter, r *http.Request, m []string) {
		n++
		if n == 1 {
			now := time.Now().UTC()
			w.Header().Set("Date", now.Format("Mon, 02 Jan 2006 15:04:05 GMT"))
			w.Header().Set("X-Rate-Limit-Reset", strconv.FormatInt(now.Unix(), 10))
			writeJSON(w, http.StatusTooManyRequests, appsErrBody("E0000047", "API call exceeded rate limit due to too many requests."))
			return
		}
		ok(w, r, m)
	})
}

func appsFixtureHandler(t *testing.T, name string) func(w http.ResponseWriter, r *http.Request, m []string) {
	body := fixture(t, name)
	return func(w http.ResponseWriter, r *http.Request, _ []string) { writeJSON(w, http.StatusOK, body) }
}

// ---- device, API-token and resource-set reachability -----------------------
//
// The connector once reached the device, API-token and resource-set endpoints
// through a client that built its server URL from the org URL's Hostname(),
// dropping the port, so it could never reach a fake listening on an ephemeral
// port by address. Tests of those endpoints therefore configure the domain
// "example.com" (covered by httptest's certificate) and a process-wide CONNECT
// proxy, set via HTTPS_PROXY before the HTTP transport first reads the
// environment, tunnels example.com:443 to the current test's fake. The setup
// is kept so the same tests run unchanged against both implementations. Loopback
// destinations are never proxied, so tests that use the fake's own address are
// unaffected.

const appsProxiedDomain = "example.com"

var appsProxy struct {
	mu     sync.Mutex
	target string
}

// startAppsProxy runs from TestMain, before any HTTP transport reads the proxy
// environment.
func startAppsProxy() {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go appsServeConnect(c)
		}
	}()
	proxyURL := "http://" + ln.Addr().String()
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		_ = os.Setenv(k, proxyURL)
	}
	for _, k := range []string{"NO_PROXY", "no_proxy"} {
		_ = os.Setenv(k, "")
	}
}

func appsServeConnect(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil || req.Method != http.MethodConnect {
		_, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}
	appsProxy.mu.Lock()
	target := appsProxy.target
	appsProxy.mu.Unlock()
	up, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", target)
	if err != nil {
		_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer up.Close()
	_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, br); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
	<-done
}

// appsVia points the connector at the proxied domain and the proxy at f.
func appsVia(t *testing.T, f *fakeOkta) connOpt {
	t.Helper()
	appsProxy.mu.Lock()
	appsProxy.target = f.Host()
	appsProxy.mu.Unlock()
	return withConfig(func(c *cfg.Okta) { c.Domain = appsProxiedDomain })
}

// ---- apps ------------------------------------------------------------------

func TestBlackboxAppsListActiveOnly(t *testing.T) {
	f := newFakeOkta(t)
	appsRegisterApps(t, f, true)
	srv := newServer(t, f)
	g := newGolden(t, f)

	apps := listAllResources(t, g, srv, "app", nil, 2)
	require.Len(t, apps, 3)
	for _, a := range apps {
		listAllEntitlements(t, g, srv, a)
	}
	g.Check()
}

func TestBlackboxAppsListSyncInactive(t *testing.T) {
	f := newFakeOkta(t)
	appsRegisterApps(t, f, false)
	srv := newServer(t, f, withConfig(func(c *cfg.Okta) { c.SyncInactiveApps = true }))
	g := newGolden(t, f)

	apps := listAllResources(t, g, srv, "app", nil, 3)
	require.Len(t, apps, 5)
	g.Check()
}

// FilterEmailDomains only applies to app users, never to the app list itself.
func TestBlackboxAppsListIgnoresEmailFilter(t *testing.T) {
	f := newFakeOkta(t)
	appsRegisterApps(t, f, true)
	srv := newServer(t, f, withConfig(func(c *cfg.Okta) { c.FilterEmailDomains = []string{"Example.com"} }))
	g := newGolden(t, f)

	apps := listAllResources(t, g, srv, "app", nil, 0)
	require.Len(t, apps, 3)
	g.Check()
}

func TestBlackboxAppsGrants(t *testing.T) {
	f := newFakeOkta(t)
	f.FixturePages("/api/v1/apps/[^/]+/groups", "apps_groups_page1.json", "apps_groups_page2.json")
	f.FixturePages("/api/v1/apps/[^/]+/users", "apps_users_page1.json", "apps_users_page2.json")
	srv := newServer(t, f)
	g := newGolden(t, f)

	grants := listAllGrants(t, g, srv, appsRes(appsSAMLID, "Salesforce Sandbox"), 2)
	require.NotEmpty(t, grants)
	g.Check()
}

func TestBlackboxAppsGrantsEmailFilter(t *testing.T) {
	f := newFakeOkta(t)
	f.FixturePages("/api/v1/apps/[^/]+/groups", "apps_groups_page1.json", "apps_groups_page2.json")
	f.FixturePages("/api/v1/apps/[^/]+/users", "apps_users_page1.json", "apps_users_page2.json")
	srv := newServer(t, f, withConfig(func(c *cfg.Okta) { c.FilterEmailDomains = []string{"Example.com"} }))
	g := newGolden(t, f)

	listAllGrants(t, g, srv, appsRes(appsSAMLID, "Salesforce Sandbox"), 0)
	g.Check()
}

// With skip-app-groups the group pass asks Okta to embed the group; an APP_GROUP
// (or an unreadable type) makes the user pass keep group-scoped users as direct,
// immutable grants.
func TestBlackboxAppsGrantsSkipAppGroups(t *testing.T) {
	f := newFakeOkta(t)
	f.FixturePages("/api/v1/apps/[^/]+/groups", "apps_groups_expand_page1.json", "apps_groups_expand_page2.json")
	f.FixturePages("/api/v1/apps/[^/]+/users", "apps_users_page1.json", "apps_users_page2.json")
	srv := newServer(t, f, withConfig(func(c *cfg.Okta) { c.SkipAppGroups = true }))
	g := newGolden(t, f)

	listAllGrants(t, g, srv, appsRes(appsSAMLID, "Salesforce Sandbox"), 2)
	g.Check()
}

// With skip-app-groups but only synced OKTA_GROUP assignments, group-scoped users
// stay suppressed (access flows through the expanded group grant).
func TestBlackboxAppsGrantsSkipAppGroupsAllSynced(t *testing.T) {
	f := newFakeOkta(t)
	f.Pages("/api/v1/apps/[^/]+/groups", `[{"id":"00g1engineering01","priority":0,"profile":{},"_embedded":{"group":{"id":"00g1engineering01","type":"OKTA_GROUP","profile":{"name":"Engineering"}}}}]`)
	f.FixturePages("/api/v1/apps/[^/]+/users", "apps_users_page1.json", "apps_users_page2.json")
	srv := newServer(t, f, withConfig(func(c *cfg.Okta) { c.SkipAppGroups = true }))
	g := newGolden(t, f)

	listAllGrants(t, g, srv, appsRes(appsSAMLID, "Salesforce Sandbox"), 0)
	g.Check()
}

func TestBlackboxAppsGetResource(t *testing.T) {
	f := newFakeOkta(t)
	f.Fixture(http.MethodGet, "/api/v1/apps/"+appsSAMLID, "apps_get_active.json")
	f.Fixture(http.MethodGet, "/api/v1/apps/0oa3ina2kLm9nP4rS5d7", "apps_get_inactive.json")
	srv := newServer(t, f)
	g := newGolden(t, f)

	appsGetCall(g, srv, "GetResource active app", "app", appsSAMLID)
	appsGetCall(g, srv, "GetResource inactive app (not syncing inactive)", "app", "0oa3ina2kLm9nP4rS5d7")
	appsGetCall(g, srv, "GetResource missing app", "app", "0oa9missing0000000000")
	g.Check()
}

func TestBlackboxAppsGetResourceSyncInactive(t *testing.T) {
	f := newFakeOkta(t)
	f.Fixture(http.MethodGet, "/api/v1/apps/0oa3ina2kLm9nP4rS5d7", "apps_get_inactive.json")
	srv := newServer(t, f, withConfig(func(c *cfg.Okta) { c.SyncInactiveApps = true }))
	g := newGolden(t, f)

	appsGetCall(g, srv, "GetResource inactive app (syncing inactive)", "app", "0oa3ina2kLm9nP4rS5d7")
	g.Check()
}

func TestBlackboxAppsGrantRevokeUser(t *testing.T) {
	f := newFakeOkta(t)
	srv := newServer(t, f)
	g := newGolden(t, f)
	app := appsRes(appsSAMLID, "Salesforce Sandbox")
	ent := appsEnt(app, "access")
	user := appsPrincipal("user", appsUserID)
	appUserPath := "/api/v1/apps/" + appsSAMLID + "/users/" + appsUserID

	// Not assigned yet: lookup 404 -> fetch user -> assign.
	f.JSON(http.MethodGet, appUserPath, http.StatusNotFound, appsErrBody("E0000007", "Not found: Resource not found: "+appsUserID+" (AppUser)"))
	f.Fixture(http.MethodGet, "/api/v1/users/"+appsUserID, "apps_okta_user.json")
	f.Fixture(http.MethodPost, "/api/v1/apps/"+appsSAMLID+"/users", "apps_user_assign_resp.json")
	appsGrantCall(g, srv, "Grant user not yet assigned", ent, user)

	// Already assigned.
	f.JSON(http.MethodGet, appUserPath, http.StatusOK, `{"id":"`+appsUserID+`","scope":"USER","status":"ACTIVE","profile":{}}`)
	appsGrantCall(g, srv, "Grant user already assigned", ent, user)

	// Lookup fails with something other than not-found.
	f.JSON(http.MethodGet, appUserPath, http.StatusForbidden, appsErrBody("E0000006", "You do not have permission to perform the requested action"))
	appsGrantCall(g, srv, "Grant user lookup forbidden", ent, user)

	// Assign fails.
	f.JSON(http.MethodGet, appUserPath, http.StatusNotFound, appsErrBody("E0000007", "Not found"))
	f.JSON(http.MethodPost, "/api/v1/apps/"+appsSAMLID+"/users", http.StatusBadRequest, appsErrBody("E0000001", "Api validation failed: user"))
	appsGrantCall(g, srv, "Grant user assign rejected", ent, user)

	// User lookup fails.
	f.JSON(http.MethodGet, "/api/v1/users/"+appsUserID, http.StatusNotFound, appsErrBody("E0000007", "Not found: Resource not found: user (User)"))
	appsGrantCall(g, srv, "Grant user missing in okta", ent, user)

	// Revoke: assigned -> delete.
	f.JSON(http.MethodGet, appUserPath, http.StatusOK, `{"id":"`+appsUserID+`","scope":"USER","status":"ACTIVE","profile":{}}`)
	f.JSON(http.MethodDelete, appUserPath, http.StatusNoContent, "")
	appsRevokeCall(g, srv, "Revoke user assigned", ent, user)

	// Revoke: lookup 404 -> already revoked.
	f.JSON(http.MethodGet, appUserPath, http.StatusNotFound, appsErrBody("E0000007", "Not found: Resource not found: "+appsUserID+" (AppUser)"))
	appsRevokeCall(g, srv, "Revoke user not assigned", ent, user)

	// Revoke: lookup ok, delete 404 -> already revoked.
	f.JSON(http.MethodGet, appUserPath, http.StatusOK, `{"id":"`+appsUserID+`","scope":"USER","status":"ACTIVE","profile":{}}`)
	f.JSON(http.MethodDelete, appUserPath, http.StatusNotFound, appsErrBody("E0000007", "Not found"))
	appsRevokeCall(g, srv, "Revoke user delete not found", ent, user)

	// Revoke: delete forbidden (e.g. group-scoped assignment).
	f.JSON(http.MethodDelete, appUserPath, http.StatusForbidden, appsErrBody("E0000006", "You do not have permission to perform the requested action"))
	appsRevokeCall(g, srv, "Revoke user delete forbidden", ent, user)

	// Unsupported principal type.
	appsGrantCall(g, srv, "Grant unsupported principal", ent, appsPrincipal("role", "SUPER_ADMIN"))
	appsRevokeCall(g, srv, "Revoke unsupported principal", ent, appsPrincipal("role", "SUPER_ADMIN"))
	g.Check()
}

func TestBlackboxAppsGrantRevokeGroup(t *testing.T) {
	f := newFakeOkta(t)
	srv := newServer(t, f)
	g := newGolden(t, f)
	app := appsRes(appsSAMLID, "Salesforce Sandbox")
	ent := appsEnt(app, "access")
	group := appsPrincipal("group", appsGroupID)
	assignPath := "/api/v1/apps/" + appsSAMLID + "/groups/" + appsGroupID

	f.JSON(http.MethodGet, assignPath, http.StatusNotFound, appsErrBody("E0000007", "Not found: Resource not found: "+appsGroupID+" (ApplicationGroupAssignment)"))
	f.Fixture(http.MethodPut, assignPath, "apps_group_assign_resp.json")
	appsGrantCall(g, srv, "Grant group not yet assigned", ent, group)

	f.JSON(http.MethodGet, assignPath, http.StatusOK, `{"id":"`+appsGroupID+`","priority":0,"profile":{}}`)
	appsGrantCall(g, srv, "Grant group already assigned", ent, group)

	f.JSON(http.MethodGet, assignPath, http.StatusForbidden, appsErrBody("E0000006", "You do not have permission to perform the requested action"))
	appsGrantCall(g, srv, "Grant group lookup forbidden", ent, group)

	f.JSON(http.MethodGet, assignPath, http.StatusNotFound, appsErrBody("E0000007", "Not found"))
	f.JSON(http.MethodPut, assignPath, http.StatusForbidden, appsErrBody("E0000006", "You do not have permission to perform the requested action"))
	appsGrantCall(g, srv, "Grant group assign forbidden", ent, group)

	f.JSON(http.MethodGet, assignPath, http.StatusOK, `{"id":"`+appsGroupID+`","priority":0,"profile":{}}`)
	f.JSON(http.MethodDelete, assignPath, http.StatusNoContent, "")
	appsRevokeCall(g, srv, "Revoke group assigned", ent, group)

	f.JSON(http.MethodGet, assignPath, http.StatusNotFound, appsErrBody("E0000007", "Not found"))
	appsRevokeCall(g, srv, "Revoke group not assigned", ent, group)

	f.JSON(http.MethodGet, assignPath, http.StatusOK, `{"id":"`+appsGroupID+`","priority":0,"profile":{}}`)
	f.JSON(http.MethodDelete, assignPath, http.StatusNotFound, appsErrBody("E0000007", "Not found"))
	appsRevokeCall(g, srv, "Revoke group delete not found", ent, group)
	g.Check()
}

// ---- resource sets / bindings ---------------------------------------------

func appsCustomRoles(c *cfg.Okta) { c.SyncCustomRoles = true }

func appsRegisterResourceSets(t *testing.T, f *fakeOkta) {
	t.Helper()
	f.FixturePages("/api/v1/iam/resource-sets", "apps_resource_sets_page1.json", "apps_resource_sets_page2.json")
	f.Fixture(http.MethodGet, "/api/v1/iam/resource-sets/"+appsRS1+"/bindings", "apps_rs1_bindings.json")
	f.Fixture(http.MethodGet, "/api/v1/iam/resource-sets/iam2abcdefghijklmn02/bindings", "apps_rs2_bindings.json")
	f.Fixture(http.MethodGet, "/api/v1/iam/resource-sets/"+appsRS3+"/bindings", "apps_rs3_bindings.json")
}

func TestBlackboxAppsResourceSets(t *testing.T) {
	f := newFakeOkta(t)
	appsRegisterResourceSets(t, f)
	f.Fixture(http.MethodGet, "/api/v1/iam/resource-sets/"+appsRS1, "apps_resource_set_get.json")
	srv := newServer(t, f, appsVia(t, f), withConfig(appsCustomRoles))
	g := newGolden(t, f)

	sets := listAllResources(t, g, srv, "resource-set", nil, 2)
	require.Len(t, sets, 3)
	for _, s := range sets {
		listAllEntitlements(t, g, srv, s)
		listAllGrants(t, g, srv, s, 0)
	}
	appsGetCall(g, srv, "GetResource resource-set", "resource-set", appsRS1)
	appsGetCall(g, srv, "GetResource resource-set missing", "resource-set", "iam9missing000000000")

	// Grant is a no-op for resource sets; Revoke deletes the binding.
	set1 := sets[0]
	ent := appsEnt(set1, "bindings")
	role := appsPrincipal("custom-role", appsRole1)
	appsGrantCall(g, srv, "Grant resource-set (no-op)", ent, role)
	f.JSON(http.MethodDelete, "/api/v1/iam/resource-sets/"+appsRS1+"/bindings/"+appsRole1, http.StatusNoContent, "")
	appsRevokeCall(g, srv, "Revoke resource-set binding", ent, role)
	f.JSON(http.MethodDelete, "/api/v1/iam/resource-sets/"+appsRS1+"/bindings/"+appsRole1, http.StatusNotFound, appsErrBody("E0000007", "Not found: Resource not found"))
	appsRevokeCall(g, srv, "Revoke resource-set binding not found", ent, role)
	f.JSON(http.MethodDelete, "/api/v1/iam/resource-sets/"+appsRS1+"/bindings/"+appsRole1, http.StatusForbidden, appsErrBody("E0000006", "You do not have permission to perform the requested action"))
	appsRevokeCall(g, srv, "Revoke resource-set binding forbidden", ent, role)
	appsRevokeCall(g, srv, "Revoke resource-set unsupported principal", ent, appsPrincipal("user", appsUserID))
	g.Check()
}

func TestBlackboxAppsResourceSetBindings(t *testing.T) {
	f := newFakeOkta(t)
	appsRegisterResourceSets(t, f)
	bindingPath := "/api/v1/iam/resource-sets/" + appsRS1 + "/bindings/" + appsRole1
	f.Fixture(http.MethodGet, bindingPath, "apps_binding_get.json")
	f.Fixture(http.MethodGet, "/api/v1/iam/resource-sets/"+appsRS1, "apps_resource_set_get.json")
	f.Fixture(http.MethodGet, bindingPath+"/members", "apps_binding_members.json")
	srv := newServer(t, f, appsVia(t, f), withConfig(appsCustomRoles))
	g := newGolden(t, f)

	bindings := listAllResources(t, g, srv, "resourceset-binding", nil, 2)
	require.Len(t, bindings, 3) // rs1 x2 roles, rs2 x1 role, rs3 none
	b1 := bindings[0]
	listAllEntitlements(t, g, srv, b1)
	// Unsupported member types must not duplicate the preceding group grant.
	grants := listAllGrants(t, g, srv, b1, 0)
	require.Len(t, grants, 2)
	require.Equal(t, "00u1alice00000001", grants[0].GetPrincipal().GetId().GetResource())
	require.Equal(t, "00g1engineering01", grants[1].GetPrincipal().GetId().GetResource())
	appsGetCall(g, srv, "GetResource resourceset-binding", "resourceset-binding", appsRS1+":"+appsRole1)

	ent := appsEnt(b1, "member")
	user := appsPrincipal("user", "00u1alice00000001")
	group := appsPrincipal("group", "00g1engineering01")

	f.JSON(http.MethodPost, "/api/v1/iam/resource-sets/"+appsRS1+"/bindings", http.StatusOK, `{}`)
	appsGrantCall(g, srv, "Grant binding member user", ent, user)
	appsGrantCall(g, srv, "Grant binding member group", ent, group)
	f.JSON(http.MethodPost, "/api/v1/iam/resource-sets/"+appsRS1+"/bindings", http.StatusConflict, appsErrBody("E0000001", "Api validation failed: members"))
	appsGrantCall(g, srv, "Grant binding member already exists (409)", ent, user)
	f.JSON(http.MethodPost, "/api/v1/iam/resource-sets/"+appsRS1+"/bindings", http.StatusForbidden, appsErrBody("E0000006", "You do not have permission to perform the requested action"))
	appsGrantCall(g, srv, "Grant binding member forbidden", ent, user)
	appsGrantCall(g, srv, "Grant binding unsupported principal", ent, appsPrincipal("custom-role", appsRole1))
	appsGrantCall(g, srv, "Grant binding malformed entitlement resource", appsEnt(&v2.Resource{Id: &v2.ResourceId{ResourceType: "resourceset-binding", Resource: "no-colon"}}, "member"), user)

	f.JSON(http.MethodDelete, bindingPath+"/members/irb1member00000001", http.StatusNoContent, "")
	appsRevokeCall(g, srv, "Revoke binding member user", ent, user)
	f.JSON(http.MethodDelete, bindingPath+"/members/irb2member00000002", http.StatusNoContent, "")
	appsRevokeCall(g, srv, "Revoke binding member group", ent, group)
	appsRevokeCall(g, srv, "Revoke binding member not in binding", ent, appsPrincipal("user", "00u9nobody000000009"))
	f.JSON(http.MethodDelete, bindingPath+"/members/irb1member00000001", http.StatusNotFound, appsErrBody("E0000007", "Not found"))
	appsRevokeCall(g, srv, "Revoke binding member delete not found", ent, user)
	f.JSON(http.MethodGet, bindingPath+"/members", http.StatusNotFound, appsErrBody("E0000007", "Not found: Resource not found"))
	appsRevokeCall(g, srv, "Revoke binding members list not found", ent, user)
	g.Check()
}

// ---- api tokens ------------------------------------------------------------

func appsRegisterTokens(t *testing.T, f *fakeOkta) {
	t.Helper()
	f.FixturePages("/api/v1/api-tokens", "apps_api_tokens_page1.json", "apps_api_tokens_page2.json")
	f.Fixture(http.MethodGet, "/api/v1/api-tokens/00Tabcdef0123456789a", "apps_api_token_get.json")
}

func TestBlackboxAppsApiTokensSyncSecrets(t *testing.T) {
	f := newFakeOkta(t)
	appsRegisterTokens(t, f)
	srv := newServer(t, f, appsVia(t, f),
		withCLIOpts(&cli.ConnectorOpts{}),
		withConfig(func(c *cfg.Okta) { c.SyncSecrets = true }))
	g := newGolden(t, f)

	toks := listAllResources(t, g, srv, "api-token", nil, 2)
	require.Len(t, toks, 3)
	listAllEntitlements(t, g, srv, toks[0])
	listAllGrants(t, g, srv, toks[0], 0)
	appsGetCall(g, srv, "GetResource api-token", "api-token", "00Tabcdef0123456789a")
	g.Check()
}

func TestBlackboxAppsApiTokensExplicitFilter(t *testing.T) {
	f := newFakeOkta(t)
	appsRegisterTokens(t, f)
	srv := newServer(t, f, appsVia(t, f), withCLIOpts(&cli.ConnectorOpts{SyncResourceTypeIDs: []string{"api-token"}}))
	g := newGolden(t, f)

	toks := listAllResources(t, g, srv, "api-token", nil, 1)
	require.Len(t, toks, 3)
	appsGetCall(g, srv, "GetResource api-token", "api-token", "00Tabcdef0123456789a")
	g.Check()
}

// An unfiltered sync (non-nil opts, empty filter) without SyncSecrets never
// touches the API-tokens endpoint.
func TestBlackboxAppsApiTokensUnfilteredFetchesNothing(t *testing.T) {
	f := newFakeOkta(t)
	appsRegisterTokens(t, f)
	srv := newServer(t, f, withCLIOpts(&cli.ConnectorOpts{}))
	g := newGolden(t, f)

	toks := listAllResources(t, g, srv, "api-token", nil, 0)
	require.Empty(t, toks)
	appsGetCall(g, srv, "GetResource api-token", "api-token", "00Tabcdef0123456789a")
	g.Check()
	require.Empty(t, f.Requests())
}

// A filter that explicitly excludes api-token behaves the same.
func TestBlackboxAppsApiTokensFilterExcludesThem(t *testing.T) {
	f := newFakeOkta(t)
	appsRegisterTokens(t, f)
	srv := newServer(t, f, appsVia(t, f), withCLIOpts(&cli.ConnectorOpts{SyncResourceTypeIDs: []string{"user"}}))
	g := newGolden(t, f)

	require.Empty(t, listAllResources(t, g, srv, "api-token", nil, 0))
	g.Check()
	require.Empty(t, f.Requests())
}

// nil connector opts (capabilities generation path) fetch tokens.
func TestBlackboxAppsApiTokensNilOpts(t *testing.T) {
	f := newFakeOkta(t)
	appsRegisterTokens(t, f)
	srv := newServer(t, f, appsVia(t, f))
	g := newGolden(t, f)

	require.Len(t, listAllResources(t, g, srv, "api-token", nil, 0), 3)
	g.Check()
}

// ---- devices ---------------------------------------------------------------

func TestBlackboxAppsDevices(t *testing.T) {
	f := newFakeOkta(t)
	f.FixturePages("/api/v1/devices", "apps_devices_page1.json", "apps_devices_page2.json")
	srv := newServer(t, f, appsVia(t, f))
	g := newGolden(t, f)

	devs := listAllResources(t, g, srv, "device", nil, 2)
	require.Len(t, devs, 4)
	listAllEntitlements(t, g, srv, devs[0])
	listAllGrants(t, g, srv, devs[0], 0)
	g.Check()
}

// Page size 0 and an oversized page size both clamp to Okta's 200 maximum.
func TestBlackboxAppsDevicesPageSizeClamp(t *testing.T) {
	f := newFakeOkta(t)
	f.FixturePages("/api/v1/devices", "apps_devices_page1.json", "apps_devices_page2.json")
	srv := newServer(t, f, appsVia(t, f), withConfig(func(c *cfg.Okta) { c.Cache = false }))
	g := newGolden(t, f)

	require.Len(t, listAllResources(t, g, srv, "device", nil, 0), 4)
	require.Len(t, listAllResources(t, g, srv, "device", nil, 5000), 4)
	require.Len(t, listAllResources(t, g, srv, "device", nil, 150), 4)
	g.Check()
}

func TestBlackboxAppsDevicesExplicitFilter(t *testing.T) {
	f := newFakeOkta(t)
	f.FixturePages("/api/v1/devices", "apps_devices_page1.json", "apps_devices_page2.json")
	srv := newServer(t, f, appsVia(t, f), withCLIOpts(&cli.ConnectorOpts{SyncResourceTypeIDs: []string{"device"}}))
	g := newGolden(t, f)

	require.Len(t, listAllResources(t, g, srv, "device", nil, 200), 4)
	g.Check()
}

// ---- error classification --------------------------------------------------

func TestBlackboxAppsErrors(t *testing.T) {
	scenarios := []struct {
		name string
		run  func(t *testing.T, f *fakeOkta, g *golden, srv types.ConnectorServer)
		mods func(f *fakeOkta) []connOpt
		path string
	}{
		{
			name: "AppList", path: "/api/v1/apps",
			run: func(t *testing.T, f *fakeOkta, g *golden, srv types.ConnectorServer) {
				listAllResources(t, g, srv, "app", nil, 0)
			},
		},
		{
			name: "AppGrants", path: "/api/v1/apps/[^/]+/groups",
			run: func(t *testing.T, f *fakeOkta, g *golden, srv types.ConnectorServer) {
				listAllGrants(t, g, srv, appsRes(appsSAMLID, "Salesforce Sandbox"), 0)
			},
		},
		{
			name: "AppUserGrants", path: "/api/v1/apps/[^/]+/users",
			run: func(t *testing.T, f *fakeOkta, g *golden, srv types.ConnectorServer) {
				f.FixturePages("/api/v1/apps/[^/]+/groups", "apps_groups_page1.json")
				listAllGrants(t, g, srv, appsRes(appsSAMLID, "Salesforce Sandbox"), 0)
			},
		},
		{
			name: "AppGet", path: "/api/v1/apps/[^/]+",
			run: func(t *testing.T, f *fakeOkta, g *golden, srv types.ConnectorServer) {
				appsGetCall(g, srv, "GetResource app", "app", appsSAMLID)
			},
		},
		{
			name: "DeviceList", path: "/api/v1/devices",
			run: func(t *testing.T, f *fakeOkta, g *golden, srv types.ConnectorServer) {
				listAllResources(t, g, srv, "device", nil, 0)
			},
		},
		{
			name: "ApiTokenList", path: "/api/v1/api-tokens",
			mods: func(f *fakeOkta) []connOpt {
				return []connOpt{withConfig(func(c *cfg.Okta) { c.SyncSecrets = true })}
			},
			run: func(t *testing.T, f *fakeOkta, g *golden, srv types.ConnectorServer) {
				listAllResources(t, g, srv, "api-token", nil, 0)
			},
		},
		{
			name: "ResourceSetList", path: "/api/v1/iam/resource-sets",
			mods: func(f *fakeOkta) []connOpt { return []connOpt{withConfig(appsCustomRoles)} },
			run: func(t *testing.T, f *fakeOkta, g *golden, srv types.ConnectorServer) {
				listAllResources(t, g, srv, "resource-set", nil, 0)
			},
		},
	}
	for _, sc := range scenarios {
		for _, ec := range appsErrorCases {
			t.Run(sc.name+"_"+ec.name, func(t *testing.T) {
				f := newFakeOkta(t)
				mods := []connOpt{appsVia(t, f)}
				if sc.mods != nil {
					mods = append(mods, sc.mods(f)...)
				}
				f.JSON(http.MethodGet, sc.path, ec.status, appsErrBody(ec.code, ec.text))
				srv := newServer(t, f, mods...)
				g := newGolden(t, f)
				sc.run(t, f, g, srv)
				g.Check()
			})
		}
	}
}

func TestBlackboxAppsRateLimitRecoversAppList(t *testing.T) {
	f := newFakeOkta(t)
	appsRateLimitOnce(f, http.MethodGet, "/api/v1/apps", appsFixtureHandler(t, "apps_list_page2.json"))
	srv := newServer(t, f)
	g := newGolden(t, f)

	listAllResources(t, g, srv, "app", nil, 0)
	g.Check()
}

func TestBlackboxAppsRateLimitRecoversDeviceList(t *testing.T) {
	f := newFakeOkta(t)
	appsRateLimitOnce(f, http.MethodGet, "/api/v1/devices", appsFixtureHandler(t, "apps_devices_page2.json"))
	srv := newServer(t, f, appsVia(t, f))
	g := newGolden(t, f)

	listAllResources(t, g, srv, "device", nil, 0)
	g.Check()
}

func TestBlackboxAppsRateLimitRecoversApiTokenList(t *testing.T) {
	f := newFakeOkta(t)
	appsRateLimitOnce(f, http.MethodGet, "/api/v1/api-tokens", appsFixtureHandler(t, "apps_api_tokens_page2.json"))
	srv := newServer(t, f, appsVia(t, f), withConfig(func(c *cfg.Okta) { c.SyncSecrets = true }))
	g := newGolden(t, f)

	listAllResources(t, g, srv, "api-token", nil, 0)
	g.Check()
}

// ---- private-key (OAuth + DPoP) auth --------------------------------------

func TestBlackboxAppsPrivateKeyList(t *testing.T) {
	cases := []struct {
		name string
		rt   string
		reg  func(t *testing.T, f *fakeOkta)
		mods func(c *cfg.Okta)
	}{
		{"app", "app", func(t *testing.T, f *fakeOkta) { appsRegisterApps(t, f, true) }, nil},
		{"resource-set", "resource-set", func(t *testing.T, f *fakeOkta) { appsRegisterResourceSets(t, f) }, appsCustomRoles},
		{"resourceset-binding", "resourceset-binding", func(t *testing.T, f *fakeOkta) { appsRegisterResourceSets(t, f) }, appsCustomRoles},
		{"api-token", "api-token", func(t *testing.T, f *fakeOkta) { appsRegisterTokens(t, f) }, func(c *cfg.Okta) { c.SyncSecrets = true }},
		{"device", "device", func(t *testing.T, f *fakeOkta) {
			f.FixturePages("/api/v1/devices", "apps_devices_page1.json", "apps_devices_page2.json")
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeOkta(t)
			tc.reg(t, f)
			mods := []connOpt{privateKeyConn(t, f), appsVia(t, f)}
			if tc.mods != nil {
				mods = append(mods, withConfig(tc.mods))
			}
			srv := newServer(t, f, mods...)
			g := newGolden(t, f)

			got := listAllResources(t, g, srv, tc.rt, nil, 2)
			require.NotEmpty(t, got)
			g.Check()
		})
	}
}
