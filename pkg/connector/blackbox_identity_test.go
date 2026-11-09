package connector_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"

	cfg "github.com/conductorone/baton-okta/pkg/config"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ---------------------------------------------------------------------------
// Helpers local to the identity (users / groups / roles / custom roles) tests
// ---------------------------------------------------------------------------

const (
	idnErr401 = `{"errorCode":"E0000011","errorSummary":"Invalid token provided","errorLink":"E0000011","errorId":"oaeAuth001","errorCauses":[]}`
	idnErr403 = `{"errorCode":"E0000006","errorSummary":"You do not have permission to perform the requested action","errorLink":"E0000006","errorId":"oaeDenied01","errorCauses":[]}`
	idnErr404 = `{"errorCode":"E0000007","errorSummary":"Not found: Resource not found: 00uzzz (User)","errorLink":"E0000007","errorId":"oaeNotFound1","errorCauses":[]}`
	idnErr400 = `{"errorCode":"E0000001","errorSummary":"Api validation failed: type","errorLink":"E0000001",` +
		`"errorId":"oaeBadReq001","errorCauses":[{"errorSummary":"type: The role type is not valid"}]}`
	idnErr500 = `{"errorCode":"E0000009","errorSummary":"Internal Server Error","errorLink":"E0000009","errorId":"oaeServer001","errorCauses":[]}`
	idnErr090 = `{"errorCode":"E0000090","errorSummary":"The role specified is already assigned to the user.","errorLink":"E0000090","errorId":"oaeAssigned1","errorCauses":[]}`

	idnUserAlice = "00uaa1111111111111a1"
	idnUserBob   = "00uaa2222222222222a2"
	idnGroupEng  = "00geng0000000000000g2"
	idnGroupAll  = "00gbuiltin00000000g1"
	idnCRSupport = "cr0support000000000001"
)

var idnAllUsersFixtures = []string{"identity_users_page1.json", "identity_users_page2.json", "identity_users_page3.json"}

// idnFake returns a fake org plus the commonly shared routes: users (3 pages),
// per-user GET, groups (2 pages), assignees (2 pages), custom roles (2 pages).
func idnFake(t *testing.T) *fakeOkta {
	t.Helper()
	f := newFakeOkta(t)
	f.FixturePages("/api/v1/users", idnAllUsersFixtures...)
	idnRouteUserGet(t, f)
	f.FixturePages("/api/v1/groups", "identity_groups_page1.json", "identity_groups_page2.json")
	f.FixturePages("/api/v1/iam/assignees/users", "identity_assignees_page1.json", "identity_assignees_page2.json")
	f.FixturePages("/api/v1/iam/roles", "identity_custom_roles_page1.json", "identity_custom_roles_page2.json")
	return f
}

// idnRouteUserGet serves GET /api/v1/users/{id} from the users fixtures.
func idnRouteUserGet(t *testing.T, f *fakeOkta) {
	t.Helper()
	byID := map[string]string{}
	for _, name := range idnAllUsersFixtures {
		var users []map[string]any
		require.NoError(t, json.Unmarshal([]byte(fixture(t, name)), &users))
		for _, u := range users {
			b, err := json.Marshal(u)
			require.NoError(t, err)
			byID[u["id"].(string)] = string(b)
		}
	}
	f.Handle(http.MethodGet, `/api/v1/users/([^/]+)`, func(w http.ResponseWriter, r *http.Request, m []string) {
		if body, ok := byID[m[1]]; ok {
			writeJSON(w, http.StatusOK, body)
			return
		}
		writeJSON(w, http.StatusNotFound, idnErr404)
	})
}

// idnRouteRoles routes the per-user and per-group "roles" listings.
func idnRouteRoles(f *fakeOkta, t *testing.T) {
	t.Helper()
	f.Fixture(http.MethodGet, `/api/v1/groups/[^/]+/roles`, "identity_group_roles.json")
	f.Fixture(http.MethodGet, `/api/v1/users/`+idnUserAlice+`/roles`, "identity_user_roles_alice.json")
	f.Fixture(http.MethodGet, `/api/v1/users/`+idnUserBob+`/roles`, "identity_user_roles_bob.json")
}

// idnRouteGroupUsers serves two member pages for the Everyone group and one
// page (users page 1) for every other group.
func idnRouteGroupUsers(f *fakeOkta, t *testing.T) {
	t.Helper()
	f.Fixture(http.MethodGet, `/api/v1/groups/[^/]+/users`, "identity_group_users_page1.json")
	f.FixturePages(`/api/v1/groups/`+idnGroupAll+`/users`, "identity_group_users_page1.json", "identity_group_users_page2.json")
}

func idnRes(rt, id string) *v2.Resource {
	return &v2.Resource{Id: &v2.ResourceId{ResourceType: rt, Resource: id}}
}

func idnEnt(res *v2.Resource, slug string) *v2.Entitlement {
	return &v2.Entitlement{
		Resource: res,
		Id:       fmt.Sprintf("%s:%s:%s", res.GetId().GetResourceType(), res.GetId().GetResource(), slug),
		Slug:     slug,
	}
}

func idnWithCustomRoles() connOpt {
	return withConfig(func(c *cfg.Okta) { c.SyncCustomRoles = true })
}

// idnProvisionCtx bounds a Grant/Revoke call. baton-sdk retries Unavailable
// failures (any 5xx / 429) with a 15s linear backoff; the deadline cuts that
// first sleep short so the recorded error is the connector's own first failure.
// Nothing else in these tests takes anywhere near the deadline.
func idnProvisionCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 3*time.Second)
}

func idnGrant(t *testing.T, g *golden, srv types.ConnectorServer, name string, ent *v2.Entitlement, principal *v2.Resource) {
	t.Helper()
	ctx, cancel := idnProvisionCtx()
	defer cancel()
	resp, err := srv.Grant(ctx, &v2.GrantManagerServiceGrantRequest{Entitlement: ent, Principal: principal})
	g.Step("Grant "+name, stripSessionUsage(resp), err)
}

func idnRevoke(t *testing.T, g *golden, srv types.ConnectorServer, name string, ent *v2.Entitlement, principal *v2.Resource) {
	t.Helper()
	ctx, cancel := idnProvisionCtx()
	defer cancel()
	resp, err := srv.Revoke(ctx, &v2.GrantManagerServiceRevokeRequest{Grant: &v2.Grant{Entitlement: ent, Principal: principal}})
	g.Step("Revoke "+name, stripSessionUsage(resp), err)
}

func idnGet(t *testing.T, g *golden, srv types.ConnectorServer, rt, id string) {
	t.Helper()
	resp, err := srv.GetResource(context.Background(), &v2.ResourceGetterServiceGetResourceRequest{
		ResourceId:   &v2.ResourceId{ResourceType: rt, Resource: id},
		ActiveSyncId: testSyncID,
	})
	g.Step(fmt.Sprintf("GetResource %s/%s", rt, id), stripSessionUsage(resp), err)
}

func idnByID(rs []*v2.Resource, id string) *v2.Resource {
	for _, r := range rs {
		if r.GetId().GetResource() == id {
			return r
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

func TestBlackboxIdentityUserList(t *testing.T) {
	f := idnFake(t)
	srv := newServer(t, f)
	g := newGolden(t, f)

	users := listAllResources(t, g, srv, "user", nil, 2)
	require.Len(t, users, 8)
	// Users have no entitlements or grants of their own.
	listAllEntitlements(t, g, srv, users[0])
	listAllGrants(t, g, srv, users[0], 100)
	g.Check()
}

func TestBlackboxIdentityUserListEmptyPage(t *testing.T) {
	f := newFakeOkta(t)
	f.JSON(http.MethodGet, "/api/v1/users", http.StatusOK, "[]")
	srv := newServer(t, f)
	g := newGolden(t, f)

	require.Empty(t, listAllResources(t, g, srv, "user", nil, 50))
	g.Check()
}

func TestBlackboxIdentityUserListEmptyMiddlePage(t *testing.T) {
	f := newFakeOkta(t)
	f.Pages("/api/v1/users", fixture(t, "identity_users_page1.json"), "[]", fixture(t, "identity_users_page3.json"))
	srv := newServer(t, f)
	g := newGolden(t, f)

	require.Len(t, listAllResources(t, g, srv, "user", nil, 2), 4)
	g.Check()
}

func TestBlackboxIdentityUserListSkipSecondaryEmails(t *testing.T) {
	f := idnFake(t)
	srv := newServer(t, f, withConfig(func(c *cfg.Okta) { c.SkipSecondaryEmails = true }))
	g := newGolden(t, f)

	listAllResources(t, g, srv, "user", nil, 100)
	g.Check()
}

func TestBlackboxIdentityUserListFilterEmailDomains(t *testing.T) {
	f := idnFake(t)
	srv := newServer(t, f, withConfig(func(c *cfg.Okta) { c.FilterEmailDomains = []string{"ACME.com"} }))
	g := newGolden(t, f)

	listAllResources(t, g, srv, "user", nil, 100)
	g.Check()
}

func TestBlackboxIdentityUserGet(t *testing.T) {
	f := idnFake(t)
	srv := newServer(t, f)
	g := newGolden(t, f)

	idnGet(t, g, srv, "user", idnUserAlice)
	idnGet(t, g, srv, "user", "00uzzz")
	g.Check()
}

func TestBlackboxIdentityUserGetFilteredOut(t *testing.T) {
	f := idnFake(t)
	srv := newServer(t, f, withConfig(func(c *cfg.Okta) { c.FilterEmailDomains = []string{"other.org"} }))
	g := newGolden(t, f)

	idnGet(t, g, srv, "user", idnUserAlice)           // acme.com only: excluded -> NotFound
	idnGet(t, g, srv, "user", "00uaa5555555555555a5") // other.org: included
	g.Check()
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

func TestBlackboxIdentityGroupList(t *testing.T) {
	f := idnFake(t)
	srv := newServer(t, f)
	g := newGolden(t, f)

	groups := listAllResources(t, g, srv, "group", nil, 5)
	require.Len(t, groups, 7)
	for _, gr := range groups {
		listAllEntitlements(t, g, srv, gr)
	}
	g.Check()
}

func TestBlackboxIdentityGroupListEmptyPage(t *testing.T) {
	f := newFakeOkta(t)
	f.JSON(http.MethodGet, "/api/v1/groups", http.StatusOK, "[]")
	srv := newServer(t, f)
	g := newGolden(t, f)

	require.Empty(t, listAllResources(t, g, srv, "group", nil, 50))
	g.Check()
}

func TestBlackboxIdentityGroupListSkipAppGroups(t *testing.T) {
	f := idnFake(t)
	srv := newServer(t, f, withConfig(func(c *cfg.Okta) { c.SkipAppGroups = true }))
	g := newGolden(t, f)

	groups := listAllResources(t, g, srv, "group", nil, 100)
	require.Len(t, groups, 6)
	g.Check()
}

func TestBlackboxIdentityGroupGrants(t *testing.T) {
	f := idnFake(t)
	idnRouteGroupUsers(f, t)
	idnRouteRoles(f, t)
	srv := newServer(t, f)
	g := newGolden(t, f)

	groups := listAllResources(t, g, srv, "group", nil, 100)
	for _, gr := range groups {
		listAllGrants(t, g, srv, gr, 100)
	}
	g.Check()
}

// Everyone's members span two pages; the page size forces multiple phases:
// users page 1, users page 2, then the roles phase.
func TestBlackboxIdentityGroupGrantsMultiPhase(t *testing.T) {
	f := idnFake(t)
	idnRouteGroupUsers(f, t)
	idnRouteRoles(f, t)
	srv := newServer(t, f)
	g := newGolden(t, f)

	groups := listAllResources(t, g, srv, "group", nil, 100)
	listAllGrants(t, g, srv, idnByID(groups, idnGroupAll), 2)
	g.Check()
}

func TestBlackboxIdentityGroupGrantsCustomRoles(t *testing.T) {
	f := idnFake(t)
	idnRouteGroupUsers(f, t)
	idnRouteRoles(f, t)
	srv := newServer(t, f, idnWithCustomRoles())
	g := newGolden(t, f)

	groups := listAllResources(t, g, srv, "group", nil, 100)
	listAllGrants(t, g, srv, idnByID(groups, idnGroupEng), 100)
	listAllGrants(t, g, srv, idnByID(groups, idnGroupAll), 100)
	g.Check()
}

func TestBlackboxIdentityGroupGrantsFilterEmailDomains(t *testing.T) {
	f := idnFake(t)
	idnRouteGroupUsers(f, t)
	idnRouteRoles(f, t)
	srv := newServer(t, f, withConfig(func(c *cfg.Okta) { c.FilterEmailDomains = []string{"acme.com"} }))
	g := newGolden(t, f)

	groups := listAllResources(t, g, srv, "group", nil, 100)
	listAllGrants(t, g, srv, idnByID(groups, idnGroupAll), 100)
	g.Check()
}

func TestBlackboxIdentityGroupGrantsEmptyMembersAndRoles(t *testing.T) {
	f := idnFake(t)
	f.JSON(http.MethodGet, `/api/v1/groups/[^/]+/users`, http.StatusOK, "[]")
	f.JSON(http.MethodGet, `/api/v1/groups/[^/]+/roles`, http.StatusOK, "[]")
	srv := newServer(t, f)
	g := newGolden(t, f)

	groups := listAllResources(t, g, srv, "group", nil, 100)
	listAllGrants(t, g, srv, idnByID(groups, idnGroupAll), 100)
	g.Check()
}

// A group-roles listing denied with E0000006 is skipped; other failures surface.
func TestBlackboxIdentityGroupGrantsRoleErrors(t *testing.T) {
	f := idnFake(t)
	f.JSON(http.MethodGet, `/api/v1/groups/[^/]+/users`, http.StatusOK, "[]")
	f.JSON(http.MethodGet, `/api/v1/groups/`+idnGroupAll+`/roles`, http.StatusForbidden, idnErr403)
	f.JSON(http.MethodGet, `/api/v1/groups/`+idnGroupEng+`/roles`, http.StatusNotFound, idnErr404)
	f.JSON(http.MethodGet, `/api/v1/groups/00gzeroapps000000000g4/roles`, http.StatusInternalServerError, idnErr500)
	f.JSON(http.MethodGet, `/api/v1/groups/00glong0000000000000g5/roles`, http.StatusInternalServerError, "")
	f.JSON(http.MethodGet, `/api/v1/groups/00gapp0000000000000g3/roles`, http.StatusUnauthorized, idnErr401)
	f.JSON(http.MethodGet, `/api/v1/groups/00gspace000000000000g6/roles`, http.StatusBadGateway, "<html>bad gateway</html>")
	srv := newServer(t, f)
	g := newGolden(t, f)

	groups := listAllResources(t, g, srv, "group", nil, 100)
	for _, id := range []string{idnGroupAll, idnGroupEng, "00gzeroapps000000000g4", "00glong0000000000000g5", "00gapp0000000000000g3", "00gspace000000000000g6"} {
		listAllGrants(t, g, srv, idnByID(groups, id), 100)
	}
	g.Check()
}

func TestBlackboxIdentityGroupGrantsMemberErrors(t *testing.T) {
	f := idnFake(t)
	f.JSON(http.MethodGet, `/api/v1/groups/`+idnGroupAll+`/users`, http.StatusForbidden, idnErr403)
	f.JSON(http.MethodGet, `/api/v1/groups/`+idnGroupEng+`/users`, http.StatusNotFound, idnErr404)
	f.JSON(http.MethodGet, `/api/v1/groups/00gzeroapps000000000g4/users`, http.StatusInternalServerError, idnErr500)
	srv := newServer(t, f)
	g := newGolden(t, f)

	groups := listAllResources(t, g, srv, "group", nil, 100)
	for _, id := range []string{idnGroupAll, idnGroupEng, "00gzeroapps000000000g4"} {
		listAllGrants(t, g, srv, idnByID(groups, id), 100)
	}
	g.Check()
}

func TestBlackboxIdentityGroupGet(t *testing.T) {
	f := newFakeOkta(t)
	f.Fixture(http.MethodGet, `/api/v1/groups/`+idnGroupEng, "identity_group_get.json")
	f.Fixture(http.MethodGet, `/api/v1/groups/00gzeroapps000000000g4`, "identity_group_get_zero.json")
	srv := newServer(t, f)
	g := newGolden(t, f)

	idnGet(t, g, srv, "group", idnGroupEng)
	idnGet(t, g, srv, "group", "00gzeroapps000000000g4") // users_count 0 and apps_count 0 -> SkipGrants
	idnGet(t, g, srv, "group", "00gmissing")             // unrouted 404
	g.Check()
}

func TestBlackboxIdentityGroupGetErrors(t *testing.T) {
	f := newFakeOkta(t)
	f.JSON(http.MethodGet, `/api/v1/groups/00g403`, http.StatusForbidden, idnErr403)
	f.JSON(http.MethodGet, `/api/v1/groups/00g500`, http.StatusInternalServerError, idnErr500)
	srv := newServer(t, f)
	g := newGolden(t, f)

	idnGet(t, g, srv, "group", "00g403")
	idnGet(t, g, srv, "group", "00g500")
	g.Check()
}

// ---------------------------------------------------------------------------
// Standard roles
// ---------------------------------------------------------------------------

func TestBlackboxIdentityRoleList(t *testing.T) {
	f := idnFake(t)
	srv := newServer(t, f)
	g := newGolden(t, f)

	roles := listAllResources(t, g, srv, "role", nil, 100)
	require.Len(t, roles, 10)
	for _, id := range []string{"SUPER_ADMIN", "USER_ADMIN"} {
		listAllEntitlements(t, g, srv, idnByID(roles, id))
	}
	// A role type the connector does not know about still gets an entitlement.
	listAllEntitlements(t, g, srv, &v2.Resource{Id: &v2.ResourceId{ResourceType: "role", Resource: "NEW_ADMIN"}, DisplayName: "New Admin"})
	idnGet(t, g, srv, "role", "SUPER_ADMIN")
	g.Check()
}

func TestBlackboxIdentityRoleGrants(t *testing.T) {
	f := idnFake(t)
	idnRouteRoles(f, t)
	srv := newServer(t, f)
	g := newGolden(t, f)

	roles := listAllResources(t, g, srv, "role", nil, 100)
	// Second call reuses the cached per-user role sets.
	for _, id := range []string{"SUPER_ADMIN", "READ_ONLY_ADMIN", "APP_ADMIN"} {
		listAllGrants(t, g, srv, idnByID(roles, id), 1)
	}
	g.Check()
}

func TestBlackboxIdentityRoleGrantsCustomRolesEnabled(t *testing.T) {
	f := idnFake(t)
	idnRouteRoles(f, t)
	srv := newServer(t, f, idnWithCustomRoles())
	g := newGolden(t, f)

	roles := listAllResources(t, g, srv, "role", nil, 100)
	listAllGrants(t, g, srv, idnByID(roles, "SUPER_ADMIN"), 100)
	g.Check()
}

func TestBlackboxIdentityRoleGrantsFilterEmailDomains(t *testing.T) {
	f := idnFake(t)
	idnRouteRoles(f, t)
	// Only other.org users pass the filter; the others' roles must not be fetched.
	srv := newServer(t, f, withConfig(func(c *cfg.Okta) { c.FilterEmailDomains = []string{"other.org"} }))
	g := newGolden(t, f)

	roles := listAllResources(t, g, srv, "role", nil, 100)
	listAllGrants(t, g, srv, idnByID(roles, "SUPER_ADMIN"), 100)
	g.Check()
}

func TestBlackboxIdentityRoleGrantsErrors(t *testing.T) {
	f := idnFake(t)
	f.Fixture(http.MethodGet, `/api/v1/users/`+idnUserAlice+`/roles`, "identity_user_roles_alice.json")
	f.JSON(http.MethodGet, `/api/v1/users/`+idnUserBob+`/roles`, http.StatusForbidden, idnErr403)
	srv := newServer(t, f)
	g := newGolden(t, f)

	roles := listAllResources(t, g, srv, "role", nil, 100)
	listAllGrants(t, g, srv, idnByID(roles, "SUPER_ADMIN"), 100)
	g.Check()
}

func TestBlackboxIdentityRoleGrantsAssigneesDenied(t *testing.T) {
	f := newFakeOkta(t)
	f.JSON(http.MethodGet, "/api/v1/iam/assignees/users", http.StatusForbidden, idnErr403)
	srv := newServer(t, f)
	g := newGolden(t, f)

	listAllGrants(t, g, srv, idnRes("role", "SUPER_ADMIN"), 100)
	g.Check()
}

func TestBlackboxIdentityRoleGrantsEmptyAssignees(t *testing.T) {
	f := newFakeOkta(t)
	f.JSON(http.MethodGet, "/api/v1/iam/assignees/users", http.StatusOK, `{"value":[],"_links":{}}`)
	srv := newServer(t, f)
	g := newGolden(t, f)

	require.Empty(t, listAllGrants(t, g, srv, idnRes("role", "SUPER_ADMIN"), 100))
	g.Check()
}

// ---------------------------------------------------------------------------
// Custom roles
// ---------------------------------------------------------------------------

func TestBlackboxIdentityCustomRoleList(t *testing.T) {
	f := idnFake(t)
	srv := newServer(t, f, idnWithCustomRoles())
	g := newGolden(t, f)

	roles := listAllResources(t, g, srv, "custom-role", nil, 1)
	require.Len(t, roles, 2)
	for _, r := range roles {
		listAllEntitlements(t, g, srv, r)
	}
	g.Check()
}

func TestBlackboxIdentityCustomRoleListEmptyPage(t *testing.T) {
	f := newFakeOkta(t)
	f.JSON(http.MethodGet, "/api/v1/iam/roles", http.StatusOK, `{"roles":[],"_links":{}}`)
	srv := newServer(t, f, idnWithCustomRoles())
	g := newGolden(t, f)

	require.Empty(t, listAllResources(t, g, srv, "custom-role", nil, 50))
	g.Check()
}

func TestBlackboxIdentityCustomRoleGrants(t *testing.T) {
	f := idnFake(t)
	idnRouteRoles(f, t)
	srv := newServer(t, f, idnWithCustomRoles())
	g := newGolden(t, f)

	roles := listAllResources(t, g, srv, "custom-role", nil, 100)
	listAllGrants(t, g, srv, idnByID(roles, idnCRSupport), 100)
	listAllGrants(t, g, srv, idnByID(roles, "cr0auditor000000000002"), 100)
	g.Check()
}

func TestBlackboxIdentityCustomRoleGet(t *testing.T) {
	f := newFakeOkta(t)
	f.Fixture(http.MethodGet, `/api/v1/iam/roles/`+idnCRSupport, "identity_custom_role_get.json")
	srv := newServer(t, f, idnWithCustomRoles())
	g := newGolden(t, f)

	idnGet(t, g, srv, "custom-role", idnCRSupport)
	idnGet(t, g, srv, "custom-role", "cr0missing")
	g.Check()
}

func TestBlackboxIdentityCustomRoleDisabledByDefault(t *testing.T) {
	f := idnFake(t)
	srv := newServer(t, f)
	g := newGolden(t, f)

	resp, err := srv.ListResources(context.Background(), &v2.ResourcesServiceListResourcesRequest{ResourceTypeId: "custom-role", ActiveSyncId: testSyncID})
	g.Step("ListResources custom-role", stripSessionUsage(resp), err)
	g.Check()
}

// ---------------------------------------------------------------------------
// Grant / Revoke
// ---------------------------------------------------------------------------

func TestBlackboxIdentityGroupMembershipGrantRevoke(t *testing.T) {
	f := newFakeOkta(t)
	f.JSON(http.MethodPut, `/api/v1/groups/`+idnGroupEng+`/users/`+idnUserAlice, http.StatusNoContent, "")
	f.JSON(http.MethodDelete, `/api/v1/groups/`+idnGroupEng+`/users/`+idnUserAlice, http.StatusNoContent, "")
	srv := newServer(t, f)
	g := newGolden(t, f)

	ent := idnEnt(idnRes("group", idnGroupEng), "member")
	user := idnRes("user", idnUserAlice)
	idnGrant(t, g, srv, "group member", ent, user)
	idnRevoke(t, g, srv, "group member", ent, user)
	// Only users can be members.
	idnGrant(t, g, srv, "group principal", ent, idnRes("group", idnGroupAll))
	idnRevoke(t, g, srv, "group principal", ent, idnRes("group", idnGroupAll))
	g.Check()
}

func TestBlackboxIdentityGroupMembershipGrantErrors(t *testing.T) {
	f := newFakeOkta(t)
	f.JSON(http.MethodPut, `/api/v1/groups/00g400/users/`+idnUserAlice, http.StatusBadRequest, idnErr400)
	f.JSON(http.MethodPut, `/api/v1/groups/00g403/users/`+idnUserAlice, http.StatusForbidden, idnErr403)
	f.JSON(http.MethodPut, `/api/v1/groups/00g404/users/`+idnUserAlice, http.StatusNotFound, idnErr404)
	f.JSON(http.MethodPut, `/api/v1/groups/00g500/users/`+idnUserAlice, http.StatusInternalServerError, idnErr500)
	f.JSON(http.MethodPut, `/api/v1/groups/00g500e/users/`+idnUserAlice, http.StatusInternalServerError, "")
	srv := newServer(t, f)
	g := newGolden(t, f)

	user := idnRes("user", idnUserAlice)
	for _, id := range []string{"00g400", "00g403", "00g404", "00g500", "00g500e"} {
		idnGrant(t, g, srv, id, idnEnt(idnRes("group", id), "member"), user)
	}
	g.Check()
}

func TestBlackboxIdentityGroupMembershipRevokeErrors(t *testing.T) {
	f := newFakeOkta(t)
	f.JSON(http.MethodDelete, `/api/v1/groups/00g404/users/`+idnUserAlice, http.StatusNotFound, idnErr404)
	f.JSON(http.MethodDelete, `/api/v1/groups/00g400/users/`+idnUserAlice, http.StatusBadRequest, idnErr400)
	f.JSON(http.MethodDelete, `/api/v1/groups/00g403/users/`+idnUserAlice, http.StatusForbidden, idnErr403)
	f.JSON(http.MethodDelete, `/api/v1/groups/00g500/users/`+idnUserAlice, http.StatusInternalServerError, idnErr500)
	f.JSON(http.MethodDelete, `/api/v1/groups/00g500e/users/`+idnUserAlice, http.StatusInternalServerError, "")
	srv := newServer(t, f)
	g := newGolden(t, f)

	user := idnRes("user", idnUserAlice)
	for _, id := range []string{"00g404", "00g400", "00g403", "00g500", "00g500e"} {
		idnRevoke(t, g, srv, id, idnEnt(idnRes("group", id), "member"), user)
	}
	g.Check()
}

func TestBlackboxIdentityRoleGrantUser(t *testing.T) {
	f := newFakeOkta(t)
	f.Handle(http.MethodPost, `/api/v1/users/`+idnUserAlice+`/roles`, func(w http.ResponseWriter, r *http.Request, _ []string) {
		writeJSON(w, http.StatusOK, `{"id":"irbNEW00000000000001","label":"Help Desk Administrator","type":"HELP_DESK_ADMIN",`+
			`"status":"ACTIVE","created":"2024-01-01T00:00:00.000Z","lastUpdated":"2024-01-01T00:00:00.000Z","assignmentType":"USER"}`)
	})
	f.JSON(http.MethodPost, `/api/v1/users/`+idnUserBob+`/roles`, http.StatusBadRequest, idnErr090)
	f.JSON(http.MethodPost, `/api/v1/users/00u400/roles`, http.StatusBadRequest, idnErr400)
	f.JSON(http.MethodPost, `/api/v1/users/00u403/roles`, http.StatusForbidden, idnErr403)
	f.JSON(http.MethodPost, `/api/v1/users/00u500/roles`, http.StatusInternalServerError, idnErr500)
	f.JSON(http.MethodPost, `/api/v1/users/00u500e/roles`, http.StatusInternalServerError, "")
	srv := newServer(t, f)
	g := newGolden(t, f)

	ent := idnEnt(idnRes("role", "HELP_DESK_ADMIN"), "assigned")
	for _, id := range []string{idnUserAlice, idnUserBob, "00u400", "00u403", "00u500", "00u500e"} {
		idnGrant(t, g, srv, id, ent, idnRes("user", id))
	}
	g.Check()
}

// Group principals are advertised as grantable on role entitlements but the
// provisioner rejects them before any request is sent.
func TestBlackboxIdentityRoleGrantRevokeGroupPrincipal(t *testing.T) {
	f := newFakeOkta(t)
	f.Fixture(http.MethodGet, `/api/v1/groups/`+idnGroupEng+`/roles`, "identity_group_roles_revoke.json")
	f.JSON(http.MethodPost, `/api/v1/groups/`+idnGroupEng+`/roles`, http.StatusOK, `{"id":"irbG","type":"USER_ADMIN","status":"ACTIVE"}`)
	f.JSON(http.MethodDelete, `/api/v1/groups/`+idnGroupEng+`/roles/irb7777777777777777`, http.StatusNoContent, "")
	srv := newServer(t, f)
	g := newGolden(t, f)

	ent := idnEnt(idnRes("role", "USER_ADMIN"), "assigned")
	idnGrant(t, g, srv, "group principal", ent, idnRes("group", idnGroupEng))
	idnRevoke(t, g, srv, "group principal", ent, idnRes("group", idnGroupEng))
	require.Empty(t, f.Requests(), "group role operations are rejected before reaching the API")
	g.Check()
}

func TestBlackboxIdentityRoleRevokeUser(t *testing.T) {
	f := newFakeOkta(t)
	f.Fixture(http.MethodGet, `/api/v1/users/`+idnUserAlice+`/roles`, "identity_user_roles_revoke.json")
	f.JSON(http.MethodDelete, `/api/v1/users/`+idnUserAlice+`/roles/irbC000000000000001`, http.StatusNoContent, "")
	// Bob: role is listed but the delete races with another admin and 404s.
	f.Fixture(http.MethodGet, `/api/v1/users/`+idnUserBob+`/roles`, "identity_user_roles_revoke.json")
	f.JSON(http.MethodDelete, `/api/v1/users/`+idnUserBob+`/roles/irbC000000000000001`, http.StatusNotFound, idnErr404)
	// Carol: listing the roles fails.
	f.JSON(http.MethodGet, `/api/v1/users/00uaa3333333333333a3/roles`, http.StatusForbidden, idnErr403)
	// Dave: delete fails with 500.
	f.Fixture(http.MethodGet, `/api/v1/users/00uaa4444444444444a4/roles`, "identity_user_roles_revoke.json")
	f.JSON(http.MethodDelete, `/api/v1/users/00uaa4444444444444a4/roles/irbC000000000000001`, http.StatusInternalServerError, idnErr500)
	// Erin: delete is forbidden.
	f.Fixture(http.MethodGet, `/api/v1/users/00uaa5555555555555a5/roles`, "identity_user_roles_revoke.json")
	f.JSON(http.MethodDelete, `/api/v1/users/00uaa5555555555555a5/roles/irbC000000000000001`, http.StatusForbidden, idnErr403)
	srv := newServer(t, f)
	g := newGolden(t, f)

	ent := idnEnt(idnRes("role", "READ_ONLY_ADMIN"), "assigned")
	for _, id := range []string{idnUserAlice, idnUserBob, "00uaa3333333333333a3", "00uaa4444444444444a4", "00uaa5555555555555a5"} {
		idnRevoke(t, g, srv, id, ent, idnRes("user", id))
	}
	// SUPER_ADMIN is only INACTIVE on Alice, and APP_ADMIN is not assigned at all.
	idnRevoke(t, g, srv, "inactive-role", idnEnt(idnRes("role", "SUPER_ADMIN"), "assigned"), idnRes("user", idnUserAlice))
	idnRevoke(t, g, srv, "unassigned-role", idnEnt(idnRes("role", "APP_ADMIN"), "assigned"), idnRes("user", idnUserAlice))
	g.Check()
}

// Custom roles have no provisioner.
func TestBlackboxIdentityCustomRoleGrantRevokeUnsupported(t *testing.T) {
	f := newFakeOkta(t)
	srv := newServer(t, f, idnWithCustomRoles())
	g := newGolden(t, f)

	ent := idnEnt(idnRes("custom-role", idnCRSupport), "assigned")
	idnGrant(t, g, srv, "custom role user", ent, idnRes("user", idnUserAlice))
	idnRevoke(t, g, srv, "custom role user", ent, idnRes("user", idnUserAlice))
	g.Check()
}

// ---------------------------------------------------------------------------
// Error classification on list calls
// ---------------------------------------------------------------------------

func TestBlackboxIdentityListErrors(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"401_E0000011", http.StatusUnauthorized, idnErr401},
		{"403_E0000006", http.StatusForbidden, idnErr403},
		{"404_E0000007", http.StatusNotFound, idnErr404},
		{"400_validation", http.StatusBadRequest, idnErr400},
		{"500_json_body", http.StatusInternalServerError, idnErr500},
		{"500_empty_body", http.StatusInternalServerError, ""},
		{"500_html_body", http.StatusInternalServerError, "<html><body>Internal Server Error</body></html>"},
		{"502_empty_body", http.StatusBadGateway, ""},
		{"403_unparseable_body", http.StatusForbidden, "not json"},
	}
	// Each resource type that lists from Okta, and the path it lists from.
	types := []struct {
		rt, path string
		mods     []connOpt
	}{
		{"user", "/api/v1/users", nil},
		{"group", "/api/v1/groups", nil},
		{"custom-role", "/api/v1/iam/roles", []connOpt{idnWithCustomRoles()}},
	}
	for _, rtc := range types {
		for _, c := range cases {
			t.Run(rtc.rt+"_"+c.name, func(t *testing.T) {
				f := newFakeOkta(t)
				f.JSON(http.MethodGet, rtc.path, c.status, c.body)
				srv := newServer(t, f, rtc.mods...)
				g := newGolden(t, f)

				listAllResources(t, g, srv, rtc.rt, nil, 50)
				g.Check()
			})
		}
	}
}

func TestBlackboxIdentityListErrorsGrants(t *testing.T) {
	for _, c := range []struct {
		name   string
		status int
		body   string
	}{
		{"401", http.StatusUnauthorized, idnErr401},
		{"500_json", http.StatusInternalServerError, idnErr500},
		{"500_empty", http.StatusInternalServerError, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeOkta(t)
			f.JSON(http.MethodGet, "/api/v1/iam/assignees/users", c.status, c.body)
			f.JSON(http.MethodGet, `/api/v1/groups/[^/]+/users`, c.status, c.body)
			srv := newServer(t, f)
			g := newGolden(t, f)

			listAllGrants(t, g, srv, idnRes("role", "SUPER_ADMIN"), 100)
			listAllGrants(t, g, srv, idnRes("group", idnGroupEng), 100)
			g.Check()
		})
	}
}

// idnRateLimitOnce answers the first request to the route with a 429 carrying
// valid reset headers, then serves the fixture.
func idnRateLimitOnce(f *fakeOkta, path, fixtureBody string) {
	calls := 0
	f.Handle(http.MethodGet, path, func(w http.ResponseWriter, r *http.Request, _ []string) {
		calls++
		if calls == 1 {
			now := time.Now()
			w.Header().Set("Date", now.UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))
			w.Header().Set("X-Rate-Limit-Reset", strconv.FormatInt(now.Unix(), 10))
			w.Header().Set("X-Rate-Limit-Limit", "600")
			w.Header().Set("X-Rate-Limit-Remaining", "0")
			writeJSON(w, http.StatusTooManyRequests, `{"errorCode":"E0000047","errorSummary":"API call exceeded rate limit due to too many requests.",`+
				`"errorLink":"E0000047","errorId":"oaeRate0001","errorCauses":[]}`)
			return
		}
		writeJSON(w, http.StatusOK, fixtureBody)
	})
}

func TestBlackboxIdentityUserListRateLimitRecovers(t *testing.T) {
	f := newFakeOkta(t)
	idnRateLimitOnce(f, "/api/v1/users", fixture(t, "identity_users_page3.json"))
	srv := newServer(t, f)
	g := newGolden(t, f)

	require.Len(t, listAllResources(t, g, srv, "user", nil, 50), 2)
	g.Check()
}

func TestBlackboxIdentityGroupListRateLimitRecovers(t *testing.T) {
	f := newFakeOkta(t)
	idnRateLimitOnce(f, "/api/v1/groups", fixture(t, "identity_groups_page1.json"))
	srv := newServer(t, f)
	g := newGolden(t, f)

	require.Len(t, listAllResources(t, g, srv, "group", nil, 50), 2)
	g.Check()
}

func TestBlackboxIdentityGroupMembersRateLimitRecovers(t *testing.T) {
	f := idnFake(t)
	idnRateLimitOnce(f, `/api/v1/groups/`+idnGroupEng+`/users`, fixture(t, "identity_group_users_page1.json"))
	f.Fixture(http.MethodGet, `/api/v1/groups/[^/]+/roles`, "identity_group_roles.json")
	srv := newServer(t, f)
	g := newGolden(t, f)

	listAllGrants(t, g, srv, idnRes("group", idnGroupEng), 100)
	g.Check()
}

// ---------------------------------------------------------------------------
// Private-key (OAuth + DPoP) auth: one List per resource type
// ---------------------------------------------------------------------------

func TestBlackboxIdentityPrivateKeyList(t *testing.T) {
	for _, rt := range []string{"user", "group", "role", "custom-role"} {
		t.Run(rt, func(t *testing.T) {
			f := idnFake(t)
			mods := []connOpt{privateKeyConn(t, f)}
			if rt == "custom-role" {
				mods = append(mods, idnWithCustomRoles())
			}
			srv := newServer(t, f, mods...)
			g := newGolden(t, f)

			require.NotEmpty(t, listAllResources(t, g, srv, rt, nil, 100))
			g.Check()
		})
	}
}

// A membership grant whose connection keeps dropping mid-response is sent
// three times and then fails as Unavailable, so the provisioner retries it.
func TestBlackboxIdentityGroupGrantDroppedConnection(t *testing.T) {
	f := idnFake(t)
	f.Handle(http.MethodPut, `/api/v1/groups/`+idnGroupEng+`/users/`+idnUserAlice, func(w http.ResponseWriter, r *http.Request, _ []string) {
		conn, _, err := w.(http.Hijacker).Hijack()
		require.NoError(t, err)
		_ = conn.Close()
	})
	srv := newServer(t, f)
	ctx, cancel := idnProvisionCtx()
	defer cancel()
	_, err := srv.Grant(ctx, &v2.GrantManagerServiceGrantRequest{
		Entitlement: idnEnt(idnRes("group", idnGroupEng), "member"),
		Principal:   idnRes("user", idnUserAlice),
	})
	require.Equal(t, codes.Unavailable, status.Code(err), "%v", err)
	require.ErrorContains(t, err, "network error")
	n := 0
	for _, r := range f.Requests() {
		if r.Method == http.MethodPut {
			n++
		}
	}
	require.Equal(t, 3, n)
}
