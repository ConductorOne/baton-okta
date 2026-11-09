package connector

import (
	"context"
	"errors"
	"net/http"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	sdkResource "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/conductorone/baton-sdk/pkg/types/sessions"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	testRoleAssignmentID = "ra1abc2def3GHI4jk5"
	testTargetGroupA     = "00gTargetA"
	testTargetGroupB     = "00gTargetB"
)

func testScopeConnector(client *okta.Client) *Okta {
	return &Okta{client: client, syncAdminRoleScopes: true}
}

func userRolesPath() string {
	return "/api/v1/users/" + testOktaUserID + "/roles"
}

func userRoleTargetsPath(kind string) string {
	if kind == roleTargetKindApp {
		return userRolesPath() + "/" + testRoleAssignmentID + "/targets/catalog/apps"
	}
	return userRolesPath() + "/" + testRoleAssignmentID + "/targets/groups"
}

func mustScopedRole(t *testing.T, roleType string) scopedRoleType {
	t.Helper()
	sr, ok := scopedRoleFromType(roleType)
	if !ok {
		t.Fatalf("%s is not a scoped role type", roleType)
	}
	return sr
}

func grantEntitlementIDs(grants []*v2.Grant) []string {
	ids := make([]string, 0, len(grants))
	for _, g := range grants {
		ids = append(ids, g.GetEntitlement().GetId())
	}
	return ids
}

func assertEntitlementIDs(t *testing.T, grants []*v2.Grant, want ...string) {
	t.Helper()
	got := grantEntitlementIDs(grants)
	if len(got) != len(want) {
		t.Fatalf("grant entitlements = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("grant entitlements = %v, want %v", got, want)
		}
	}
}

func TestRoleScopeGrants_EntireOrganization(t *testing.T) {
	client := newScriptedOktaClient(t,
		oktaRequestStep{method: http.MethodGet, path: userRoleTargetsPath(roleTargetKindApp), statusCode: http.StatusOK, body: `[]`},
	)

	grants, err := testScopeConnector(client).roleScopeGrants(t.Context(), nil,
		rolePrincipal{resourceType: resourceTypeUser.Id, id: testOktaUserID}, testRoleAssignmentID, mustScopedRole(t, "APP_ADMIN"))
	if err != nil {
		t.Fatalf("roleScopeGrants() error: %v", err)
	}
	assertEntitlementIDs(t, grants, "role:APP_ADMIN:entire-organization")
	if got := grants[0].GetPrincipal().GetId().GetResource(); got != testOktaUserID {
		t.Fatalf("principal = %q, want %q", got, testOktaUserID)
	}
}

func TestRoleScopeGrants_GroupTargetsArePaginated(t *testing.T) {
	client := newScriptedOktaClient(t,
		oktaRequestStep{
			method:     http.MethodGet,
			path:       userRoleTargetsPath(roleTargetKindGroup),
			statusCode: http.StatusOK,
			headers:    map[string]string{"Link": `<https://example.okta.com` + userRoleTargetsPath(roleTargetKindGroup) + `?after=` + testTargetGroupA + `>; rel="next"`},
			body:       `[{"id":"` + testTargetGroupA + `"}]`,
		},
		oktaRequestStep{
			method:     http.MethodGet,
			path:       userRoleTargetsPath(roleTargetKindGroup),
			query:      map[string]string{"after": testTargetGroupA},
			statusCode: http.StatusOK,
			body:       `[{"id":"` + testTargetGroupB + `"}]`,
		},
	)

	grants, err := testScopeConnector(client).roleScopeGrants(t.Context(), nil,
		rolePrincipal{resourceType: resourceTypeUser.Id, id: testOktaUserID}, testRoleAssignmentID, mustScopedRole(t, "USER_ADMIN"))
	if err != nil {
		t.Fatalf("roleScopeGrants() error: %v", err)
	}
	assertEntitlementIDs(t, grants,
		"group:"+testTargetGroupA+":group-admin",
		"group:"+testTargetGroupB+":group-admin",
	)
}

func TestRoleScopeGrants_AppTargetsExpandCatalogApps(t *testing.T) {
	client := newScriptedOktaClient(t,
		oktaRequestStep{
			method:     http.MethodGet,
			path:       userRoleTargetsPath(roleTargetKindApp),
			statusCode: http.StatusOK,
			// An app instance target, then an OIN catalog target covering every instance.
			body: `[{"id":"0oaInstance1","name":"salesforce"},{"name":"salesforce"}]`,
		},
		oktaRequestStep{
			method:     http.MethodGet,
			path:       "/api/v1/apps",
			query:      map[string]string{"filter": `name eq "salesforce"`},
			statusCode: http.StatusOK,
			body: `[{"id":"0oaInstance1","name":"salesforce","status":"ACTIVE"},
				{"id":"0oaInstance2","name":"salesforce","status":"ACTIVE"},
				{"id":"0oaInactive","name":"salesforce","status":"INACTIVE"}]`,
		},
	)

	grants, err := testScopeConnector(client).roleScopeGrants(t.Context(), nil,
		rolePrincipal{resourceType: resourceTypeUser.Id, id: testOktaUserID}, testRoleAssignmentID, mustScopedRole(t, "APP_ADMIN"))
	if err != nil {
		t.Fatalf("roleScopeGrants() error: %v", err)
	}
	assertEntitlementIDs(t, grants,
		"app:0oaInstance1:app-admin",
		"app:0oaInstance2:app-admin",
	)
}

func TestRoleScopeGrants_GroupPrincipalExpandsToMembers(t *testing.T) {
	client := newScriptedOktaClient(t,
		oktaRequestStep{
			method:     http.MethodGet,
			path:       "/api/v1/groups/" + testGroupID + "/roles/" + testRoleAssignmentID + "/targets/groups",
			statusCode: http.StatusOK,
			body:       `[{"id":"` + testTargetGroupA + `"}]`,
		},
	)

	grants, err := testScopeConnector(client).roleScopeGrants(t.Context(), nil,
		rolePrincipal{resourceType: resourceTypeGroup.Id, id: testGroupID}, testRoleAssignmentID, mustScopedRole(t, "HELP_DESK_ADMIN"),
		roleGroupScopeGrantOpts(testGroupID, true)...)
	if err != nil {
		t.Fatalf("roleScopeGrants() error: %v", err)
	}
	assertEntitlementIDs(t, grants, "group:"+testTargetGroupA+":help-desk-admin")

	expandable := &v2.GrantExpandable{}
	grantAnnos := annotations.Annotations(grants[0].GetAnnotations())
	ok, err := grantAnnos.Pick(expandable)
	if err != nil || !ok {
		t.Fatalf("grant is missing GrantExpandable: ok=%v err=%v", ok, err)
	}
	if want := "group:" + testGroupID + ":member"; len(expandable.GetEntitlementIds()) != 1 || expandable.GetEntitlementIds()[0] != want {
		t.Fatalf("GrantExpandable entitlements = %v, want [%s]", expandable.GetEntitlementIds(), want)
	}
}

func TestRoleScopeEntitlements(t *testing.T) {
	groupRes := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeGroup.Id, Resource: testTargetGroupA}, DisplayName: "Engineering"}

	t.Run("groups get one entitlement per group-scoped role only when enabled", func(t *testing.T) {
		for _, enabled := range []bool{false, true} {
			o := groupBuilder(&Okta{syncAdminRoleScopes: enabled})
			ents, _, err := o.Entitlements(t.Context(), groupRes, sdkResource.SyncOpAttrs{})
			if err != nil {
				t.Fatalf("Entitlements() error: %v", err)
			}
			want := 1
			if enabled {
				want = 4
			}
			if len(ents) != want {
				t.Fatalf("enabled=%v: got %d entitlements, want %d", enabled, len(ents), want)
			}
		}
	})

	t.Run("group entitlement names the role and group", func(t *testing.T) {
		ents := roleScopeTargetEntitlements(groupRes, roleTargetKindGroup)
		if got, want := ents[0].GetDisplayName(), "Engineering Group Administrator"; got != want {
			t.Fatalf("display name = %q, want %q", got, want)
		}
		if got, want := ents[0].GetId(), "group:"+testTargetGroupA+":group-admin"; got != want {
			t.Fatalf("id = %q, want %q", got, want)
		}
	})

	t.Run("only scopable roles get the entire-organization entitlement", func(t *testing.T) {
		o := roleBuilder(nil, &Okta{syncAdminRoleScopes: true})
		for roleType, want := range map[string]int{"APP_ADMIN": 2, "USER_ADMIN": 2, "SUPER_ADMIN": 1} {
			role := standardRoleFromType(roleType)
			res, err := roleResource(role, resourceTypeRole)
			if err != nil {
				t.Fatal(err)
			}
			ents, _, err := o.Entitlements(t.Context(), res, sdkResource.SyncOpAttrs{})
			if err != nil {
				t.Fatalf("Entitlements() error: %v", err)
			}
			if len(ents) != want {
				t.Fatalf("%s: got %d entitlements, want %d", roleType, len(ents), want)
			}
		}
	})
}

func TestRoleScopeEntitlementMatching(t *testing.T) {
	groupRes := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeGroup.Id, Resource: testGroupID}}
	roleRes := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeRole.Id, Resource: "APP_ADMIN"}}

	tests := []struct {
		name       string
		e          *v2.Entitlement
		wantTarget bool
		wantOrg    bool
	}{
		{name: "membership by id", e: &v2.Entitlement{Resource: groupRes, Id: "group:" + testGroupID + ":member", Slug: "member"}},
		{name: "membership with no id or slug", e: groupMembershipEntitlement()},
		{name: "scope target by id", e: &v2.Entitlement{Resource: groupRes, Id: "group:" + testGroupID + ":group-admin"}, wantTarget: true},
		{name: "scope target by slug only", e: &v2.Entitlement{Resource: groupRes, Slug: "group-admin"}, wantTarget: true},
		// C1 lets admins edit slugs; the connector ID must still win.
		{name: "scope target with edited slug", e: &v2.Entitlement{Resource: groupRes, Id: "group:" + testGroupID + ":group-admin", Slug: "Group Admin"}, wantTarget: true},
		{name: "entire org by id", e: &v2.Entitlement{Resource: roleRes, Id: "role:APP_ADMIN:entire-organization"}, wantOrg: true},
		{name: "entire org with edited slug", e: &v2.Entitlement{Resource: roleRes, Id: "role:APP_ADMIN:entire-organization", Slug: "Org-wide"}, wantOrg: true},
		{name: "assigned with slug edited to look like entire org", e: &v2.Entitlement{Resource: roleRes, Id: "role:APP_ADMIN:assigned", Slug: "entire-organization"}},
		{name: "entire org by slug only", e: &v2.Entitlement{Resource: roleRes, Slug: "entire-organization"}, wantOrg: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRoleScopeTargetEntitlement(tc.e); got != tc.wantTarget {
				t.Errorf("isRoleScopeTargetEntitlement = %v, want %v", got, tc.wantTarget)
			}
			if got := isEntireOrgEntitlement(tc.e); got != tc.wantOrg {
				t.Errorf("isEntireOrgEntitlement = %v, want %v", got, tc.wantOrg)
			}
		})
	}
}

func TestRoleScopeTargetEntitlementsAreNotProvisionable(t *testing.T) {
	// No scripted requests: rejecting must happen before any Okta call, or a
	// revoke of "Engineering Group Administrator" would remove group membership.
	groupEnt := &v2.Entitlement{
		Resource: &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeGroup.Id, Resource: testGroupID}},
		Id:       "group:" + testGroupID + ":group-admin",
	}
	appEnt := &v2.Entitlement{
		Resource: &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeApp.Id, Resource: testAppID}},
		Id:       "app:" + testAppID + ":app-admin",
		Slug:     "Edited by an admin",
	}
	client := newScriptedOktaClient(t)
	gb := groupBuilder(&Okta{client: client})
	ab := newTestAppBuilder(client)

	checks := map[string]error{}
	_, checks["group grant"] = gb.Grant(t.Context(), testUserPrincipal(), groupEnt)
	_, checks["group revoke"] = gb.Revoke(t.Context(), &v2.Grant{Entitlement: groupEnt, Principal: testUserPrincipal()})
	_, checks["app grant"] = ab.Grant(t.Context(), testUserPrincipal(), appEnt)
	_, checks["app revoke"] = ab.Revoke(t.Context(), &v2.Grant{Entitlement: appEnt, Principal: testUserPrincipal()})
	_, checks["group revoke for group principal"] = gb.Revoke(t.Context(), &v2.Grant{Entitlement: groupEnt, Principal: appGroupPrincipal()})
	rb := roleBuilder(client, testScopeConnector(client))
	_, checks["entire org revoke for group principal"] = rb.Revoke(t.Context(), &v2.Grant{Entitlement: entireOrgEntitlement("APP_ADMIN"), Principal: appGroupPrincipal()})
	_, checks["entire org grant for group principal"] = rb.Grant(t.Context(), appGroupPrincipal(), entireOrgEntitlement("APP_ADMIN"))
	for name, err := range checks {
		if status.Code(err) != codes.Unimplemented {
			t.Errorf("%s: code = %v (%v), want Unimplemented", name, status.Code(err), err)
		}
	}
}

func entireOrgEntitlement(roleType string) *v2.Entitlement {
	return &v2.Entitlement{
		Resource: &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeRole.Id, Resource: roleType}},
		Id:       "role:" + roleType + ":entire-organization",
	}
}

func userAppAdminRolesBody() string {
	return `[{"id":"` + testRoleAssignmentID + `","type":"APP_ADMIN","status":"ACTIVE","assignmentType":"USER"}]`
}

func TestRoleRevokeEntireOrganization(t *testing.T) {
	t.Run("removes an assignment with no targets", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{method: http.MethodGet, path: userRolesPath(), statusCode: http.StatusOK, body: userAppAdminRolesBody()},
			oktaRequestStep{method: http.MethodGet, path: userRoleTargetsPath(roleTargetKindApp), statusCode: http.StatusOK, body: `[]`},
			oktaRequestStep{method: http.MethodDelete, path: userRolesPath() + "/" + testRoleAssignmentID, statusCode: http.StatusNoContent},
		)
		annos, err := roleBuilder(client, testScopeConnector(client)).Revoke(t.Context(),
			&v2.Grant{Entitlement: entireOrgEntitlement("APP_ADMIN"), Principal: testUserPrincipal()})
		if err != nil {
			t.Fatalf("Revoke() error: %v", err)
		}
		if annos.Contains(&v2.GrantAlreadyRevoked{}) {
			t.Fatalf("Revoke() reported GrantAlreadyRevoked for an entire-organization assignment")
		}
	})

	t.Run("leaves an assignment narrowed to specific apps", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{method: http.MethodGet, path: userRolesPath(), statusCode: http.StatusOK, body: userAppAdminRolesBody()},
			oktaRequestStep{method: http.MethodGet, path: userRoleTargetsPath(roleTargetKindApp), statusCode: http.StatusOK, body: `[{"id":"0oaInstance1","name":"salesforce"}]`},
		)
		annos, err := roleBuilder(client, testScopeConnector(client)).Revoke(t.Context(),
			&v2.Grant{Entitlement: entireOrgEntitlement("APP_ADMIN"), Principal: testUserPrincipal()})
		if err != nil {
			t.Fatalf("Revoke() error: %v", err)
		}
		if !annos.Contains(&v2.GrantAlreadyRevoked{}) {
			t.Fatalf("Revoke() annotations = %v, want GrantAlreadyRevoked", annos)
		}
	})
}

func TestRoleGrantEntireOrganization_ExistingScopedAssignment(t *testing.T) {
	client := newScriptedOktaClient(t,
		oktaRequestStep{
			method:     http.MethodPost,
			path:       userRolesPath(),
			statusCode: http.StatusBadRequest,
			body:       `{"errorCode":"E0000090","errorSummary":"You have specified a role that is already assigned to the user"}`,
		},
		oktaRequestStep{method: http.MethodGet, path: userRolesPath(), statusCode: http.StatusOK, body: userAppAdminRolesBody()},
		oktaRequestStep{method: http.MethodGet, path: userRoleTargetsPath(roleTargetKindApp), statusCode: http.StatusOK, body: `[{"id":"0oaInstance1","name":"salesforce"}]`},
	)
	_, err := roleBuilder(client, testScopeConnector(client)).Grant(t.Context(), testUserPrincipal(), entireOrgEntitlement("APP_ADMIN"))
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("Grant() code = %v (%v), want FailedPrecondition", status.Code(err), err)
	}
}

func TestRoleRevokeEntireOrganization_TargetsNotFound(t *testing.T) {
	steps := func(rolesAfter string) []oktaRequestStep {
		return []oktaRequestStep{
			{method: http.MethodGet, path: userRolesPath(), statusCode: http.StatusOK, body: userAppAdminRolesBody()},
			{method: http.MethodGet, path: userRoleTargetsPath(roleTargetKindApp), statusCode: http.StatusNotFound, body: oktaNotFoundResponse()},
			{method: http.MethodGet, path: userRolesPath(), statusCode: http.StatusOK, body: rolesAfter},
		}
	}
	grant := &v2.Grant{Entitlement: entireOrgEntitlement("APP_ADMIN"), Principal: testUserPrincipal()}

	t.Run("assignment gone is already revoked", func(t *testing.T) {
		client := newScriptedOktaClient(t, steps(`[]`)...)
		annos, err := roleBuilder(client, testScopeConnector(client)).Revoke(t.Context(), grant)
		if err != nil {
			t.Fatalf("Revoke() error: %v", err)
		}
		if !annos.Contains(&v2.GrantAlreadyRevoked{}) {
			t.Fatalf("Revoke() annotations = %v, want GrantAlreadyRevoked", annos)
		}
	})

	t.Run("assignment still present is an error", func(t *testing.T) {
		client := newScriptedOktaClient(t, steps(userAppAdminRolesBody())...)
		_, err := roleBuilder(client, testScopeConnector(client)).Revoke(t.Context(), grant)
		if status.Code(err) != codes.NotFound {
			t.Fatalf("Revoke() code = %v (%v), want NotFound", status.Code(err), err)
		}
	})
}

func TestRoleRevokeEntireOrganization_IgnoresGroupInheritedAssignment(t *testing.T) {
	// Only a group-inherited assignment exists, so there is no direct
	// assignment to remove and no targets call to make.
	client := newScriptedOktaClient(t,
		oktaRequestStep{method: http.MethodGet, path: userRolesPath(), statusCode: http.StatusOK,
			body: `[{"id":"raInherited","type":"APP_ADMIN","status":"ACTIVE","assignmentType":"GROUP"}]`},
	)
	annos, err := roleBuilder(client, testScopeConnector(client)).Revoke(t.Context(),
		&v2.Grant{Entitlement: entireOrgEntitlement("APP_ADMIN"), Principal: testUserPrincipal()})
	if err != nil {
		t.Fatalf("Revoke() error: %v", err)
	}
	if !annos.Contains(&v2.GrantAlreadyRevoked{}) {
		t.Fatalf("Revoke() annotations = %v, want GrantAlreadyRevoked", annos)
	}
}

func TestRoleScopeGrants_TargetsNotFound(t *testing.T) {
	targets404 := oktaRequestStep{method: http.MethodGet, path: userRoleTargetsPath(roleTargetKindGroup), statusCode: http.StatusNotFound, body: oktaNotFoundResponse()}

	t.Run("assignment removed mid-sync emits nothing", func(t *testing.T) {
		client := newScriptedOktaClient(t, targets404,
			oktaRequestStep{method: http.MethodGet, path: userRolesPath(), statusCode: http.StatusOK, body: `[]`},
		)
		grants, err := testScopeConnector(client).roleScopeGrants(t.Context(), nil,
			rolePrincipal{resourceType: resourceTypeUser.Id, id: testOktaUserID}, testRoleAssignmentID, mustScopedRole(t, "USER_ADMIN"))
		if err != nil {
			t.Fatalf("roleScopeGrants() error: %v", err)
		}
		if len(grants) != 0 {
			t.Fatalf("got %d grants, want none", len(grants))
		}
	})

	// A 404 while the assignment still exists means the path itself is
	// unavailable; skipping it would silently drop every assignment's scope.
	t.Run("assignment still present fails loudly", func(t *testing.T) {
		client := newScriptedOktaClient(t, targets404,
			oktaRequestStep{method: http.MethodGet, path: userRolesPath(), statusCode: http.StatusOK,
				body: `[{"id":"` + testRoleAssignmentID + `","type":"USER_ADMIN","status":"ACTIVE","assignmentType":"USER"}]`},
		)
		_, err := testScopeConnector(client).roleScopeGrants(t.Context(), nil,
			rolePrincipal{resourceType: resourceTypeUser.Id, id: testOktaUserID}, testRoleAssignmentID, mustScopedRole(t, "USER_ADMIN"))
		if status.Code(err) != codes.NotFound {
			t.Fatalf("roleScopeGrants() code = %v (%v), want NotFound", status.Code(err), err)
		}
	})
}

func TestGroupGrants_AdminRoleScopes(t *testing.T) {
	groupRolesPath := "/api/v1/groups/" + testGroupID + "/roles"
	client := newScriptedOktaClient(t,
		// First page: the user phase.
		oktaRequestStep{method: http.MethodGet, path: "/api/v1/groups/" + testGroupID + "/users", statusCode: http.StatusOK, body: `[]`},
		// Second page: the role phase.
		oktaRequestStep{method: http.MethodGet, path: groupRolesPath, statusCode: http.StatusOK,
			body: `[{"id":"` + testRoleAssignmentID + `","type":"HELP_DESK_ADMIN","label":"Help Desk Administrator","status":"ACTIVE","assignmentType":"GROUP"}]`},
		oktaRequestStep{method: http.MethodGet, path: groupRolesPath + "/" + testRoleAssignmentID + "/targets/groups", statusCode: http.StatusOK,
			body: `[{"id":"` + testTargetGroupA + `"}]`},
	)
	gb := groupBuilder(&Okta{client: client, userFilters: &userFilterConfig{}, syncAdminRoleScopes: true})
	res := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeGroup.Id, Resource: testGroupID}}
	ss := newMemorySessionStore()

	_, results, err := gb.Grants(t.Context(), res, sdkResource.SyncOpAttrs{Session: ss})
	if err != nil {
		t.Fatalf("Grants() user phase error: %v", err)
	}
	grants, _, err := gb.Grants(t.Context(), res, sdkResource.SyncOpAttrs{Session: ss, PageToken: pagination.Token{Token: results.NextPageToken}})
	if err != nil {
		t.Fatalf("Grants() role phase error: %v", err)
	}
	assertEntitlementIDs(t, grants, "role:HELP_DESK_ADMIN:assigned", "group:"+testTargetGroupA+":help-desk-admin")
	for _, g := range grants {
		if got := g.GetPrincipal().GetId().GetResource(); got != testGroupID {
			t.Errorf("%s principal = %q, want group %q", g.GetEntitlement().GetId(), got, testGroupID)
		}
		expandable := &v2.GrantExpandable{}
		grantAnnos := annotations.Annotations(g.GetAnnotations())
		if ok, _ := grantAnnos.Pick(expandable); !ok {
			t.Errorf("%s is missing GrantExpandable to the group's members", g.GetEntitlement().GetId())
		}
	}
}

func TestRoleScopeGrants_SkipsUnsyncedAppGroups(t *testing.T) {
	client := newScriptedOktaClient(t,
		oktaRequestStep{method: http.MethodGet, path: userRoleTargetsPath(roleTargetKindGroup), statusCode: http.StatusOK,
			body: `[{"id":"` + testTargetGroupA + `","type":"APP_GROUP"},{"id":"` + testTargetGroupB + `","type":"OKTA_GROUP"}]`},
	)
	o := testScopeConnector(client)
	o.skipAppGroups = true
	grants, err := o.roleScopeGrants(t.Context(), nil,
		rolePrincipal{resourceType: resourceTypeUser.Id, id: testOktaUserID}, testRoleAssignmentID, mustScopedRole(t, "USER_ADMIN"))
	if err != nil {
		t.Fatalf("roleScopeGrants() error: %v", err)
	}
	assertEntitlementIDs(t, grants, "group:"+testTargetGroupB+":group-admin")
}

// memorySessionStore is a minimal sessions.SessionStore for exercising the
// connector's per-sync caches.
type memorySessionStore struct {
	data map[string][]byte
}

func newMemorySessionStore() *memorySessionStore {
	return &memorySessionStore{data: make(map[string][]byte)}
}

func sessionKey(ctx context.Context, key string, opts []sessions.SessionStoreOption) string {
	bag := &sessions.SessionStoreBag{}
	for _, opt := range opts {
		_ = opt(ctx, bag)
	}
	return bag.Prefix + "/" + key
}

func (m *memorySessionStore) Get(ctx context.Context, key string, opt ...sessions.SessionStoreOption) ([]byte, bool, error) {
	v, ok := m.data[sessionKey(ctx, key, opt)]
	return v, ok, nil
}

func (m *memorySessionStore) GetMany(ctx context.Context, keys []string, opt ...sessions.SessionStoreOption) (map[string][]byte, []string, error) {
	found := make(map[string][]byte)
	var missing []string
	for _, k := range keys {
		if v, ok := m.data[sessionKey(ctx, k, opt)]; ok {
			found[k] = v
		} else {
			missing = append(missing, k)
		}
	}
	return found, missing, nil
}

func (m *memorySessionStore) Set(ctx context.Context, key string, value []byte, opt ...sessions.SessionStoreOption) error {
	m.data[sessionKey(ctx, key, opt)] = value
	return nil
}

func (m *memorySessionStore) SetMany(ctx context.Context, values map[string][]byte, opt ...sessions.SessionStoreOption) error {
	for k, v := range values {
		m.data[sessionKey(ctx, k, opt)] = v
	}
	return nil
}

func (m *memorySessionStore) Delete(ctx context.Context, key string, opt ...sessions.SessionStoreOption) error {
	delete(m.data, sessionKey(ctx, key, opt))
	return nil
}

func (m *memorySessionStore) Clear(context.Context, ...sessions.SessionStoreOption) error {
	m.data = make(map[string][]byte)
	return nil
}

func (m *memorySessionStore) GetAll(context.Context, string, ...sessions.SessionStoreOption) (map[string][]byte, string, error) {
	return m.data, "", nil
}

func roleGrantsFor(t *testing.T, rb *roleResourceType, ss sessions.SessionStore, roleType string) []*v2.Grant {
	t.Helper()
	res, err := roleResource(standardRoleFromType(roleType), resourceTypeRole)
	if err != nil {
		t.Fatal(err)
	}
	grants, _, err := rb.Grants(t.Context(), res, sdkResource.SyncOpAttrs{Session: ss})
	if err != nil {
		t.Fatalf("Grants(%s) error: %v", roleType, err)
	}
	return grants
}

func TestRoleGrants_AdminRoleScopes(t *testing.T) {
	assignees := oktaRequestStep{method: http.MethodGet, path: apiPathListAllUsersWithRoleAssignments, statusCode: http.StatusOK,
		body: `{"value":[{"id":"` + testOktaUserID + `"}]}`}
	userRoles := oktaRequestStep{method: http.MethodGet, path: userRolesPath(), statusCode: http.StatusOK,
		body: `[{"id":"` + testRoleAssignmentID + `","type":"USER_ADMIN","status":"ACTIVE","assignmentType":"USER"},
			{"id":"raOther","type":"APP_ADMIN","status":"ACTIVE","assignmentType":"USER"}]`}

	t.Run("flag off makes no targets calls", func(t *testing.T) {
		client := newScriptedOktaClient(t, assignees, userRoles)
		o := &Okta{client: client, userFilters: &userFilterConfig{}}
		grants := roleGrantsFor(t, roleBuilder(client, o), newMemorySessionStore(), "USER_ADMIN")
		assertEntitlementIDs(t, grants, "role:USER_ADMIN:assigned")
	})

	t.Run("flag on emits scope grants and reuses cached assignments", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			assignees, userRoles,
			oktaRequestStep{method: http.MethodGet, path: userRoleTargetsPath(roleTargetKindGroup), statusCode: http.StatusOK,
				body: `[{"id":"` + testTargetGroupA + `"}]`},
			// Second role resource: the assignee list comes from the Okta client's
			// response cache, and roles and assignment IDs from the session cache.
			oktaRequestStep{method: http.MethodGet, path: userRolesPath() + "/raOther/targets/catalog/apps", statusCode: http.StatusOK, body: `[]`},
		)
		o := &Okta{client: client, userFilters: &userFilterConfig{}, syncAdminRoleScopes: true}
		rb := roleBuilder(client, o)
		ss := newMemorySessionStore()

		assertEntitlementIDs(t, roleGrantsFor(t, rb, ss, "USER_ADMIN"),
			"role:USER_ADMIN:assigned", "group:"+testTargetGroupA+":group-admin")
		assertEntitlementIDs(t, roleGrantsFor(t, rb, ss, "APP_ADMIN"),
			"role:APP_ADMIN:assigned", "role:APP_ADMIN:entire-organization")
	})
}

func TestRoleTargetPagingStopsOnCancel(t *testing.T) {
	// No scripted requests: a cancelled context must stop before any page is read.
	client := newScriptedOktaClient(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	o := testScopeConnector(client)
	principal := rolePrincipal{resourceType: resourceTypeUser.Id, id: testOktaUserID}
	_, err := o.listRoleTargets(ctx, principal, testRoleAssignmentID, mustScopedRole(t, "USER_ADMIN"), false)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("listRoleTargets() error = %v, want context.Canceled", err)
	}
	if _, err := o.catalogAppInstanceIDs(ctx, nil, "salesforce"); !errors.Is(err, context.Canceled) {
		t.Fatalf("catalogAppInstanceIDs() error = %v, want context.Canceled", err)
	}
}
