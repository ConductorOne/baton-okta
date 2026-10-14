package connector

import (
	"net/http"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	sdkResource "github.com/conductorone/baton-sdk/pkg/types/resource"
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
	groupRes := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeGroup.Id, Resource: testTargetGroupA}, DisplayName: "Atlanta"}

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
		if got, want := ents[0].GetDisplayName(), "Atlanta Group Administrator"; got != want {
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

func TestEntitlementSlug(t *testing.T) {
	res := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeGroup.Id, Resource: testGroupID}}
	if got := entitlementSlug(&v2.Entitlement{Resource: res, Slug: "member"}); got != "member" {
		t.Fatalf("slug = %q, want member", got)
	}
	if got := entitlementSlug(&v2.Entitlement{Resource: res, Id: "group:" + testGroupID + ":group-admin"}); got != "group-admin" {
		t.Fatalf("slug from id = %q, want group-admin", got)
	}
	if got := entitlementSlug(groupMembershipEntitlement()); got != "" {
		t.Fatalf("slug of bare entitlement = %q, want empty", got)
	}
}

func TestRoleScopeTargetEntitlementsAreNotProvisionable(t *testing.T) {
	// No scripted requests: rejecting must happen before any Okta call, or a
	// revoke of "Atlanta Group Administrator" would remove group membership.
	groupEnt := &v2.Entitlement{
		Resource: &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeGroup.Id, Resource: testGroupID}},
		Id:       "group:" + testGroupID + ":group-admin",
	}
	appEnt := &v2.Entitlement{
		Resource: &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeApp.Id, Resource: testAppID}},
		Slug:     "app-admin",
	}
	client := newScriptedOktaClient(t)
	gb := groupBuilder(&Okta{client: client})
	ab := newTestAppBuilder(client)

	checks := map[string]error{}
	_, checks["group grant"] = gb.Grant(t.Context(), testUserPrincipal(), groupEnt)
	_, checks["group revoke"] = gb.Revoke(t.Context(), &v2.Grant{Entitlement: groupEnt, Principal: testUserPrincipal()})
	_, checks["app grant"] = ab.Grant(t.Context(), testUserPrincipal(), appEnt)
	_, checks["app revoke"] = ab.Revoke(t.Context(), &v2.Grant{Entitlement: appEnt, Principal: testUserPrincipal()})
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
