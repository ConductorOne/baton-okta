package connector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	sdkGrant "github.com/conductorone/baton-sdk/pkg/types/grant"
	sdkResource "github.com/conductorone/baton-sdk/pkg/types/resource"
	mapset "github.com/deckarep/golang-set/v2"
	oktaSDK "github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func logEvent(eventType string, targets ...*oktaSDK.LogTarget) *oktaSDK.LogEvent {
	published := time.Date(2026, time.August, 25, 12, 0, 0, 0, time.UTC)
	return &oktaSDK.LogEvent{
		Uuid:      "00000000-0000-4000-8000-000000000001",
		EventType: eventType,
		Published: &published,
		Actor:     &oktaSDK.LogActor{Type: oktaLogTargetTypeUser, Id: "actor1"},
		Target:    targets,
	}
}

// Okta emits removal events for app assignments and admin-role revocations.
// Both must produce CreateRevokeEvents whose entitlement slug matches the one
// the sync builds, or c1 fails the entitlement lookup and drops the event.
func TestRevokeFilters(t *testing.T) {
	for _, tt := range []struct {
		name         string
		filter       EventFilter
		event        *oktaSDK.LogEvent
		wantSlug     string
		wantResource string
		wantType     string
	}{
		{
			name:   "app membership remove",
			filter: ApplicationMembershipRevokeFilter,
			event: logEvent("application.user_membership.remove",
				&oktaSDK.LogTarget{Type: "AppInstance", Id: "app1", DisplayName: "Salesforce"},
				&oktaSDK.LogTarget{Type: oktaLogTargetTypeUser, Id: "user1", AlternateId: "user@example.com"},
			),
			// Must match app.go's "access" assignment entitlement.
			wantSlug:     "access",
			wantResource: "app1",
			wantType:     resourceTypeApp.Id,
		},
		{
			name:   "role privilege revoke",
			filter: RoleMembershipRevokeFilter,
			event: logEvent("user.account.privilege.revoke",
				&oktaSDK.LogTarget{Type: "ROLE", DisplayName: "Mobile Administrator"},
				&oktaSDK.LogTarget{Type: oktaLogTargetTypeUser, Id: "user1", AlternateId: "user@example.com"},
			),
			// Must match role.go's "assigned" assignment entitlement.
			wantSlug: "assigned",
			// Resolved from the label because privilege events carry no role type.
			wantResource: "MOBILE_ADMIN",
			wantType:     resourceTypeRole.Id,
		},
		{
			// This label was previously mistyped in standardRoleTypes, which
			// dropped every revoke for this role.
			name:   "role privilege revoke, read-only admin",
			filter: RoleMembershipRevokeFilter,
			event: logEvent("user.account.privilege.revoke",
				&oktaSDK.LogTarget{Type: "ROLE", DisplayName: "Read-only Administrator"},
				&oktaSDK.LogTarget{Type: oktaLogTargetTypeUser, Id: "user1", AlternateId: "user@example.com"},
			),
			wantSlug:     "assigned",
			wantResource: "READ_ONLY_ADMIN",
			wantType:     resourceTypeRole.Id,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.True(t, tt.filter.Matches(tt.event))

			rv, err := tt.filter.Handle(zap.NewNop(), tt.event)
			require.NoError(t, err)
			require.Equal(t, tt.event.Uuid, rv.Id)

			revoke := rv.GetCreateRevokeEvent()
			require.NotNil(t, revoke, "must be a revoke event, not a resource change")
			require.Equal(t, tt.wantSlug, revoke.GetEntitlement().GetSlug())
			require.Equal(t, tt.wantResource, revoke.GetEntitlement().GetResource().GetId().GetResource())
			require.Equal(t, tt.wantType, revoke.GetEntitlement().GetResource().GetId().GetResourceType())
			require.Equal(t, "user1", revoke.GetPrincipal().GetId().GetResource())
			require.Equal(t, resourceTypeUser.Id, revoke.GetPrincipal().GetId().GetResourceType())
		})
	}
}

// An unknown role label has no standard type to resolve, so the event is skipped
// rather than emitted against a bogus resource ID. Skipped, not errored: an
// unmapped label is an upstream condition, not a connector fault.
func TestRoleMembershipRevokeFilterUnknownLabel(t *testing.T) {
	event := logEvent("user.account.privilege.revoke",
		&oktaSDK.LogTarget{Type: "ROLE", DisplayName: "Some Custom Role"},
		&oktaSDK.LogTarget{Type: oktaLogTargetTypeUser, Id: "user1"},
	)
	rv, err := RoleMembershipRevokeFilter.Handle(zap.NewNop(), event)
	require.NoError(t, err)
	require.Nil(t, rv, "a skipped event must not reach the feed")
}

// A filter that is not in activeFilters is never queried, so registration is the
// invariant worth asserting -- not that a filter can build a query string.
func TestRevokeFiltersAreRegistered(t *testing.T) {
	queried := mapset.NewSet[string]()
	for _, filter := range activeFilters {
		queried = queried.Union(filter.EventTypes)
	}

	require.True(t, queried.Contains("application.user_membership.remove"))
	require.True(t, queried.Contains("user.account.privilege.revoke"))
}

// Example payload showing the shape Okta sends. A third target of type
// ROLE_UNASSIGNED_ALL_PRIVILEGES_REVOKED, and the ROLE target's id
// ("HelpDeskAdmin") is neither the role type the sync uses as a resource ID
// nor its alternateId — hence the displayName lookup.
const privilegeRevokeFixture = `{
  "actor": {"id":"00uEXAMPLEACTOR00001","type":"User","alternateId":"admin@example.com","displayName":"Admin"},
  "eventType": "user.account.privilege.revoke",
  "outcome": {"result":"SUCCESS"},
  "published": "2026-08-25T17:41:22.539Z",
  "uuid": "00000000-0000-4000-8000-000000000002",
  "target": [
    {"id":"00uEXAMPLEUSER000001","type":"User","alternateId":"user@example.com","displayName":"Target User"},
    {"id":"ROLE_UNASSIGNED_ALL_PRIVILEGES_REVOKED",
     "type":"ROLE_UNASSIGNED_ALL_PRIVILEGES_REVOKED",
     "alternateId":"unknown",
     "displayName":"All Privileges revoked from User. User has no admin privileges"},
    {"id":"HelpDeskAdmin","type":"ROLE","alternateId":"EXAMPLEASSIGNMENTID1","displayName":"Help Desk Administrator"}
  ]
}`

func TestRoleMembershipRevokeFilterExtraTargets(t *testing.T) {
	event := &oktaSDK.LogEvent{}
	require.NoError(t, json.Unmarshal([]byte(privilegeRevokeFixture), event))

	// The extra ROLE_UNASSIGNED_ALL_PRIVILEGES_REVOKED target must not be
	// mistaken for a second ROLE target, or the handler rejects the event.
	require.True(t, RoleMembershipRevokeFilter.Matches(event))

	rv, err := RoleMembershipRevokeFilter.Handle(zap.NewNop(), event)
	require.NoError(t, err)
	require.Equal(t, "00000000-0000-4000-8000-000000000002", rv.Id)

	revoke := rv.GetCreateRevokeEvent()
	require.NotNil(t, revoke)
	// Must equal the entitlement the sync builds in role.go, or c1 cannot
	// resolve it and silently drops the event.
	require.Equal(t, "role:HELP_DESK_ADMIN:assigned", revoke.GetEntitlement().GetId())
	require.Equal(t, "00uEXAMPLEUSER000001", revoke.GetPrincipal().GetId().GetResource())
}

// Okta has no "app.lifecycle.*" namespace; requesting it silently matched nothing.
func TestApplicationLifecycleFilterEventTypes(t *testing.T) {
	types := ApplicationLifecycleFilter.EventTypes

	for _, want := range []string{
		"application.lifecycle.create",
		"application.lifecycle.update",
		"application.lifecycle.activate",
	} {
		require.True(t, types.Contains(want), "missing %s", want)
	}

	require.False(t, types.Contains("app.lifecycle.create"), "app.lifecycle.* is not a real Okta namespace")
	// Both leave the targeted sync with no resource to write, so the SDK records a
	// task failure and the stale resource survives regardless.
	require.False(t, types.Contains("application.lifecycle.delete"))
	require.False(t, types.Contains("application.lifecycle.deactivate"))

	event := logEvent("application.lifecycle.create",
		&oktaSDK.LogTarget{Type: "AppInstance", Id: "app1", DisplayName: "Salesforce"},
	)
	require.True(t, ApplicationLifecycleFilter.Matches(event))

	rv, err := ApplicationLifecycleFilter.Handle(zap.NewNop(), event)
	require.NoError(t, err)
	change := rv.GetResourceChangeEvent()
	require.NotNil(t, change)
	require.Equal(t, "app1", change.GetResourceId().GetResource())
	require.Equal(t, resourceTypeApp.Id, change.GetResourceId().GetResourceType())
}

// Example payloads showing the shape Okta sends: three targets — AppUser,
// AppInstance and User — so the extra AppUser bucket must not disturb the
// single-AppInstance / single-User expectations.
const appMembershipRemoveFixture = `[
 {"eventType":"application.user_membership.remove","published":"2026-08-25T17:41:22.359Z","uuid":"00000000-0000-4000-8000-000000000003",
  "target":[{"id":"0uaEXAMPLEAPPUSER001","type":"AppUser","alternateId":"unknown","displayName":"Target User"},
            {"id":"0oaEXAMPLEADMINAPP01","type":"AppInstance","alternateId":"Okta Admin Console","displayName":"Okta Admin Console"},
            {"id":"00uEXAMPLEUSER000001","type":"User","alternateId":"user@example.com","displayName":"Target User"}]},
 {"eventType":"application.user_membership.remove","published":"2026-08-25T18:19:21.524Z","uuid":"00000000-0000-4000-8000-000000000004",
  "target":[{"id":"0uaEXAMPLEAPPUSER002","type":"AppUser","alternateId":"user@example.com","displayName":"Target User"},
            {"id":"0oaEXAMPLEAPP0000001","type":"AppInstance","alternateId":"ExampleWebApp","displayName":"OpenID Connect Client"},
            {"id":"00uEXAMPLEUSER000001","type":"User","alternateId":"user@example.com","displayName":"Target User"}]}
]`

func TestApplicationMembershipRevokeFilterAppUserTarget(t *testing.T) {
	var events []*oktaSDK.LogEvent
	require.NoError(t, json.Unmarshal([]byte(appMembershipRemoveFixture), &events))
	require.Len(t, events, 2)

	// Entitlement IDs must equal what app.go builds from app.Id, or c1 cannot
	// resolve them and silently drops the event.
	wantEntitlements := []string{
		"app:0oaEXAMPLEADMINAPP01:access",
		"app:0oaEXAMPLEAPP0000001:access",
	}

	for i, event := range events {
		require.True(t, ApplicationMembershipRevokeFilter.Matches(event))

		rv, err := ApplicationMembershipRevokeFilter.Handle(zap.NewNop(), event)
		require.NoError(t, err)
		require.Equal(t, event.Uuid, rv.Id)

		revoke := rv.GetCreateRevokeEvent()
		require.NotNil(t, revoke)
		require.Equal(t, wantEntitlements[i], revoke.GetEntitlement().GetId())
		require.Equal(t, "00uEXAMPLEUSER000001", revoke.GetPrincipal().GetId().GetResource())
	}
}

// Example payloads showing the shape Okta sends. Assignment and unassignment share
// under the same user.account.privilege.grant type, so the ROLE_ASSIGNED /
// ROLE_UNASSIGNED target is the only thing separating a grant from a revoke.
// Note debugData.privilegeGranted lists the privileges remaining after the
// change, not the change itself, so it cannot serve as the discriminator.
const privilegeGrantFixture = `[
 {"eventType":"user.account.privilege.grant","published":"2026-08-28T16:24:11.960Z",
  "uuid":"00000000-0000-4000-8000-000000000005",
  "debugContext":{"debugData":{"privilegeGranted":"User administrator (all)"}},
  "target":[{"id":"00uEXAMPLEUSER000001","type":"User","alternateId":"user@example.com","displayName":"Target User"},
            {"id":"ROLE_ASSIGNED","type":"ROLE_ASSIGNED","alternateId":"unknown","displayName":"Role Assigned"},
            {"id":"UserAdmin","type":"ROLE","alternateId":"EXAMPLEASSIGNMENTID2","displayName":"Group Administrator"}]},
 {"eventType":"user.account.privilege.grant","published":"2026-08-28T16:24:39.708Z",
  "uuid":"00000000-0000-4000-8000-000000000006",
  "target":[{"id":"00uEXAMPLEUSER000001","type":"User","alternateId":"user@example.com","displayName":"Target User"},
            {"id":"ROLE_ASSIGNED","type":"ROLE_ASSIGNED","alternateId":"unknown","displayName":"Role Assigned"},
            {"id":"AppAdmin","type":"ROLE","alternateId":"EXAMPLEASSIGNMENTID3","displayName":"Application Administrator"}]},
 {"eventType":"user.account.privilege.grant","published":"2026-08-28T16:30:42.694Z",
  "uuid":"00000000-0000-4000-8000-000000000007",
  "target":[{"id":"00uEXAMPLEUSER000001","type":"User","alternateId":"user@example.com","displayName":"Target User"},
            {"id":"ROLE_ASSIGNED","type":"ROLE_ASSIGNED","alternateId":"unknown","displayName":"Role Assigned"},
            {"id":"ApiAccessManagementAdmin","type":"ROLE","alternateId":"EXAMPLEASSIGNMENTID4","displayName":"API Access Management Administrator"}]},
 {"eventType":"user.account.privilege.grant","published":"2026-08-28T16:32:57.838Z",
  "uuid":"00000000-0000-4000-8000-000000000008",
  "debugContext":{"debugData":{"privilegeGranted":"User administrator (all), API Access Management administrator"}},
  "target":[{"id":"00uEXAMPLEUSER000001","type":"User","alternateId":"user@example.com","displayName":"Target User"},
            {"id":"ROLE_UNASSIGNED","type":"ROLE_UNASSIGNED","alternateId":"unknown","displayName":"Role Unassigned"},
            {"id":"AppAdmin","type":"ROLE","alternateId":"EXAMPLEASSIGNMENTID3","displayName":"Application Administrator"}]},
 {"eventType":"user.account.privilege.grant","published":"2026-08-28T17:33:38.480Z",
  "uuid":"00000000-0000-4000-8000-000000000009",
  "target":[{"id":"00uEXAMPLEUSER000001","type":"User","alternateId":"user@example.com","displayName":"Target User"},
            {"id":"ROLE_ASSIGNED","type":"ROLE_ASSIGNED","alternateId":"unknown","displayName":"Role Assigned"},
            {"id":"ReportAdmin","type":"ROLE","alternateId":"EXAMPLEASSIGNMENTID5","displayName":"Report Administrator"}]},
 {"eventType":"user.account.privilege.grant","published":"2026-08-28T17:33:39.022Z",
  "uuid":"00000000-0000-4000-8000-000000000010",
  "target":[{"id":"00uEXAMPLEUSER000001","type":"User","alternateId":"user@example.com","displayName":"Target User"},
            {"id":"ROLE_ASSIGNED","type":"ROLE_ASSIGNED","alternateId":"unknown","displayName":"Role Assigned"},
            {"id":"MobileAdmin","type":"ROLE","alternateId":"EXAMPLEASSIGNMENTID6","displayName":"Mobile Administrator"}]},
 {"eventType":"user.account.privilege.grant","published":"2026-08-28T17:33:39.464Z",
  "uuid":"00000000-0000-4000-8000-000000000011",
  "target":[{"id":"00uEXAMPLEUSER000001","type":"User","alternateId":"user@example.com","displayName":"Target User"},
            {"id":"ROLE_ASSIGNED","type":"ROLE_ASSIGNED","alternateId":"unknown","displayName":"Role Assigned"},
            {"id":"GroupMembershipAdmin","type":"ROLE","alternateId":"EXAMPLEASSIGNMENTID7","displayName":"Group Membership Administrator"}]}
]`

func TestRoleMembershipFilterDiscriminatesAssignment(t *testing.T) {
	var events []*oktaSDK.LogEvent
	require.NoError(t, json.Unmarshal([]byte(privilegeGrantFixture), &events))
	require.Len(t, events, 7)

	want := []struct {
		entitlement string
		isGrant     bool
	}{
		{"role:USER_ADMIN:assigned", true},
		{"role:APP_ADMIN:assigned", true},
		{"role:API_ACCESS_MANAGEMENT_ADMIN:assigned", true},
		// Same event type as the three above, and the same role as the second:
		// only the ROLE_UNASSIGNED target makes this a revoke.
		{"role:APP_ADMIN:assigned", false},
		// Three roles assigned in a single UI action. Okta logs one event per role
		// rather than one event carrying three ROLE targets, so each keeps a single
		// ROLE target and the len(...) != 1 guard holds.
		{"role:REPORT_ADMIN:assigned", true},
		{"role:MOBILE_ADMIN:assigned", true},
		{"role:GROUP_MEMBERSHIP_ADMIN:assigned", true},
	}

	for i, event := range events {
		require.True(t, RoleMembershipFilter.Matches(event), "event %d", i)

		rv, err := RoleMembershipFilter.Handle(zap.NewNop(), event)
		require.NoError(t, err, "event %d", i)
		require.Equal(t, event.Uuid, rv.Id)

		if want[i].isGrant {
			grant := rv.GetCreateGrantEvent()
			require.NotNil(t, grant, "event %d must be a grant", i)
			require.Nil(t, rv.GetCreateRevokeEvent())
			require.Equal(t, want[i].entitlement, grant.GetEntitlement().GetId())
			require.Equal(t, "00uEXAMPLEUSER000001", grant.GetPrincipal().GetId().GetResource())
			continue
		}

		revoke := rv.GetCreateRevokeEvent()
		require.NotNil(t, revoke, "event %d must be a revoke, not a grant", i)
		require.Nil(t, rv.GetCreateGrantEvent(), "an unassignment must never emit a grant")
		require.Equal(t, want[i].entitlement, revoke.GetEntitlement().GetId())
		require.Equal(t, "00uEXAMPLEUSER000001", revoke.GetPrincipal().GetId().GetResource())
	}
}

// Custom role bindings share the event type but carry no ROLE target, and no
// discriminator at all means Okta changed something we do not understand.
// Either way, emitting a grant would reaffirm possibly-removed access.
func TestRoleMembershipFilterSkipsUnknownDiscriminator(t *testing.T) {
	for _, tt := range []struct {
		name    string
		targets []*oktaSDK.LogTarget
	}{
		{
			name: "custom role binding removed",
			targets: []*oktaSDK.LogTarget{
				{Type: oktaLogTargetTypeUser, Id: "user1"},
				{Type: "CUSTOM_ROLE_BINDING_REMOVED", Id: "CUSTOM_ROLE_BINDING_REMOVED"},
			},
		},
		{
			name: "no discriminator",
			targets: []*oktaSDK.LogTarget{
				{Type: oktaLogTargetTypeUser, Id: "user1"},
				{Type: "ROLE", DisplayName: "Application Administrator"},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			event := logEvent("user.account.privilege.grant", tt.targets...)
			rv, err := RoleMembershipFilter.Handle(zap.NewNop(), event)
			require.NoError(t, err)
			require.Nil(t, rv, "a skipped event must not reach the feed")
		})
	}
}

// An unresolvable label is an expected upstream condition, not a connector
// fault, so it must skip rather than surface as an error per revocation.
func TestRoleMembershipFilterSkipsUnknownLabel(t *testing.T) {
	event := logEvent("user.account.privilege.grant",
		&oktaSDK.LogTarget{Type: oktaLogTargetTypeUser, Id: "user1"},
		&oktaSDK.LogTarget{Type: oktaLogTargetRoleUnassigned, Id: oktaLogTargetRoleUnassigned},
		&oktaSDK.LogTarget{Type: "ROLE", DisplayName: "Some Custom Role"},
	)
	rv, err := RoleMembershipFilter.Handle(zap.NewNop(), event)
	require.NoError(t, err)
	require.Nil(t, rv, "a skipped event must not reach the feed")
}

// Example payloads for the group-derived shape. Assigning a role to a group produces one
// event per group member, each marked with a _GROUP_ suffix on the discriminator
// and carrying no Group target at all. The group that conferred the role is
// therefore unknowable from the event, while the sync models this access as a
// group-principal grant (role.go roleGroupGrant, with GrantExpandable). Emitting a
// user-principal grant here would contradict the sync and flap. Skip instead.
const groupDerivedPrivilegeFixture = `[
 {"eventType":"user.account.privilege.grant","published":"2026-08-28T18:23:44.250Z",
  "uuid":"00000000-0000-4000-8000-000000000012",
  "target":[{"id":"00uEXAMPLEUSER000001","type":"User","alternateId":"user@example.com","displayName":"Target User"},
            {"id":"ROLE_ASSIGNED_GROUP_ROLE_CHANGE","type":"ROLE_ASSIGNED_GROUP_ROLE_CHANGE","alternateId":"unknown","displayName":"Role Assigned from Group Role Change"},
            {"id":"UserAdmin","type":"ROLE","alternateId":"EXAMPLEASSIGNMENTID2","displayName":"Group Administrator"}]},
 {"eventType":"user.account.privilege.grant","published":"2026-08-28T18:23:44.588Z",
  "uuid":"00000000-0000-4000-8000-000000000013",
  "target":[{"id":"00uEXAMPLEUSER000001","type":"User","alternateId":"user@example.com","displayName":"Target User"},
            {"id":"CUSTOM_ROLE_BINDING_ADDED_GROUP_CHANGE","type":"CUSTOM_ROLE_BINDING_ADDED_GROUP_CHANGE","alternateId":"unknown","displayName":"Custom role binding added from Group Change"},
            {"id":"cr0EXAMPLEROLE000001","type":"CUSTOM_ROLE","alternateId":"/api/v1/iam/roles/cr0EXAMPLEROLE000001","displayName":"Example Custom Role"},
            {"id":"iamEXAMPLERSET000001","type":"RESOURCE_SET","alternateId":"/api/v1/iam/resource-sets/iamEXAMPLERSET000001","displayName":"Example Resource Set"}]}
]`

func TestRoleMembershipFilterSkipsGroupDerivedChanges(t *testing.T) {
	var events []*oktaSDK.LogEvent
	require.NoError(t, json.Unmarshal([]byte(groupDerivedPrivilegeFixture), &events))
	require.Len(t, events, 2)

	for _, event := range events {
		// The event still matches: it carries a User target, and the standard-role
		// variant carries a ROLE target too.
		require.True(t, RoleMembershipFilter.Matches(event))

		// A _GROUP_ suffix must never be read as the direct discriminator it
		// prefixes, or an inherited role reaches C1 as a direct grant.
		rv, err := RoleMembershipFilter.Handle(zap.NewNop(), event)
		require.NoError(t, err)
		require.Nil(t, rv, "an inherited role change must not reach the feed")
	}
}

// StandardRoleTypeFromLabel must resolve these against oktaSystemLogLabels regardless
// of standardRoleTypes' Label, which is allowed to differ (it's the text synced to C1,
// not what's matched against the System Log). Two of these previously drifted from
// Okta's actual casing/wording, which silently dropped every grant event for those roles.
func TestRoleMembershipFilterResolvesStandardLabels(t *testing.T) {
	for _, tt := range []struct {
		label    string
		wantType string
	}{
		{"Read-only Administrator", "READ_ONLY_ADMIN"},
		{"Organization Administrator", "ORG_ADMIN"},
		{"Help Desk Administrator", "HELP_DESK_ADMIN"},
	} {
		t.Run(tt.wantType, func(t *testing.T) {
			event := logEvent("user.account.privilege.grant",
				&oktaSDK.LogTarget{Type: "ROLE", Id: "RoleId", DisplayName: tt.label},
				&oktaSDK.LogTarget{Type: oktaLogTargetTypeUser, Id: "user1", AlternateId: "user@example.com"},
				&oktaSDK.LogTarget{Type: oktaLogTargetRoleAssigned},
			)

			rv, err := RoleMembershipFilter.Handle(zap.NewNop(), event)
			require.NoError(t, err)
			require.NotNil(t, rv, "a standard role label must resolve to a type")

			grant := rv.GetCreateGrantEvent()
			require.NotNil(t, grant)
			require.Equal(t, tt.wantType, grant.GetEntitlement().GetResource().GetId().GetResource())
			require.Equal(t, "assigned", grant.GetEntitlement().GetSlug())
			// Pins the resource's DisplayName to the synced Label, not the raw log
			// text -- catches a regression back to role.DisplayName, which would
			// only misfire for the two roles whose wordings differ.
			require.Equal(t, standardRoleFromType(tt.wantType).Label, grant.GetEntitlement().GetResource().GetDisplayName())
		})
	}
}

// oktaSystemLogLabels must have a non-empty entry for every standardRoleTypes entry --
// StandardRoleTypeFromLabel resolves only against that map now (role.go), so a role
// added to one table without the other has its grant/revoke events silently dropped.
// No network, no credentials: this is an internal-consistency check between the two
// tables, not a check against Okta's real behavior -- see TestStandardRoleTypesMatchOkta
// (integration_debug_test.go) for that.
func TestOktaSystemLogLabelsCoversAllStandardRoles(t *testing.T) {
	for _, role := range standardRoleTypes {
		t.Run(role.Type, func(t *testing.T) {
			require.NotEmpty(t, oktaSystemLogLabels[role.Type],
				"role %s has no oktaSystemLogLabels entry -- its grant/revoke events will be silently dropped",
				role.Type)
		})
	}
}

func groupAssignmentFixture(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("testdata/group-application-assignment.json")
	require.NoError(t, err)
	return string(data)
}

func groupAssignmentFilter(t *testing.T) EventFilter {
	t.Helper()
	for _, filter := range activeFilters {
		if filter.EventTypes.Contains("group.application_assignment.add") {
			return filter
		}
	}
	t.Fatal("group application assignment filter is not registered")
	return EventFilter{}
}

// listEventsCapturingFilter serves body as the System Log page and returns the
// emitted events along with the filter the connector sent.
func listEventsCapturingFilter(t *testing.T, c *Okta, body string) ([]*v2.Event, string) {
	t.Helper()
	var filterQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/logs" {
			t.Errorf("unexpected request path: %s", r.URL.Path)
		}
		filterQuery = r.URL.Query().Get("filter")
		writeOktaTestResponse(w, http.StatusOK, body)
	}))
	t.Cleanup(server.Close)
	_, client, err := oktaSDK.NewClient(t.Context(),
		oktaSDK.WithOrgUrl(server.URL),
		oktaSDK.WithToken("test-token"),
		oktaSDK.WithHttpClientPtr(server.Client()),
		oktaSDK.WithTestingDisableHttpsCheck(true),
		oktaSDK.WithCache(false),
	)
	require.NoError(t, err)
	c.client = client
	events, _, _, err := c.ListEvents(t.Context(), nil, &pagination.StreamToken{Size: 100})
	require.NoError(t, err)
	return events, filterQuery
}

func TestListEventsGroupApplicationAssignment(t *testing.T) {
	events, filterQuery := listEventsCapturingFilter(t, &Okta{}, "["+groupAssignmentFixture(t)+"]")
	require.Contains(t, filterQuery, `eventType eq "group.application_assignment.add"`)
	require.Contains(t, filterQuery, `outcome.result eq "SUCCESS"`)
	require.Len(t, events, 1)
	require.Equal(t, "00000000-0000-4000-8000-000000000020", events[0].GetId())
	require.True(t, events[0].GetOccurredAt().AsTime().Equal(time.Date(2026, time.October, 23, 17, 38, 52, 970000000, time.UTC)))
	grant := events[0].GetCreateGrantEvent()
	require.NotNil(t, grant)
	require.Equal(t, "app:app1:access", grant.GetEntitlement().GetId())
	require.Equal(t, "access", grant.GetEntitlement().GetSlug())
	require.Equal(t, "app", grant.GetEntitlement().GetResource().GetId().GetResourceType())
	require.Equal(t, "app1", grant.GetEntitlement().GetResource().GetId().GetResource())
	require.Equal(t, "group", grant.GetPrincipal().GetId().GetResourceType())
	require.Equal(t, "group1", grant.GetPrincipal().GetId().GetResource())
	resource, err := sdkResource.NewResource("Example application", resourceTypeApp, "app1")
	require.NoError(t, err)
	fullSyncGrant := sdkGrant.NewGrant(resource, "access", grant.GetPrincipal())
	eventGrant := sdkGrant.NewGrantID(grant.GetPrincipal(), grant.GetEntitlement())
	require.Equal(t, fullSyncGrant.GetId(), eventGrant)
	expansion := &v2.GrantExpandable{}
	annos := annotations.Annotations(grant.GetAnnotations())
	found, err := annos.Pick(expansion)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, []string{"group:group1:member"}, expansion.GetEntitlementIds())
	require.True(t, expansion.GetShallow())
}

func TestListEventsGroupApplicationAssignmentWithSkippedAppGroups(t *testing.T) {
	// The event cannot tell an APP_GROUP from other groups, so it is emitted
	// regardless; C1 drops grants whose group principal was never synced.
	events, filterQuery := listEventsCapturingFilter(t, &Okta{skipAppGroups: true}, "["+groupAssignmentFixture(t)+"]")
	require.Contains(t, filterQuery, `eventType eq "group.application_assignment.add"`)
	require.Len(t, events, 1)
	require.Equal(t, "group1", events[0].GetCreateGrantEvent().GetPrincipal().GetId().GetResource())
}

func TestApplicationGroupAssignmentFilterRejectsMalformedTargets(t *testing.T) {
	filter := groupAssignmentFilter(t)
	for _, tt := range []struct {
		name    string
		targets []*oktaSDK.LogTarget
	}{
		{name: "missing group", targets: []*oktaSDK.LogTarget{{Type: "AppInstance", Id: "app1"}}},
		{name: "missing application", targets: []*oktaSDK.LogTarget{{Type: "UserGroup", Id: "group1"}}},
		{name: "duplicate groups", targets: []*oktaSDK.LogTarget{{Type: "UserGroup", Id: "group1"}, {Type: "UserGroup", Id: "group2"}, {Type: "AppInstance", Id: "app1"}}},
		{name: "duplicate applications", targets: []*oktaSDK.LogTarget{{Type: "UserGroup", Id: "group1"}, {Type: "AppInstance", Id: "app1"}, {Type: "AppInstance", Id: "app2"}}},
		{name: "empty group id", targets: []*oktaSDK.LogTarget{{Type: "UserGroup"}, {Type: "AppInstance", Id: "app1"}}},
		{name: "empty application id", targets: []*oktaSDK.LogTarget{{Type: "UserGroup", Id: "group1"}, {Type: "AppInstance"}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			event := logEvent("group.application_assignment.add", tt.targets...)
			event.Outcome = &oktaSDK.LogOutcome{Result: "SUCCESS"}
			rv, err := filter.Handle(zap.NewNop(), event)
			require.Error(t, err)
			require.Nil(t, rv)
		})
	}
}

func TestApplicationGroupAssignmentFilterMatchesOnlySuccessfulEvents(t *testing.T) {
	filter := groupAssignmentFilter(t)
	for _, tt := range []struct {
		outcome *oktaSDK.LogOutcome
		want    bool
	}{
		{outcome: nil, want: false},
		{outcome: &oktaSDK.LogOutcome{Result: "FAILURE"}, want: false},
		{outcome: &oktaSDK.LogOutcome{Result: "SKIPPED"}, want: false},
		{outcome: &oktaSDK.LogOutcome{Result: "UNKNOWN"}, want: false},
		{outcome: &oktaSDK.LogOutcome{Result: "SUCCESS"}, want: true},
	} {
		event := &oktaSDK.LogEvent{}
		require.NoError(t, json.Unmarshal([]byte(groupAssignmentFixture(t)), event))
		event.Outcome = tt.outcome
		require.Equal(t, tt.want, filter.Matches(event))
	}
}
