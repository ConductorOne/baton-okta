package connector

import (
	"encoding/json"
	"testing"
	"time"

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
