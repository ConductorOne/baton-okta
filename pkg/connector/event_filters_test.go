package connector

import (
	"encoding/json"
	"testing"
	"time"

	oktaSDK "github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func logEvent(eventType string, targets ...*oktaSDK.LogTarget) *oktaSDK.LogEvent {
	published := time.Date(2026, time.August, 25, 12, 0, 0, 0, time.UTC)
	return &oktaSDK.LogEvent{
		Uuid:      "b0f1c2d3-0000-4000-8000-000000000001",
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

// An unknown role label has no standard type to resolve, so the event is
// rejected rather than emitted against a bogus resource ID.
func TestRoleMembershipRevokeFilterUnknownLabel(t *testing.T) {
	event := logEvent("user.account.privilege.revoke",
		&oktaSDK.LogTarget{Type: "ROLE", DisplayName: "Some Custom Role"},
		&oktaSDK.LogTarget{Type: oktaLogTargetTypeUser, Id: "user1"},
	)
	_, err := RoleMembershipRevokeFilter.Handle(zap.NewNop(), event)
	require.ErrorContains(t, err, "error getting role from label")
}

// Both new event types must reach the Okta System Log query, otherwise the
// filters never see an event to handle.
func TestRevokeFiltersAreQueried(t *testing.T) {
	filter := (&EventFilter{
		EventTypes:  ApplicationMembershipRevokeFilter.EventTypes,
		TargetTypes: ApplicationMembershipRevokeFilter.TargetTypes,
	}).Filter()
	require.Contains(t, filter, `eventType eq "application.user_membership.remove"`)

	filter = (&EventFilter{
		EventTypes:  RoleMembershipRevokeFilter.EventTypes,
		TargetTypes: RoleMembershipRevokeFilter.TargetTypes,
	}).Filter()
	require.Contains(t, filter, `eventType eq "user.account.privilege.revoke"`)
}

// Real payload from a test tenant. Okta sends a third target whose type is
// ROLE_UNASSIGNED_ALL_PRIVILEGES_REVOKED, and the ROLE target's id
// ("HelpDeskAdmin") is neither the role type the sync uses as a resource ID
// nor its alternateId — hence the displayName lookup.
const privilegeRevokeFixture = `{
  "actor": {"id":"00ux6rfqpqkPp4A72697","type":"User","alternateId":"admin@example.com","displayName":"Admin"},
  "eventType": "user.account.privilege.revoke",
  "outcome": {"result":"SUCCESS"},
  "published": "2026-08-25T17:41:22.539Z",
  "uuid": "30010c48-a0ac-11f1-ae0a-95c6e5af725d",
  "target": [
    {"id":"00u12xvaouixjW1y3698","type":"User","alternateId":"user@example.com","displayName":"Target User"},
    {"id":"ROLE_UNASSIGNED_ALL_PRIVILEGES_REVOKED","type":"ROLE_UNASSIGNED_ALL_PRIVILEGES_REVOKED","alternateId":"unknown","displayName":"All Privileges revoked from User. User has no admin privileges"},
    {"id":"HelpDeskAdmin","type":"ROLE","alternateId":"JBCUYUC7IRCVGS27IFCE2SKO","displayName":"Help Desk Administrator"}
  ]
}`

func TestRoleMembershipRevokeFilterRealPayload(t *testing.T) {
	event := &oktaSDK.LogEvent{}
	require.NoError(t, json.Unmarshal([]byte(privilegeRevokeFixture), event))

	// The extra ROLE_UNASSIGNED_ALL_PRIVILEGES_REVOKED target must not be
	// mistaken for a second ROLE target, or the handler rejects the event.
	require.True(t, RoleMembershipRevokeFilter.Matches(event))

	rv, err := RoleMembershipRevokeFilter.Handle(zap.NewNop(), event)
	require.NoError(t, err)
	require.Equal(t, "30010c48-a0ac-11f1-ae0a-95c6e5af725d", rv.Id)

	revoke := rv.GetCreateRevokeEvent()
	require.NotNil(t, revoke)
	// Must equal the entitlement the sync builds in role.go, or c1 cannot
	// resolve it and silently drops the event.
	require.Equal(t, "role:HELP_DESK_ADMIN:assigned", revoke.GetEntitlement().GetId())
	require.Equal(t, "00u12xvaouixjW1y3698", revoke.GetPrincipal().GetId().GetResource())
}

// Okta has no "app.lifecycle.*" namespace; requesting it silently matched nothing.
func TestApplicationLifecycleFilterEventTypes(t *testing.T) {
	types := ApplicationLifecycleFilter.EventTypes

	for _, want := range []string{
		"application.lifecycle.create",
		"application.lifecycle.update",
		"application.lifecycle.activate",
		"application.lifecycle.deactivate",
	} {
		require.True(t, types.Contains(want), "missing %s", want)
	}

	require.False(t, types.Contains("app.lifecycle.create"), "app.lifecycle.* is not a real Okta namespace")
	// Emitting a ResourceChangeEvent for a delete is a no-op: the targeted sync's
	// GetResource returns not-found and the stale resource is left behind.
	require.False(t, types.Contains("application.lifecycle.delete"))

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

// Real payloads from a test tenant. Okta sends three targets — AppUser,
// AppInstance and User — so the extra AppUser bucket must not disturb the
// single-AppInstance / single-User expectations.
const appMembershipRemoveFixture = `[
 {"eventType":"application.user_membership.remove","published":"2026-08-25T17:41:22.359Z","uuid":"2fe59500-a0ac-11f1-ae0a-95c6e5af725d",
  "target":[{"id":"0ua16tpeb9kz6QXVf698","type":"AppUser","alternateId":"unknown","displayName":"Target User"},
            {"id":"0oax6rfqm2b7mnaGs697","type":"AppInstance","alternateId":"Okta Admin Console","displayName":"Okta Admin Console"},
            {"id":"00u12xvaouixjW1y3698","type":"User","alternateId":"user@example.com","displayName":"Target User"}]},
 {"eventType":"application.user_membership.remove","published":"2026-08-25T18:19:21.524Z","uuid":"7e628fc1-a0b1-11f1-bf59-8b5627020a34",
  "target":[{"id":"0ua16tp99dorEApPa698","type":"AppUser","alternateId":"user@example.com","displayName":"Target User"},
            {"id":"0oa16scusspsHf5ab698","type":"AppInstance","alternateId":"TestWEbApp01","displayName":"OpenID Connect Client"},
            {"id":"00u12xvaouixjW1y3698","type":"User","alternateId":"user@example.com","displayName":"Target User"}]}
]`

func TestApplicationMembershipRevokeFilterRealPayload(t *testing.T) {
	var events []*oktaSDK.LogEvent
	require.NoError(t, json.Unmarshal([]byte(appMembershipRemoveFixture), &events))
	require.Len(t, events, 2)

	// Entitlement IDs must equal what app.go builds from app.Id, or c1 cannot
	// resolve them and silently drops the event.
	wantEntitlements := []string{
		"app:0oax6rfqm2b7mnaGs697:access",
		"app:0oa16scusspsHf5ab698:access",
	}

	for i, event := range events {
		require.True(t, ApplicationMembershipRevokeFilter.Matches(event))

		rv, err := ApplicationMembershipRevokeFilter.Handle(zap.NewNop(), event)
		require.NoError(t, err)
		require.Equal(t, event.Uuid, rv.Id)

		revoke := rv.GetCreateRevokeEvent()
		require.NotNil(t, revoke)
		require.Equal(t, wantEntitlements[i], revoke.GetEntitlement().GetId())
		require.Equal(t, "00u12xvaouixjW1y3698", revoke.GetPrincipal().GetId().GetResource())
	}
}
