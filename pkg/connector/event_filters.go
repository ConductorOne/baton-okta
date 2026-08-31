package connector

import (
	"fmt"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	sdkEntitlement "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	sdkResource "github.com/conductorone/baton-sdk/pkg/types/resource"
	mapset "github.com/deckarep/golang-set/v2"
	oktaSDK "github.com/okta/okta-sdk-golang/v2/okta"
	"go.uber.org/zap"
)

var (
	GroupChangeFilter = EventFilter{
		EventTypes:  mapset.NewSet("group.lifecycle.create"),
		TargetTypes: mapset.NewSet("UserGroup"),
		EventHandler: func(l *zap.Logger, event *oktaSDK.LogEvent, targetMap map[string][]*oktaSDK.LogTarget, rv *v2.Event) error {
			if len(targetMap["UserGroup"]) != 1 {
				return fmt.Errorf("okta-connectorv2: expected 1 UserGroup target, got %d", len(targetMap["UserGroup"]))
			}
			userGroup := targetMap["UserGroup"][0]
			resourceId := &v2.ResourceId{
				ResourceType: resourceTypeGroup.Id,
				Resource:     userGroup.Id,
			}
			rv.Event = &v2.Event_ResourceChangeEvent{
				ResourceChangeEvent: &v2.ResourceChangeEvent{
					ResourceId: resourceId,
				},
			}
			l.Debug("okta-event-feed: GroupChangeFilter",
				zap.String("event_type", event.EventType),
				zap.String("resource_type", resourceId.ResourceType),
				zap.String("resource_id", resourceId.Resource),
				zap.String("group_display_name", userGroup.DisplayName),
			)
			return nil
		},
	}
	CreateGrantFilter = EventFilter{
		EventTypes:  mapset.NewSet("group.user_membership.add"),
		TargetTypes: mapset.NewSet("UserGroup", oktaLogTargetTypeUser),
		EventHandler: func(l *zap.Logger, event *oktaSDK.LogEvent, targetMap map[string][]*oktaSDK.LogTarget, rv *v2.Event) error {
			if len(targetMap["UserGroup"]) != 1 {
				return fmt.Errorf("okta-connectorv2: expected 1 UserGroup target, got %d", len(targetMap["UserGroup"]))
			}
			userGroup := targetMap["UserGroup"][0]
			if len(targetMap[oktaLogTargetTypeUser]) != 1 {
				return fmt.Errorf("okta-connectorv2: expected 1 User target, got %d", len(targetMap[oktaLogTargetTypeUser]))
			}
			user := targetMap[oktaLogTargetTypeUser][0]

			resource, err := sdkResource.NewResource(userGroup.DisplayName, resourceTypeGroup, userGroup.Id)
			if err != nil {
				return fmt.Errorf("okta-connectorv2: error creating resource: %w", err)
			}

			principal, err := sdkResource.NewResource(user.DisplayName, resourceTypeUser, user.Id)
			if err != nil {
				return fmt.Errorf("okta-connectorv2: error creating resource: %w", err)
			}

			userTrait, err := sdkResource.NewUserTrait(sdkResource.WithEmail(user.AlternateId, true))
			if err != nil {
				return fmt.Errorf("okta-connectorv2: error creating user trait: %w", err)
			}
			principal.Annotations = annotations.New(userTrait)

			rv.Event = &v2.Event_CreateGrantEvent{
				CreateGrantEvent: &v2.CreateGrantEvent{
					Entitlement: sdkEntitlement.NewAssignmentEntitlement(resource, "member"),
					Principal:   principal,
				},
			}

			l.Debug("okta-event-feed: CreateGrantFilter",
				zap.String("event_type", event.EventType),
				zap.String("resource_type", resourceTypeGroup.Id),
				zap.String("resource_id", userGroup.Id),
				zap.String("group_display_name", userGroup.DisplayName),
				zap.String("user_id", user.Id),
			)
			return nil
		},
	}
	CreateRevokeFilter = EventFilter{
		EventTypes:  mapset.NewSet("group.user_membership.remove"),
		TargetTypes: mapset.NewSet("UserGroup", oktaLogTargetTypeUser),
		EventHandler: func(l *zap.Logger, event *oktaSDK.LogEvent, targetMap map[string][]*oktaSDK.LogTarget, rv *v2.Event) error {
			if len(targetMap["UserGroup"]) != 1 {
				return fmt.Errorf("okta-connectorv2: expected 1 UserGroup target, got %d", len(targetMap["UserGroup"]))
			}
			userGroup := targetMap["UserGroup"][0]
			if len(targetMap[oktaLogTargetTypeUser]) != 1 {
				return fmt.Errorf("okta-connectorv2: expected 1 User target, got %d", len(targetMap[oktaLogTargetTypeUser]))
			}
			user := targetMap[oktaLogTargetTypeUser][0]

			resource, err := sdkResource.NewResource(userGroup.DisplayName, resourceTypeGroup, userGroup.Id)
			if err != nil {
				return fmt.Errorf("okta-connectorv2: error creating resource: %w", err)
			}

			principal, err := sdkResource.NewResource(user.DisplayName, resourceTypeUser, user.Id)
			if err != nil {
				return fmt.Errorf("okta-connectorv2: error creating resource: %w", err)
			}

			userTrait, err := sdkResource.NewUserTrait(sdkResource.WithEmail(user.AlternateId, true))
			if err != nil {
				return fmt.Errorf("okta-connectorv2: error creating user trait: %w", err)
			}
			principal.Annotations = annotations.New(userTrait)

			rv.Event = &v2.Event_CreateRevokeEvent{
				CreateRevokeEvent: &v2.CreateRevokeEvent{
					Entitlement: sdkEntitlement.NewAssignmentEntitlement(resource, "member"),
					Principal:   principal,
				},
			}

			l.Debug("okta-event-feed: CreateRevokeFilter",
				zap.String("event_type", event.EventType),
				zap.String("resource_type", resourceTypeGroup.Id),
				zap.String("resource_id", userGroup.Id),
				zap.String("group_display_name", userGroup.DisplayName),
				zap.String("user_id", user.Id),
			)
			return nil
		},
	}
	ApplicationLifecycleFilter = EventFilter{
		// Okta namespaces app lifecycle events under "application.lifecycle". The
		// "app.lifecycle.create" this used to request is not a real event type, so
		// app creations were never picked up.
		//
		// "delete" and "deactivate" are intentionally absent. Both leave the targeted
		// sync with no resource to write: a deleted app is gone, and a deactivated one
		// is filtered out by appResourceType.Get unless sync-inactive-apps is set. The
		// SDK turns that nil resource into NotFound and records a task failure
		// (resource_syncer.go), so emitting them costs a request and a failure metric
		// while leaving the stale resource in place either way.
		EventTypes: mapset.NewSet(
			"application.lifecycle.create",
			"application.lifecycle.update",
			"application.lifecycle.activate",
		),
		TargetTypes: mapset.NewSet("AppInstance"),
		EventHandler: func(l *zap.Logger, event *oktaSDK.LogEvent, targetMap map[string][]*oktaSDK.LogTarget, rv *v2.Event) error {
			if len(targetMap["AppInstance"]) != 1 {
				return fmt.Errorf("okta-connectorv2: expected 1 AppInstance target, got %d", len(targetMap["AppInstance"]))
			}
			appInstance := targetMap["AppInstance"][0]
			resourceId := &v2.ResourceId{
				ResourceType: resourceTypeApp.Id,
				Resource:     appInstance.Id,
			}
			rv.Event = &v2.Event_ResourceChangeEvent{
				ResourceChangeEvent: &v2.ResourceChangeEvent{
					ResourceId: resourceId,
				},
			}
			l.Debug("okta-event-feed: ApplicationLifecycleFilter",
				zap.String("event_type", event.EventType),
				zap.String("resource_type", resourceId.ResourceType),
				zap.String("resource_id", resourceId.Resource),
				zap.String("app_display_name", appInstance.DisplayName),
			)
			return nil
		},
	}
	ApplicationMembershipFilter = EventFilter{
		EventTypes:  mapset.NewSet("application.user_membership.add"),
		TargetTypes: mapset.NewSet("AppInstance", oktaLogTargetTypeUser),
		EventHandler: func(l *zap.Logger, event *oktaSDK.LogEvent, targetMap map[string][]*oktaSDK.LogTarget, rv *v2.Event) error {
			if len(targetMap["AppInstance"]) != 1 {
				return fmt.Errorf("okta-connectorv2: expected 1 AppInstance target, got %d", len(targetMap["AppInstance"]))
			}
			if len(targetMap[oktaLogTargetTypeUser]) != 1 {
				return fmt.Errorf("okta-connectorv2: expected 1 User target, got %d", len(targetMap[oktaLogTargetTypeUser]))
			}
			user := targetMap[oktaLogTargetTypeUser][0]
			appInstance := targetMap["AppInstance"][0]

			resource, err := sdkResource.NewResource(appInstance.DisplayName, resourceTypeApp, appInstance.Id)
			if err != nil {
				return fmt.Errorf("okta-connectorv2: error creating resource: %w", err)
			}

			principal, err := sdkResource.NewResource(user.DisplayName, resourceTypeUser, user.Id)
			if err != nil {
				return fmt.Errorf("okta-connectorv2: error creating resource: %w", err)
			}

			userTrait, err := sdkResource.NewUserTrait(sdkResource.WithEmail(user.AlternateId, true))
			if err != nil {
				return fmt.Errorf("okta-connectorv2: error creating user trait: %w", err)
			}
			principal.Annotations = annotations.New(userTrait)

			rv.Event = &v2.Event_CreateGrantEvent{
				CreateGrantEvent: &v2.CreateGrantEvent{
					Entitlement: sdkEntitlement.NewAssignmentEntitlement(resource, "access"),
					Principal:   principal,
				},
			}

			l.Debug("okta-event-feed: ApplicationMembershipFilter",
				zap.String("event_type", event.EventType),
				zap.String("resource_type", resourceTypeApp.Id),
				zap.String("resource_id", appInstance.Id),
				zap.String("app_display_name", appInstance.DisplayName),
				zap.String("user_id", user.Id),
			)
			return nil
		},
	}
	ApplicationMembershipRevokeFilter = EventFilter{
		EventTypes:  mapset.NewSet("application.user_membership.remove"),
		TargetTypes: mapset.NewSet("AppInstance", oktaLogTargetTypeUser),
		EventHandler: func(l *zap.Logger, event *oktaSDK.LogEvent, targetMap map[string][]*oktaSDK.LogTarget, rv *v2.Event) error {
			if len(targetMap["AppInstance"]) != 1 {
				return fmt.Errorf("okta-connectorv2: expected 1 AppInstance target, got %d", len(targetMap["AppInstance"]))
			}
			if len(targetMap[oktaLogTargetTypeUser]) != 1 {
				return fmt.Errorf("okta-connectorv2: expected 1 User target, got %d", len(targetMap[oktaLogTargetTypeUser]))
			}
			user := targetMap[oktaLogTargetTypeUser][0]
			appInstance := targetMap["AppInstance"][0]

			resource, err := sdkResource.NewResource(appInstance.DisplayName, resourceTypeApp, appInstance.Id)
			if err != nil {
				return fmt.Errorf("okta-connectorv2: error creating resource: %w", err)
			}

			principal, err := sdkResource.NewResource(user.DisplayName, resourceTypeUser, user.Id)
			if err != nil {
				return fmt.Errorf("okta-connectorv2: error creating resource: %w", err)
			}

			userTrait, err := sdkResource.NewUserTrait(sdkResource.WithEmail(user.AlternateId, true))
			if err != nil {
				return fmt.Errorf("okta-connectorv2: error creating user trait: %w", err)
			}
			principal.Annotations = annotations.New(userTrait)

			rv.Event = &v2.Event_CreateRevokeEvent{
				CreateRevokeEvent: &v2.CreateRevokeEvent{
					Entitlement: sdkEntitlement.NewAssignmentEntitlement(resource, "access"),
					Principal:   principal,
				},
			}

			l.Debug("okta-event-feed: ApplicationMembershipRevokeFilter",
				zap.String("event_type", event.EventType),
				zap.String("resource_type", resourceTypeApp.Id),
				zap.String("resource_id", appInstance.Id),
				zap.String("app_display_name", appInstance.DisplayName),
				zap.String("user_id", user.Id),
			)
			return nil
		},
	}
	RoleMembershipFilter = EventFilter{
		// Okta reports both assignment and unassignment of standard admin roles under
		// this one event type, distinguishing them with an extra ROLE_ASSIGNED or
		// ROLE_UNASSIGNED target, so an unassignment has to emit a revoke. Custom role
		// bindings (CUSTOM_ROLE_BINDING_ADDED / _REMOVED) reuse the event type as well
		// but carry no ROLE target and belong to the custom-role resource type, so they
		// are skipped here.
		//
		// user.account.privilege.revoke covers only the removal of a user's last role;
		// RoleMembershipRevokeFilter handles that case.
		EventTypes:  mapset.NewSet("user.account.privilege.grant"),
		TargetTypes: mapset.NewSet("ROLE", oktaLogTargetTypeUser),
		EventHandler: func(l *zap.Logger, event *oktaSDK.LogEvent, targetMap map[string][]*oktaSDK.LogTarget, rv *v2.Event) error {
			assigned := len(targetMap[oktaLogTargetRoleAssigned]) > 0
			unassigned := len(targetMap[oktaLogTargetRoleUnassigned]) > 0

			switch {
			case assigned && unassigned:
				return fmt.Errorf("okta-connectorv2: event has both %s and %s targets", oktaLogTargetRoleAssigned, oktaLogTargetRoleUnassigned)
			case !assigned && !unassigned:
				// Custom role bindings land here, as would any discriminator Okta adds
				// later. Defaulting to a grant would reaffirm access that may have just
				// been removed, so skip rather than guess.
				l.Debug("okta-event-feed: RoleMembershipFilter: no role assignment discriminator, skipping",
					zap.String("event_type", event.EventType),
					zap.String("event_id", event.Uuid),
				)
				return nil
			}

			if len(targetMap["ROLE"]) != 1 {
				return fmt.Errorf("okta-connectorv2: expected 1 ROLE target, got %d", len(targetMap["ROLE"]))
			}
			role := targetMap["ROLE"][0]

			if len(targetMap[oktaLogTargetTypeUser]) != 1 {
				return fmt.Errorf("okta-connectorv2: expected 1 User target, got %d", len(targetMap[oktaLogTargetTypeUser]))
			}
			user := targetMap[oktaLogTargetTypeUser][0]

			// The ROLE target's id is a camelCase name ("UserAdmin") and its alternateId
			// is an assignment identifier, so neither is the role type the sync uses as a
			// resource ID. Look it up by label instead.
			roleType := StandardRoleTypeFromLabel(role.DisplayName)
			if roleType == nil {
				// Expected for custom roles and for any label missing from
				// standardRoleTypes; there is no resource to point an event at.
				l.Debug("okta-event-feed: RoleMembershipFilter: no standard role for label, skipping",
					zap.String("role_display_name", role.DisplayName),
					zap.String("event_id", event.Uuid),
				)
				return nil
			}

			roleResource, err := sdkResource.NewResource(role.DisplayName, resourceTypeRole, roleType.Type)
			if err != nil {
				return fmt.Errorf("okta-connectorv2: error creating resource: %w", err)
			}

			principal, err := sdkResource.NewResource(user.DisplayName, resourceTypeUser, user.Id)
			if err != nil {
				return fmt.Errorf("okta-connectorv2: error creating resource: %w", err)
			}

			userTrait, err := sdkResource.NewUserTrait(sdkResource.WithEmail(user.AlternateId, true))
			if err != nil {
				return fmt.Errorf("okta-connectorv2: error creating user trait: %w", err)
			}
			principal.Annotations = annotations.New(userTrait)

			entitlement := sdkEntitlement.NewAssignmentEntitlement(roleResource, "assigned")
			if assigned {
				rv.Event = &v2.Event_CreateGrantEvent{
					CreateGrantEvent: &v2.CreateGrantEvent{
						Entitlement: entitlement,
						Principal:   principal,
					},
				}
			} else {
				rv.Event = &v2.Event_CreateRevokeEvent{
					CreateRevokeEvent: &v2.CreateRevokeEvent{
						Entitlement: entitlement,
						Principal:   principal,
					},
				}
			}

			l.Debug("okta-event-feed: RoleMembershipFilter",
				zap.String("event_type", event.EventType),
				zap.Bool("assigned", assigned),
				zap.String("resource_type", resourceTypeRole.Id),
				zap.String("resource_id", roleType.Type),
				zap.String("role_display_name", role.DisplayName),
				zap.String("user_id", user.Id),
			)
			return nil
		},
	}
	RoleMembershipRevokeFilter = EventFilter{
		EventTypes:  mapset.NewSet("user.account.privilege.revoke"),
		TargetTypes: mapset.NewSet("ROLE", oktaLogTargetTypeUser),
		EventHandler: func(l *zap.Logger, event *oktaSDK.LogEvent, targetMap map[string][]*oktaSDK.LogTarget, rv *v2.Event) error {
			if len(targetMap["ROLE"]) != 1 {
				return fmt.Errorf("okta-connectorv2: expected 1 ROLE target, got %d", len(targetMap["ROLE"]))
			}
			role := targetMap["ROLE"][0]

			if len(targetMap[oktaLogTargetTypeUser]) != 1 {
				return fmt.Errorf("okta-connectorv2: expected 1 User target, got %d", len(targetMap[oktaLogTargetTypeUser]))
			}
			user := targetMap[oktaLogTargetTypeUser][0]

			// Same as RoleMembershipFilter: privilege events don't carry a usable
			// role ID or type, so resolve the standard role by its label.
			roleType := StandardRoleTypeFromLabel(role.DisplayName)
			if roleType == nil {
				l.Debug("okta-event-feed: RoleMembershipRevokeFilter: no standard role for label, skipping",
					zap.String("role_display_name", role.DisplayName),
					zap.String("event_id", event.Uuid),
				)
				return nil
			}

			roleResource, err := sdkResource.NewResource(role.DisplayName, resourceTypeRole, roleType.Type)
			if err != nil {
				return fmt.Errorf("okta-connectorv2: error creating resource: %w", err)
			}

			principal, err := sdkResource.NewResource(user.DisplayName, resourceTypeUser, user.Id)
			if err != nil {
				return fmt.Errorf("okta-connectorv2: error creating resource: %w", err)
			}

			userTrait, err := sdkResource.NewUserTrait(sdkResource.WithEmail(user.AlternateId, true))
			if err != nil {
				return fmt.Errorf("okta-connectorv2: error creating user trait: %w", err)
			}
			principal.Annotations = annotations.New(userTrait)

			rv.Event = &v2.Event_CreateRevokeEvent{
				CreateRevokeEvent: &v2.CreateRevokeEvent{
					Entitlement: sdkEntitlement.NewAssignmentEntitlement(roleResource, "assigned"),
					Principal:   principal,
				},
			}

			l.Debug("okta-event-feed: RoleMembershipRevokeFilter",
				zap.String("event_type", event.EventType),
				zap.String("resource_type", resourceTypeRole.Id),
				zap.String("resource_id", roleType.Type),
				zap.String("role_display_name", role.DisplayName),
				zap.String("user_id", user.Id),
			)
			return nil
		},
	}
	UserLifecycleFilter = EventFilter{
		EventTypes: mapset.NewSet(
			"user.lifecycle.create",
			"user.lifecycle.activate",
			"user.account.update_profile",
			"user.lifecycle.deactivate",
			"user.lifecycle.suspend",
			"user.lifecycle.unsuspend",
			"user.lifecycle.reactivate",
		),
		TargetTypes: mapset.NewSet(oktaLogTargetTypeUser),
		EventHandler: func(_ *zap.Logger, event *oktaSDK.LogEvent, targetMap map[string][]*oktaSDK.LogTarget, rv *v2.Event) error {
			if len(targetMap[oktaLogTargetTypeUser]) != 1 {
				return fmt.Errorf("okta-connectorv2: expected 1 User target, got %d", len(targetMap[oktaLogTargetTypeUser]))
			}
			user := targetMap[oktaLogTargetTypeUser][0]
			rv.Event = &v2.Event_ResourceChangeEvent{
				ResourceChangeEvent: &v2.ResourceChangeEvent{
					ResourceId: &v2.ResourceId{
						ResourceType: resourceTypeUser.Id,
						Resource:     user.Id,
					},
				},
			}
			return nil
		},
	}
	UsageFilter = EventFilter{
		EventTypes:  mapset.NewSet("user.authentication.sso"),
		ActorType:   oktaLogTargetTypeUser,
		TargetTypes: mapset.NewSet("AppInstance"),
		EventHandler: func(_ *zap.Logger, event *oktaSDK.LogEvent, targetMap map[string][]*oktaSDK.LogTarget, rv *v2.Event) error {
			if len(targetMap["AppInstance"]) != 1 {
				return fmt.Errorf("okta-connectorv2: expected 1 AppInstance target, got %d", len(targetMap["AppInstance"]))
			}
			appInstance := targetMap["AppInstance"][0]
			userTrait, err := sdkResource.NewUserTrait(sdkResource.WithEmail(event.Actor.AlternateId, true))
			if err != nil {
				return err
			}
			rv.Event = &v2.Event_UsageEvent{
				UsageEvent: &v2.UsageEvent{
					TargetResource: &v2.Resource{
						Id: &v2.ResourceId{
							ResourceType: resourceTypeApp.Id,
							Resource:     appInstance.Id,
						},
						DisplayName: appInstance.DisplayName,
					},
					ActorResource: &v2.Resource{
						Id: &v2.ResourceId{
							ResourceType: resourceTypeUser.Id,
							Resource:     event.Actor.Id,
						},
						DisplayName: event.Actor.DisplayName,
						Annotations: annotations.New(userTrait),
					},
				},
			}
			return nil
		},
	}
)
