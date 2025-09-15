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
		EventTypes:  mapset.NewSet[string]("group.lifecycle.create"),
		TargetTypes: mapset.NewSet[string]("UserGroup"),
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
		EventTypes:  mapset.NewSet[string]("group.user_membership.add"),
		TargetTypes: mapset.NewSet[string]("UserGroup", "User"),
		EventHandler: func(l *zap.Logger, event *oktaSDK.LogEvent, targetMap map[string][]*oktaSDK.LogTarget, rv *v2.Event) error {
			if len(targetMap["UserGroup"]) != 1 {
				return fmt.Errorf("okta-connectorv2: expected 1 UserGroup target, got %d", len(targetMap["UserGroup"]))
			}
			userGroup := targetMap["UserGroup"][0]
			if len(targetMap["User"]) != 1 {
				return fmt.Errorf("okta-connectorv2: expected 1 User target, got %d", len(targetMap["User"]))
			}
			user := targetMap["User"][0]

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
	ApplicationLifecycleFilter = EventFilter{
		EventTypes:  mapset.NewSet[string]("app.lifecycle.create", "application.lifecycle.update"),
		TargetTypes: mapset.NewSet[string]("AppInstance"),
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
		EventTypes:  mapset.NewSet[string]("application.user_membership.add"),
		TargetTypes: mapset.NewSet[string]("AppInstance", "User"),
		EventHandler: func(l *zap.Logger, event *oktaSDK.LogEvent, targetMap map[string][]*oktaSDK.LogTarget, rv *v2.Event) error {
			if len(targetMap["AppInstance"]) != 1 {
				return fmt.Errorf("okta-connectorv2: expected 1 AppInstance target, got %d", len(targetMap["AppInstance"]))
			}
			if len(targetMap["User"]) != 1 {
				return fmt.Errorf("okta-connectorv2: expected 1 User target, got %d", len(targetMap["User"]))
			}
			user := targetMap["User"][0]
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
	RoleMembershipFilter = EventFilter{
		EventTypes:  mapset.NewSet[string]("user.account.privilege.grant"),
		TargetTypes: mapset.NewSet[string]("ROLE", "User"),
		EventHandler: func(_ *zap.Logger, event *oktaSDK.LogEvent, targetMap map[string][]*oktaSDK.LogTarget, rv *v2.Event) error {
			if len(targetMap["ROLE"]) != 1 {
				return fmt.Errorf("okta-connectorv2: expected 1 ROLE target, got %d", len(targetMap["ROLE"]))
			}
			role := targetMap["ROLE"][0]

			if len(targetMap["User"]) != 1 {
				return fmt.Errorf("okta-connectorv2: expected 1 User target, got %d", len(targetMap["User"]))
			}
			user := targetMap["User"][0]

			// for some reason we don't get the role ID (or type) formatted properly.
			// hack to look it up via DisplayName
			roleType := StandardRoleTypeFromLabel(role.DisplayName)
			if roleType == nil {
				return fmt.Errorf("okta-connectorv2: error getting role from label: %s", role.DisplayName)
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

			rv.Event = &v2.Event_CreateGrantEvent{
				CreateGrantEvent: &v2.CreateGrantEvent{
					Entitlement: sdkEntitlement.NewAssignmentEntitlement(roleResource, "assigned"),
					Principal:   principal,
				},
			}
			return nil
		},
	}
	UserLifecycleFilter = EventFilter{
		EventTypes:  mapset.NewSet[string]("user.lifecycle.create", "user.lifecycle.activate", "user.account.update_profile"),
		TargetTypes: mapset.NewSet[string]("User"),
		EventHandler: func(_ *zap.Logger, event *oktaSDK.LogEvent, targetMap map[string][]*oktaSDK.LogTarget, rv *v2.Event) error {
			if len(targetMap["User"]) != 1 {
				return fmt.Errorf("okta-connectorv2: expected 1 User target, got %d", len(targetMap["User"]))
			}
			user := targetMap["User"][0]
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
		EventTypes:  mapset.NewSet[string]("user.authentication.sso"),
		ActorType:   "User",
		TargetTypes: mapset.NewSet[string]("AppInstance"),
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
