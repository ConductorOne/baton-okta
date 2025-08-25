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
		EventHandler: func(l *zap.Logger, event *oktaSDK.LogEvent, targetMap map[string][]*oktaSDK.LogTarget, rv *v2.Event) (bool, error) {
			if len(targetMap["UserGroup"]) != 1 {
				return false, fmt.Errorf("okta-connectorv2: expected 1 UserGroup target, got %d", len(targetMap["UserGroup"]))
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
			return true, nil
		},
	}
	CreateGrantFilter = EventFilter{
		EventTypes:  mapset.NewSet[string]("group.user_membership.add"),
		TargetTypes: mapset.NewSet[string]("UserGroup", "User"),
		EventHandler: func(l *zap.Logger, event *oktaSDK.LogEvent, targetMap map[string][]*oktaSDK.LogTarget, rv *v2.Event) (bool, error) {
			if len(targetMap["UserGroup"]) != 1 {
				return false, fmt.Errorf("okta-connectorv2: expected 1 UserGroup target, got %d", len(targetMap["UserGroup"]))
			}
			userGroup := targetMap["UserGroup"][0]
			if len(targetMap["User"]) != 1 {
				return false, fmt.Errorf("okta-connectorv2: expected 1 User target, got %d", len(targetMap["User"]))
			}
			user := targetMap["User"][0]

			resource, err := sdkResource.NewResource(userGroup.DisplayName, resourceTypeGroup, userGroup.Id)
			if err != nil {
				return false, fmt.Errorf("okta-connectorv2: error creating resource: %w", err)
			}

			principal, err := sdkResource.NewResource(user.DisplayName, resourceTypeUser, user.Id)
			if err != nil {
				return false, fmt.Errorf("okta-connectorv2: error creating resource: %w", err)
			}

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
			return true, nil
		},
	}
	ApplicationLifecycleFilter = EventFilter{
		EventTypes:  mapset.NewSet[string]("app.lifecycle.create", "application.lifecycle.update"),
		TargetTypes: mapset.NewSet[string]("AppInstance"),
		EventHandler: func(l *zap.Logger, event *oktaSDK.LogEvent, targetMap map[string][]*oktaSDK.LogTarget, rv *v2.Event) (bool, error) {
			if len(targetMap["AppInstance"]) != 1 {
				return false, fmt.Errorf("okta-connectorv2: expected 1 AppInstance target, got %d", len(targetMap["AppInstance"]))
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
			return true, nil
		},
	}
	ApplicationMembershipFilter = EventFilter{
		EventTypes:  mapset.NewSet[string]("application.user_membership.add", "application.user_membership.update", "group.application_assignment.add"),
		TargetTypes: mapset.NewSet[string]("AppInstance"),
		EventHandler: func(l *zap.Logger, event *oktaSDK.LogEvent, targetMap map[string][]*oktaSDK.LogTarget, rv *v2.Event) (bool, error) {
			if len(targetMap["AppInstance"]) != 1 {
				return false, fmt.Errorf("okta-connectorv2: expected 1 AppInstance target, got %d", len(targetMap["AppInstance"]))
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

			// Filter out job transactions for application.user_membership.add events. We assume these are triggered by the
			// group.application_assignment.add event for each user in the group.
			if event.EventType == "application.user_membership.add" && event.Transaction.Type == "JOB" {
				l.Debug("okta-event-feed: ApplicationMembershipFilter - skipping job transaction",
					zap.String("event_type", event.EventType),
					zap.String("resource_type", resourceId.ResourceType),
					zap.String("resource_id", resourceId.Resource),
					zap.String("app_display_name", appInstance.DisplayName),
					zap.String("transaction_type", event.Transaction.Type),
				)
				return false, nil
			}

			l.Debug("okta-event-feed: ApplicationMembershipFilter",
				zap.String("event_type", event.EventType),
				zap.String("resource_type", resourceId.ResourceType),
				zap.String("resource_id", resourceId.Resource),
				zap.String("app_display_name", appInstance.DisplayName),
				zap.String("transaction_type", event.Transaction.Type),
			)
			return true, nil
		},
	}
	RoleMembershipFilter = EventFilter{
		EventTypes:  mapset.NewSet[string]("user.account.privilege.grant"),
		TargetTypes: mapset.NewSet[string]("ROLE", "User"),
		EventHandler: func(_ *zap.Logger, event *oktaSDK.LogEvent, targetMap map[string][]*oktaSDK.LogTarget, rv *v2.Event) (bool, error) {
			if len(targetMap["ROLE"]) != 1 {
				return false, fmt.Errorf("okta-connectorv2: expected 1 ROLE target, got %d", len(targetMap["ROLE"]))
			}
			role := targetMap["ROLE"][0]

			// for some reason we don't get the role ID (or type) formatted properly.
			// hack to look it up via DisplayName
			roleType := StandardRoleTypeFromLabel(role.DisplayName)
			if roleType == nil {
				return false, fmt.Errorf("okta-connectorv2: error getting role from label: %s", role.DisplayName)
			}

			rv.Event = &v2.Event_ResourceChangeEvent{
				ResourceChangeEvent: &v2.ResourceChangeEvent{
					ResourceId: &v2.ResourceId{
						ResourceType: resourceTypeRole.Id,
						Resource:     roleType.Type,
					},
				},
			}
			return true, nil
		},
	}
	UserLifecycleFilter = EventFilter{
		EventTypes:  mapset.NewSet[string]("user.lifecycle.create", "user.lifecycle.activate", "user.account.update_profile"),
		TargetTypes: mapset.NewSet[string]("User"),
		EventHandler: func(_ *zap.Logger, event *oktaSDK.LogEvent, targetMap map[string][]*oktaSDK.LogTarget, rv *v2.Event) (bool, error) {
			if len(targetMap["User"]) != 1 {
				return false, fmt.Errorf("okta-connectorv2: expected 1 User target, got %d", len(targetMap["User"]))
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
			return true, nil
		},
	}
	UsageFilter = EventFilter{
		EventTypes:  mapset.NewSet[string]("user.authentication.sso"),
		ActorType:   "User",
		TargetTypes: mapset.NewSet[string]("AppInstance"),
		EventHandler: func(_ *zap.Logger, event *oktaSDK.LogEvent, targetMap map[string][]*oktaSDK.LogTarget, rv *v2.Event) (bool, error) {
			if len(targetMap["AppInstance"]) != 1 {
				return false, fmt.Errorf("okta-connectorv2: expected 1 AppInstance target, got %d", len(targetMap["AppInstance"]))
			}
			appInstance := targetMap["AppInstance"][0]
			userTrait, err := sdkResource.NewUserTrait(sdkResource.WithEmail(event.Actor.AlternateId, true))
			if err != nil {
				return false, err
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
			return true, nil
		},
	}
)
