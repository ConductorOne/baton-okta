package connector

import (
	"fmt"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
	mapset "github.com/deckarep/golang-set/v2"
	oktaSDK "github.com/okta/okta-sdk-golang/v2/okta"
)

var (
	GroupChangeFilter = EventFilter{
		EventTypes:  mapset.NewSet[string]("group.user_membership.add", "group.user_membership.remove", "group.lifecycle.create", "group.lifecycle.delete"),
		TargetTypes: mapset.NewSet[string]("UserGroup"),
		EventHandler: func(event *oktaSDK.LogEvent, targetMap map[string][]*oktaSDK.LogTarget, rv *v2.Event) error {
			if len(targetMap["UserGroup"]) != 1 {
				return fmt.Errorf("okta-connectorv2: expected 1 UserGroup target, got %d", len(targetMap["UserGroup"]))
			}
			userGroup := targetMap["UserGroup"][0]
			rv.Event = &v2.Event_ResourceChangeEvent{
				ResourceChangeEvent: &v2.ResourceChangeEvent{
					ResourceId: &v2.ResourceId{
						ResourceType: resourceTypeGroup.Id,
						Resource:     userGroup.Id,
					},
				},
			}
			return nil
		},
	}
	ApplicationLifecycleFilter = EventFilter{
		EventTypes:  mapset.NewSet[string]("app.lifecycle.create", "app.lifecycle.delete", "application.lifecycle.update"),
		TargetTypes: mapset.NewSet[string]("AppInstance"),
		EventHandler: func(event *oktaSDK.LogEvent, targetMap map[string][]*oktaSDK.LogTarget, rv *v2.Event) error {
			if len(targetMap["AppInstance"]) != 1 {
				return fmt.Errorf("okta-connectorv2: expected 1 AppInstance target, got %d", len(targetMap["AppInstance"]))
			}
			appInstance := targetMap["AppInstance"][0]
			rv.Event = &v2.Event_ResourceChangeEvent{
				ResourceChangeEvent: &v2.ResourceChangeEvent{
					ResourceId: &v2.ResourceId{
						ResourceType: resourceTypeApp.Id,
						Resource:     appInstance.Id,
					},
				},
			}
			return nil
		},
	}
	ApplicationMembershipFilter = EventFilter{
		EventTypes:  mapset.NewSet[string]("application.user_membership.add", "application.user_membership.remove", "application.user_membership.update"),
		TargetTypes: mapset.NewSet[string]("AppInstance"),
		EventHandler: func(event *oktaSDK.LogEvent, targetMap map[string][]*oktaSDK.LogTarget, rv *v2.Event) error {
			if len(targetMap["AppInstance"]) != 1 {
				return fmt.Errorf("okta-connectorv2: expected 1 AppInstance target, got %d", len(targetMap["AppInstance"]))
			}
			appInstance := targetMap["AppInstance"][0]
			rv.Event = &v2.Event_ResourceChangeEvent{
				ResourceChangeEvent: &v2.ResourceChangeEvent{
					ResourceId: &v2.ResourceId{
						ResourceType: resourceTypeApp.Id,
						Resource:     appInstance.Id,
					},
				},
			}
			return nil
		},
	}
	RoleMembershipFilter = EventFilter{
		EventTypes:  mapset.NewSet[string]("user.account.privilege.grant", "user.account.privilege.revoke"),
		TargetTypes: mapset.NewSet[string]("ROLE", "User"),
		EventHandler: func(event *oktaSDK.LogEvent, targetMap map[string][]*oktaSDK.LogTarget, rv *v2.Event) error {
			if len(targetMap["ROLE"]) != 1 {
				return fmt.Errorf("okta-connectorv2: expected 1 ROLE target, got %d", len(targetMap["ROLE"]))
			}
			role := targetMap["ROLE"][0]

			// for some reason we don't get the role ID (or type) formatted properly.
			// hack to look it up via DisplayName
			roleType := StandardRoleTypeFromLabel(role.DisplayName)
			if roleType == nil {
				return fmt.Errorf("okta-connectorv2: expected 1 ROLE target, got %d", len(targetMap["ROLE"]))
			}

			rv.Event = &v2.Event_ResourceChangeEvent{
				ResourceChangeEvent: &v2.ResourceChangeEvent{
					ResourceId: &v2.ResourceId{
						ResourceType: resourceTypeRole.Id,
						Resource:     roleType.Type,
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
		EventHandler: func(event *oktaSDK.LogEvent, targetMap map[string][]*oktaSDK.LogTarget, rv *v2.Event) error {
			if len(targetMap["AppInstance"]) != 1 {
				return fmt.Errorf("okta-connectorv2: expected 1 AppInstance target, got %d", len(targetMap["AppInstance"]))
			}
			appInstance := targetMap["AppInstance"][0]
			userTrait, err := resource.NewUserTrait(resource.WithEmail(event.Actor.AlternateId, true))
			if err != nil {
				return err
			}
			rv.Event = &v2.Event_UsageEvent{
				UsageEvent: &v2.UsageEvent{
					TargetResource: &v2.Resource{
						Id: &v2.ResourceId{
							ResourceType: appInstance.Type,
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
