package connector

import (
	"context"
	"fmt"

	sdkResource "github.com/conductorone/baton-sdk/pkg/types/resource"
	oktav5 "github.com/conductorone/okta-sdk-golang/v5/okta"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/ratelimit"
	sdkEntitlement "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

type customRoleResourceType struct {
	resourceType *v2.ResourceType
	connector    *Okta
}

func (o *customRoleResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *customRoleResourceType) List(
	ctx context.Context,
	resourceID *v2.ResourceId,
	token *pagination.Token,
) ([]*v2.Resource, string, annotations.Annotations, error) {
	bag, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeCustomRole.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	response, nextPage, annon, err := paginateV5(ctx, o.connector.clientV5, page, func(ctx2 context.Context) (*oktav5.IamRoles, *oktav5.APIResponse, error) {
		return o.connector.clientV5.RoleAPI.ListRoles(ctx).Execute()
	})
	if err != nil {
		return nil, "", annon, err
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, "", nil, err
	}

	rv := make([]*v2.Resource, 0)
	for _, role := range response.Roles {
		resource, err := customRoleResourceV5(ctx, &role)
		if err != nil {
			return nil, "", annon, fmt.Errorf("okta-connectorv2: failed to create ustom role resource: %w", err)
		}

		rv = append(rv, resource)
	}

	pageToken, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, err
	}

	return rv, pageToken, annon, nil
}

func (o *customRoleResourceType) Entitlements(
	ctx context.Context,
	resource *v2.Resource,
	token *pagination.Token,
) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement

	role := &oktav5.IamRole{
		Id:    oktav5.PtrString(resource.Id.Resource),
		Label: resource.DisplayName,
	}

	en := sdkEntitlement.NewAssignmentEntitlement(resource, "assigned",
		sdkEntitlement.WithDisplayName(fmt.Sprintf("%s Role Member", role.Label)),
		sdkEntitlement.WithDescription(fmt.Sprintf("Has the %s role in Okta", role.Label)),
		sdkEntitlement.WithAnnotation(&v2.V1Identifier{
			Id: V1MembershipEntitlementID(*role.Id),
		}),
		sdkEntitlement.WithGrantableTo(resourceTypeUser, resourceTypeGroup),
	)
	rv = append(rv, en)

	return rv, "", nil, nil
}

// listGroupAssignedRolesV5
// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleAssignmentBGroup/#tag/RoleAssignmentBGroup/operation/listGroupAssignedRoles
func listGroupAssignedRolesV5(ctx context.Context, client *oktav5.APIClient, groupId string) ([]oktav5.Role, *oktav5.APIResponse, error) {
	return client.RoleAssignmentAPI.ListGroupAssignedRoles(ctx, groupId).Execute()
}

// listAssignedRolesForUserV5. List all user role assignments.
// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleAssignmentAUser/#tag/RoleAssignmentAUser/operation/listAssignedRolesForUser
func listAssignedRolesForUserV5(ctx context.Context, client *oktav5.APIClient, userId string) ([]oktav5.Role, *oktav5.APIResponse, error) {
	return client.RoleAssignmentAPI.ListAssignedRolesForUser(ctx, userId).Execute()
}

func (o *customRoleResourceType) Grants(
	ctx context.Context,
	resource *v2.Resource,
	token *pagination.Token,
) ([]*v2.Grant, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	var rv []*v2.Grant

	bag, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeCustomRole.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	usersWithRoleAssignments, nextPage, annos, err := paginateV5(ctx, o.connector.clientV5, page, func(ctx2 context.Context) (*oktav5.RoleAssignedUsers, *oktav5.APIResponse, error) {
		return listAllUsersWithRoleAssignmentsV5(ctx, o.connector.clientV5)
	})

	if err != nil {
		return nil, "", annos, err
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
	}

	for _, user := range usersWithRoleAssignments.Value {
		if user.Id == nil {
			l.Warn("user has no ID, skipping", zap.Any("user", user))
			continue
		}

		userId := *user.Id

		userRoles, err := o.getUserRolesFromCache(ctx, userId)
		if err != nil {
			return nil, "", nil, err
		}

		if userRoles == nil {
			userRoles = mapset.NewSet[string]()
			roles, resp, err := listAssignedRolesForUserV5(ctx, o.connector.clientV5, userId)
			if err != nil {
				anno, err := wrapErrorV5(resp, err)
				return nil, "", anno, err
			}

			for _, role := range roles {
				if role.Id == nil || role.Status == nil || role.AssignmentType == nil {
					continue
				}

				if *role.Status == roleStatusInactive || *role.AssignmentType != "USER" {
					continue
				}

				if *role.Type == roleTypeCustom {
					userRoles.Add(*role.Id)
				} else {
					userRoles.Add(*role.Type)
				}
			}

			o.connector.userRoleCache.Store(userId, userRoles)
		}

		if userRoles.ContainsOne(resource.Id.GetResource()) {
			rv = append(rv, roleGrant(userId, resource))
		}
	}

	pageToken, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, err
	}

	return rv, pageToken, annos, nil
}

func (o *customRoleResourceType) getUserRolesFromCache(ctx context.Context, userId string) (mapset.Set[string], error) {
	appUserRoleCacheVal, ok := o.connector.userRoleCache.Load(userId)
	if !ok {
		return nil, nil
	}
	userRoles, ok := appUserRoleCacheVal.(mapset.Set[string])
	if !ok {
		return nil, fmt.Errorf("error converting user '%s' roles map from cache", userId)
	}
	return userRoles, nil
}

func (o *customRoleResourceType) Get(ctx context.Context, resourceId *v2.ResourceId, parentResourceId *v2.ResourceId) (*v2.Resource, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	l.Debug("getting custom role", zap.String("role_id", resourceId.Resource))

	var annos annotations.Annotations

	roleId := resourceId.Resource

	role, resp, err := o.connector.clientV5.RoleAPI.GetRole(ctx, roleId).Execute()
	if err != nil {
		anno, err := wrapErrorV5(resp, err)
		return nil, anno, err
	}

	if resp != nil {
		if desc, err := ratelimit.ExtractRateLimitData(resp.StatusCode, &resp.Header); err == nil {
			annos.WithRateLimiting(desc)
		}
	}

	resource, err := customRoleResourceV5(ctx, role)
	if err != nil {
		return nil, annos, err
	}

	return resource, annos, nil
}

func customRoleResourceV5(ctx context.Context, role *oktav5.IamRole) (*v2.Resource, error) {
	var objectID = role.Label
	if nullableStr(role.Id) != "" {
		objectID = *role.Id
	}

	profile := map[string]interface{}{
		"id":    nullableStr(role.Id),
		"label": role.Label,
	}

	return sdkResource.NewRoleResource(
		role.Label,
		resourceTypeCustomRole,
		objectID,
		[]sdkResource.RoleTraitOption{sdkResource.WithRoleProfile(profile)},
		sdkResource.WithAnnotation(&v2.V1Identifier{
			Id: fmtResourceIdV1(objectID),
		}),
	)
}

func customRoleBuilder(connector *Okta) *customRoleResourceType {
	return &customRoleResourceType{
		resourceType: resourceTypeCustomRole,
		connector:    connector,
	}
}
