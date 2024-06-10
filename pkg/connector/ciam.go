package connector

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	sdkEntitlement "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"go.uber.org/zap"
)

type ciamUserBuilder struct{}

func (c *ciamUserBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return resourceTypeUser
}

func (c *ciamUserBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func (c *ciamUserBuilder) Entitlements(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func (c *ciamUserBuilder) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func ciamUser() *ciamUserBuilder {
	return &ciamUserBuilder{}
}

type ciamResourceBuilder struct {
	client *okta.Client
}

func (o *ciamResourceBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	bag := &pagination.Bag{}
	err := bag.Unmarshal(pToken.Token)

	if bag.Current() == nil {
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceTypeUser.Id,
		})
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceTypeRole.Id,
		})
	}

	var rv []*v2.Resource
	var annos annotations.Annotations

	current := bag.Current()
	switch current.ResourceTypeID {
	case resourceTypeUser.Id:
		if current.ResourceID != "" {
			oktaUser, resp, err := o.client.User.GetUser(ctx, current.ResourceID)
			if err != nil {
				return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to get user: %w", err)
			}
			_, annos, err = parseResp(resp)
			if err != nil {
				return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
			}

			resource, err := userResource(ctx, oktaUser)
			if err != nil {
				return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to create user resource: %w", err)
			}
			rv = append(rv, resource)
			bag.Pop()
		} else {
			qp := queryParams(pToken.Size, current.Token)
			adminFlags, respCtx, err := listAdministratorRoleFlags(ctx, o.client, pToken, qp)
			if err != nil {
				// We don't have permissions to fetch role assignments, so return an empty list
				if errors.Is(err, errMissingRolePermissions) {
					return nil, "", nil, nil
				}
				return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list users: %w", err)
			}

			nextPage, respAnnos, err := parseResp(respCtx.OktaResponse)
			if err != nil {
				return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
			}

			err = bag.Next(nextPage)
			if err != nil {
				return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
			}

			annos = respAnnos

			for _, administratorRoleFlag := range adminFlags {
				bag.Push(pagination.PageState{
					ResourceTypeID: resourceTypeUser.Id,
					ResourceID:     administratorRoleFlag.UserId,
				})
			}
		}
	case resourceTypeRole.Id:
		for _, role := range standardRoleTypes {
			resource, err := roleResource(ctx, role)
			if err != nil {
				return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to create role resource: %w", err)
			}

			rv = append(rv, resource)
		}
		bag.Pop()
	}

	pageToken, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, err
	}

	return rv, pageToken, annos, nil
}

func (o *ciamResourceBuilder) Entitlements(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement

	role := standardRoleFromType(resource.Id.GetResource())

	en := sdkEntitlement.NewAssignmentEntitlement(resource, "assigned",
		sdkEntitlement.WithDisplayName(fmt.Sprintf("%s Role Member", role.Label)),
		sdkEntitlement.WithDescription(fmt.Sprintf("Has the %s role in Okta", role.Label)),
		sdkEntitlement.WithAnnotation(&v2.V1Identifier{
			Id: V1MembershipEntitlementID(role.Type),
		}),
		sdkEntitlement.WithGrantableTo(resourceTypeUser),
	)

	rv = append(rv, en)

	return rv, "", nil, nil
}

func (o *ciamResourceBuilder) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	var rv []*v2.Grant
	bag, page, err := parsePageToken(pToken.Token, resource.Id)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	qp := queryParams(pToken.Size, page)
	adminFlags, respCtx, err := listAdministratorRoleFlags(ctx, o.client, pToken, qp)
	if err != nil {
		// We don't have permissions to fetch role assignments, so return an empty list
		if errors.Is(err, errMissingRolePermissions) {
			return nil, "", nil, nil
		}
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list users: %w", err)
	}

	nextPage, annos, err := parseResp(respCtx.OktaResponse)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
	}

	for _, administratorRoleFlag := range adminFlags {
		if userHasRoleAccess(administratorRoleFlag, resource) {
			userID := administratorRoleFlag.UserId
			roleID := resource.Id.GetResource()
			rv = append(rv, roleGrant(userID, roleID, resource))
		}
	}

	pageToken, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, err
	}

	return rv, pageToken, annos, nil
}

func (g *ciamResourceBuilder) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	if principal.Id.ResourceType != resourceTypeUser.Id {
		l.Warn(
			"okta-connector: only users or groups can be granted role membership",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("okta-connector: only users or groups can be granted repo membership")
	}

	roleId := entitlement.Resource.Id.Resource
	switch principal.Id.ResourceType {
	case resourceTypeUser.Id:
		userId := principal.Id.Resource
		role := okta.AssignRoleRequest{
			Type: roleId,
		}
		createdRole, response, err := g.client.User.AssignRoleToUser(ctx, userId, role, nil)
		if err != nil {
			defer response.Body.Close()
			errOkta, err := getError(response)
			if err != nil {
				return nil, err
			}

			if errOkta.ErrorCode == alreadyAssignedRole {
				l.Warn(
					"okta-connector: The role specified is already assigned to the user",
					zap.String("principal_id", principal.Id.String()),
					zap.String("principal_type", principal.Id.ResourceType),
					zap.String("ErrorCode", errOkta.ErrorCode),
					zap.String("ErrorSummary", errOkta.ErrorSummary),
				)
			}

			return nil, fmt.Errorf("okta-connector: %v", errOkta)
		}

		l.Warn("Role Membership has been created.",
			zap.String("ID", createdRole.Id),
			zap.String("Description", createdRole.Description),
			zap.Time("CreatedAt", *createdRole.Created),
			zap.String("Label", createdRole.Label),
			zap.String("Status", createdRole.Status),
			zap.String("Type", createdRole.Type),
		)
	case resourceTypeGroup.Id:
		groupId := principal.Id.Resource
		role := okta.AssignRoleRequest{
			Type: roleId,
		}
		createdRole, response, err := g.client.Group.AssignRoleToGroup(ctx, groupId, role, nil)
		if err != nil {
			defer response.Body.Close()
			errOkta, err := getError(response)
			if err != nil {
				return nil, err
			}

			if errOkta.ErrorCode == alreadyAssignedRole {
				l.Warn(
					"okta-connector: The role specified is already assigned to the group",
					zap.String("principal_id", principal.Id.String()),
					zap.String("principal_type", principal.Id.ResourceType),
					zap.String("ErrorCode", errOkta.ErrorCode),
					zap.String("ErrorSummary", errOkta.ErrorSummary),
				)
			}

			return nil, fmt.Errorf("okta-connector: %v", errOkta)
		}

		l.Warn("Role Membership has been created.",
			zap.String("ID", createdRole.Id),
			zap.String("Description", createdRole.Description),
			zap.Time("CreatedAt", *createdRole.Created),
			zap.String("Label", createdRole.Label),
			zap.String("Status", createdRole.Status),
			zap.String("Type", createdRole.Type),
		)
	default:
		return nil, fmt.Errorf("okta-connector: invalid grant resource type: %s", principal.Id.ResourceType)
	}

	return nil, nil
}

func (g *ciamResourceBuilder) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	entitlement := grant.Entitlement
	principal := grant.Principal
	roleId := ""
	if principal.Id.ResourceType != resourceTypeUser.Id {
		l.Warn(
			"okta-connector: only users or groups can have role membership revoked",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("okta-connector:only users or groups can have role membership revoked")
	}

	roleType := entitlement.Resource.Id.Resource
	switch principal.Id.ResourceType {
	case resourceTypeUser.Id:
		userId := principal.Id.Resource
		roles, response, err := g.client.User.ListAssignedRolesForUser(ctx, userId, nil)
		if err != nil {
			return nil, fmt.Errorf("okta-connector: failed to get roles: %s %s", err.Error(), response.Body)
		}

		rolePos := slices.IndexFunc(roles, func(r *okta.Role) bool {
			return r.Type == roleType && r.Status == userStatusActive
		})
		if rolePos == NF {
			l.Warn(
				"okta-connector: user does not have role membership",
				zap.String("principal_id", principal.Id.String()),
				zap.String("principal_type", principal.Id.ResourceType),
				zap.String("role_type", entitlement.Resource.Id.Resource),
			)
			return nil, fmt.Errorf("okta-connector: user does not have role membership")
		}

		roleId = roles[rolePos].Id
		response, err = g.client.User.RemoveRoleFromUser(ctx, userId, roleId)
		if err != nil {
			return nil, fmt.Errorf("okta-connector: failed to remove role: %s %s", err.Error(), response.Body)
		}

		if response.StatusCode == http.StatusNoContent {
			l.Warn("Membership has been revoked",
				zap.String("Status", response.Status),
			)
		}
	case resourceTypeGroup.Id:
		groupId := principal.Id.Resource
		roles, response, err := g.client.Group.ListGroupAssignedRoles(ctx, groupId, nil)
		if err != nil {
			return nil, fmt.Errorf("okta-connector: failed to get roles: %s %s", err.Error(), response.Body)
		}

		rolePos := slices.IndexFunc(roles, func(r *okta.Role) bool {
			return r.Type == roleType && r.Status == userStatusActive
		})
		if rolePos == NF {
			l.Warn(
				"okta-connector: group does not have role membership",
				zap.String("principal_id", principal.Id.String()),
				zap.String("principal_type", principal.Id.ResourceType),
				zap.String("role_type", entitlement.Resource.Id.Resource),
			)
			return nil, fmt.Errorf("okta-connector: group does not have role membership")
		}

		roleId = roles[rolePos].Id
		response, err = g.client.Group.RemoveRoleFromGroup(ctx, groupId, roleId)
		if err != nil {
			return nil, fmt.Errorf("okta-connector: failed to remove role: %s %s", err.Error(), response.Body)
		}

		if response.StatusCode == http.StatusNoContent {
			l.Warn("Membership has been revoked",
				zap.String("Status", response.Status),
			)
		}
	default:
		return nil, fmt.Errorf("okta-connector: invalid grant resource type: %s", principal.Id.ResourceType)
	}

	return nil, nil
}
func (o *ciamResourceBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return resourceTypeRole
}

func ciamBuilder(client *okta.Client) *ciamResourceBuilder {
	return &ciamResourceBuilder{
		client: client,
	}
}
