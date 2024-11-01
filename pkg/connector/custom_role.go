package connector

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	sdkEntitlement "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"go.uber.org/zap"
)

type customRoleResourceType struct {
	resourceType    *v2.ResourceType
	domain          string
	apiToken        string
	client          *okta.Client
	syncCustomRoles bool
}

func (o *customRoleResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *customRoleResourceType) List(
	ctx context.Context,
	resourceID *v2.ResourceId,
	token *pagination.Token,
) ([]*v2.Resource, string, annotations.Annotations, error) {
	var nextPageToken string
	bag, _, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeCustomRole.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	var rv []*v2.Resource
	if o.syncCustomRoles {
		rv, err = o.listCustomRoles(ctx, resourceID, token)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list custom roles: %w", err)
		}
	}

	err = bag.Next(nextPageToken)
	if err != nil {
		return nil, "", nil, err
	}

	nextPageToken, err = bag.Marshal()
	if err != nil {
		return nil, "", nil, err
	}

	return rv, nextPageToken, nil, nil
}

func (o *customRoleResourceType) Entitlements(
	ctx context.Context,
	resource *v2.Resource,
	token *pagination.Token,
) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var (
		rv   []*v2.Entitlement
		role *okta.Role
	)
	role = standardRoleFromType(resource.Id.GetResource())
	if role == nil {
		role = &okta.Role{
			Label: resource.DisplayName,
			Type:  resource.Id.Resource,
		}
	}
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

// listGroupAssignedRoles. List all group role assignments
// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleAssignmentBGroup/#tag/RoleAssignmentBGroup/operation/listGroupAssignedRoles
func (o *customRoleResourceType) listGroupAssignedRoles(ctx context.Context, groupId string, qp *query.Params) ([]*Roles, *okta.Response, error) {
	apiPath, err := url.JoinPath(groupsUrl, groupId, "roles")
	if err != nil {
		return nil, nil, err
	}

	reqUrl, err := url.Parse(apiPath)
	if err != nil {
		return nil, nil, err
	}

	var role []*Roles
	resp, err := doRequest(ctx, reqUrl.String(), http.MethodGet, &role, o.client)
	if err != nil {
		return nil, nil, err
	}

	return role, resp, nil
}

func (o *customRoleResourceType) listGroups(ctx context.Context, token *pagination.Token, qp *query.Params) ([]*okta.Group, *responseContext, error) {
	groups, resp, err := o.client.Group.ListGroups(ctx, qp)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch groups from okta: %w", err)
	}

	reqCtx, err := responseToContext(token, resp)
	if err != nil {
		return nil, nil, err
	}

	return groups, reqCtx, nil
}

func (o *customRoleResourceType) Grants(
	ctx context.Context,
	resource *v2.Resource,
	token *pagination.Token,
) ([]*v2.Grant, string, annotations.Annotations, error) {
	var rv []*v2.Grant
	_, page, err := parsePageToken(token.Token, resource.Id)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	_, bag, err := unmarshalSkipToken(token)
	if err != nil {
		return nil, "", nil, err
	}

	if bag.Current() == nil {
		// Push onto stack in reverse
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceTypeGroup.Id,
		})
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceTypeUser.Id,
		})
	}

	adminFlags, respCtx, err := listAdministratorRoleFlags(ctx, o.client, token, page)
	if err != nil {
		// We don't have permissions to fetch role assignments, so return an empty list
		if errors.Is(err, errMissingRolePermissions) {
			return nil, "", nil, nil
		}

		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list users: %w", err)
	}

	if o.syncCustomRoles {
		switch bag.ResourceTypeID() {
		case resourceTypeGroup.Id:
			pageGroupToken := "{}"
			for pageGroupToken != "" {
				groupToken := &pagination.Token{
					Token: pageGroupToken,
				}
				bagGroups, pageGroups, err := parsePageToken(groupToken.Token, resource.Id)
				if err != nil {
					return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
				}

				qp := queryParams(groupToken.Size, pageGroups)
				groups, respGroupCtx, err := o.listGroups(ctx, groupToken, qp)
				if err != nil {
					return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list groups: %w", err)
				}

				nextGroupPage, _, err := parseResp(respGroupCtx.OktaResponse)
				if err != nil {
					return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
				}

				err = bagGroups.Next(nextGroupPage)
				if err != nil {
					return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
				}

				for _, group := range groups {
					groupId := group.Id
					roles, _, err := o.listGroupAssignedRoles(ctx, groupId, nil)
					if err != nil {
						return nil, "", nil, err
					}

					for _, role := range roles {
						if role.Status == roleStatusInactive || role.AssignmentType != "GROUP" || role.Type != roleTypeCustom {
							continue
						}

						// It's a custom role. We need to match the label to the display name
						if role.Label == resource.GetDisplayName() {
							rv = append(rv, roleGroupGrant(groupId, resource))
						}
					}
				}

				pageGroupToken, err = bagGroups.Marshal()
				if err != nil {
					return nil, "", nil, err
				}
			}
		case resourceTypeUser.Id:
			pageUserToken := "{}"
			for pageUserToken != "" {
				userToken := &pagination.Token{
					Token: pageUserToken,
				}
				bagUsers, pageUsers, err := parsePageToken(userToken.Token, resource.Id)
				if err != nil {
					return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
				}

				qp := queryParams(userToken.Size, pageUsers)
				users, respUserCtx, err := listUsers(ctx, o.client, userToken, qp)
				if err != nil {
					return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list users: %w", err)
				}

				nextUserPage, _, err := parseResp(respUserCtx.OktaResponse)
				if err != nil {
					return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
				}

				err = bagUsers.Next(nextUserPage)
				if err != nil {
					return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
				}

				for _, user := range users {
					userId := user.Id
					roles, _, err := o.client.User.ListAssignedRolesForUser(ctx, userId, nil)
					if err != nil {
						return nil, "", nil, err
					}

					for _, role := range roles {
						if role.Status == roleStatusInactive || role.AssignmentType != "USER" || role.Type != roleTypeCustom {
							continue
						}

						// It's a custom role. We need to match the label to the display name
						if role.Label == resource.GetDisplayName() {
							rv = append(rv, roleGrant(userId, resource))
						}
					}
				}

				pageUserToken, err = bagUsers.Marshal()
				if err != nil {
					return nil, "", nil, err
				}
			}
		default:
			return nil, "", nil, fmt.Errorf("okta-connector: invalid grant resource type: %s", bag.ResourceTypeID())
		}
	}

	nextPage, annos, err := parseAdminListResp(respCtx.OktaResponse)
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
			if userID != "" {
				rv = append(rv, roleGrant(userID, resource))
			}
		}
	}

	pageToken, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, err
	}

	return rv, pageToken, annos, nil
}

func (o *customRoleResourceType) listCustomRoles(
	ctx context.Context,
	_ *v2.ResourceId,
	token *pagination.Token,
) ([]*v2.Resource, error) {
	_, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeRole.Id})
	if err != nil {
		return nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	qp := queryParams(token.Size, page)
	roles, _, err := listOktaIamCustomRoles(ctx, o.client, token, qp)
	if err != nil {
		return nil, fmt.Errorf("okta-connectorv2: failed to list custom roles: %w", err)
	}

	rv := make([]*v2.Resource, 0)
	for _, role := range roles {
		resource, err := roleResource(ctx, role, resourceTypeCustomRole)
		if err != nil {
			return nil, fmt.Errorf("okta-connectorv2: failed to create role resource: %w", err)
		}

		rv = append(rv, resource)
	}

	return rv, nil
}

func (g *customRoleResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
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

func (g *customRoleResourceType) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
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

func customRoleBuilder(domain string, apiToken string, client *okta.Client, syncCustomRoles bool) *customRoleResourceType {
	return &customRoleResourceType{
		resourceType:    resourceTypeCustomRole,
		domain:          domain,
		apiToken:        apiToken,
		client:          client,
		syncCustomRoles: syncCustomRoles,
	}
}
