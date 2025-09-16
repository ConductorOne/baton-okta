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
	oktav5 "github.com/conductorone/okta-sdk-golang/v5/okta"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"go.uber.org/zap"
)

type ciamResourceBuilder struct {
	client              *okta.Client
	clientV5            *oktav5.APIClient
	skipSecondaryEmails bool
}

func (o *ciamResourceBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	bag := &pagination.Bag{}
	err := bag.Unmarshal(pToken.Token)
	if err != nil {
		return nil, "", nil, err
	}

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
			oktaUser, resp, err := o.clientV5.UserAPI.GetUser(ctx, current.ResourceID).Execute()
			if err != nil {
				anno, err := wrapErrorV5(resp, err, errors.New("okta-connectorv2: failed to get user"))
				return nil, "", anno, err
			}
			_, annos, err = parseRespV5(resp)
			if err != nil {
				return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
			}

			resource, err := userResource(ctx, &oktav5.User{
				Id:                    oktaUser.Id,
				Profile:               oktaUser.Profile,
				Status:                oktaUser.Status,
				Created:               oktaUser.Created,
				AdditionalProperties:  oktaUser.AdditionalProperties,
				Type:                  oktaUser.Type,
				StatusChanged:         oktaUser.StatusChanged,
				LastLogin:             oktaUser.LastLogin,
				LastUpdated:           oktaUser.LastUpdated,
				Activated:             oktaUser.Activated,
				Credentials:           oktaUser.Credentials,
				Links:                 oktaUser.Links,
				PasswordChanged:       oktaUser.PasswordChanged,
				RealmId:               oktaUser.RealmId,
				TransitioningToStatus: oktaUser.TransitioningToStatus,
			}, o.skipSecondaryEmails)
			if err != nil {
				return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to create user resource: %w", err)
			}
			rv = append(rv, resource)
			bag.Pop()
		} else {
			adminFlags, respCtx, err := listAdministratorRoleFlags(ctx, o.client, pToken, current.Token)
			if err != nil {
				// We don't have permissions to fetch role assignments, so return an empty list
				if errors.Is(err, errMissingRolePermissions) {
					l.Warn("okta-connectorv2: missing role permissions")
					return nil, "", nil, nil
				}
				return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list users: %w", err)
			}

			nextPage, respAnnos, err := parseAdminListResp(respCtx.OktaResponse)
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
		l.Debug("Listing users", zap.Any("bag", bag))
	case resourceTypeRole.Id:
		l.Debug("Listing roles", zap.Any("bag", bag))
		for _, role := range standardRoleTypes {
			resource, err := roleResourceV5(ctx, role)
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

	if role.Type == nil {
		return nil, "", nil, nil
	}

	en := sdkEntitlement.NewAssignmentEntitlement(resource, "assigned",
		sdkEntitlement.WithDisplayName(fmt.Sprintf("%s Role Member", nullableStr(role.Label))),
		sdkEntitlement.WithDescription(fmt.Sprintf("Has the %s role in Okta", nullableStr(role.Label))),
		sdkEntitlement.WithAnnotation(&v2.V1Identifier{
			Id: V1MembershipEntitlementID(*role.Type),
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

	// TODO(Golds): uses internal api, need to switch to v5
	adminFlags, respCtx, err := listAdministratorRoleFlags(ctx, o.client, pToken, page)
	if err != nil {
		// We don't have permissions to fetch role assignments, so return an empty list
		if errors.Is(err, errMissingRolePermissions) {
			return nil, "", nil, nil
		}
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list users: %w", err)
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
			rv = append(rv, roleGrant(userID, resource))
		}
	}

	nextPageToken, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, err
	}

	return rv, nextPageToken, annos, nil
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
		createdRole, response, err := g.clientV5.RoleAssignmentAPI.AssignRoleToUser(ctx, userId).
			AssignRoleRequest(oktav5.AssignRoleRequest{
				Type: oktav5.PtrString(roleId),
			}).
			Execute()
		if err != nil {
			if errOkta, ok := asErrorV5(err); ok {
				if errOkta.ErrorCode == nil {
					l.Warn("okta-connector: nil error code from okta v5 client")
					return nil, fmt.Errorf("okta-connector: nil error code from okta v5 client: %v", errOkta)
				}

				if *errOkta.ErrorCode == alreadyAssignedRole {
					l.Warn(
						"okta-connector: The role specified is already assigned to the user",
						zap.String("principal_id", principal.Id.String()),
						zap.String("principal_type", principal.Id.ResourceType),
						zap.String("ErrorCode", nullableStr(errOkta.ErrorCode)),
						zap.String("ErrorSummary", nullableStr(errOkta.ErrorCode)),
					)
				}
			}

			anno, err := wrapErrorV5(response, err, errors.New("okta-connector: failed to assign role to user"))

			return anno, err
		}

		l.Warn("Role Membership has been created.",
			zap.String("ID", nullableStr(createdRole.Id)),
			zap.String("Description", nullableStr(createdRole.Description)),
			zap.Time("CreatedAt", *createdRole.Created),
			zap.String("Label", nullableStr(createdRole.Label)),
			zap.String("Status", nullableStr(createdRole.Status)),
			zap.String("Type", nullableStr(createdRole.Type)),
		)
	case resourceTypeGroup.Id:
		groupId := principal.Id.Resource
		createdRole, response, err := g.clientV5.RoleAssignmentAPI.AssignRoleToGroup(ctx, groupId).
			AssignRoleRequest(oktav5.AssignRoleRequest{
				Type: oktav5.PtrString(roleId),
			}).
			Execute()
		if err != nil {
			if errOkta, ok := asErrorV5(err); ok {
				if errOkta.ErrorCode == nil {
					l.Warn("okta-connector: nil error code from okta v5 client")
					return nil, fmt.Errorf("okta-connector: nil error code from okta v5 client: %v", errOkta)
				}

				if *errOkta.ErrorCode == alreadyAssignedRole {
					l.Warn(
						"okta-connector: The role specified is already assigned to the group",
						zap.String("principal_id", principal.Id.String()),
						zap.String("principal_type", principal.Id.ResourceType),
						zap.String("ErrorCode", nullableStr(errOkta.ErrorCode)),
						zap.String("ErrorSummary", nullableStr(errOkta.ErrorSummary)),
					)
				}
			}

			anno, err := wrapErrorV5(response, err, errors.New("okta-connector: failed to assign role to group"))

			return anno, err
		}

		l.Warn("Role Membership has been created.",
			zap.String("ID", nullableStr(createdRole.Id)),
			zap.String("Description", nullableStr(createdRole.Description)),
			zap.Time("CreatedAt", *createdRole.Created),
			zap.String("Label", nullableStr(createdRole.Label)),
			zap.String("Status", nullableStr(createdRole.Status)),
			zap.String("Type", nullableStr(createdRole.Type)),
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
		roles, response, err := g.clientV5.RoleAssignmentAPI.ListAssignedRolesForUser(ctx, userId).Execute()
		if err != nil {
			anno, err := wrapErrorV5(response, err, errors.New("okta-connector: failed to get roles for user"))
			return anno, err
		}

		rolePos := slices.IndexFunc(roles, func(r oktav5.Role) bool {
			return nullableStr(r.Type) == roleType && nullableStr(r.Status) == userStatusActive
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

		roleId = nullableStr(roles[rolePos].Id)
		if roleId == "" {
			return nil, fmt.Errorf("okta-connector: user does not have role membership")
		}

		response, err = g.clientV5.RoleAssignmentAPI.UnassignRoleFromUser(ctx, userId, roleId).Execute()
		if err != nil {
			anno, err := wrapErrorV5(response, err, errors.New("okta-connector: failed to remove role from user"))
			return anno, err
		}

		if response.StatusCode == http.StatusNoContent {
			l.Warn("Membership has been revoked",
				zap.String("Status", response.Status),
			)
		}
	case resourceTypeGroup.Id:
		groupId := principal.Id.Resource
		roles, response, err := g.clientV5.RoleAssignmentAPI.ListGroupAssignedRoles(ctx, groupId).Execute()
		if err != nil {
			anno, err := wrapErrorV5(response, err, errors.New("okta-connector: failed to get roles for group"))
			return anno, err
		}

		rolePos := slices.IndexFunc(roles, func(r oktav5.Role) bool {
			return nullableStr(r.Type) == roleType && nullableStr(r.Status) == userStatusActive
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

		roleId = nullableStr(roles[rolePos].Id)
		if roleId == "" {
			return nil, fmt.Errorf("okta-connector: group does not have role membership")
		}

		response, err = g.clientV5.RoleAssignmentAPI.UnassignRoleFromGroup(ctx, groupId, roleId).Execute()
		if err != nil {
			anno, err := wrapErrorV5(response, err, errors.New("okta-connector: failed to remove role from group"))
			return anno, err
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

func (o *ciamResourceBuilder) Get(ctx context.Context, resourceId *v2.ResourceId, parentResourceId *v2.ResourceId) (*v2.Resource, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	l.Debug("getting role", zap.String("role_id", resourceId.Resource))

	for _, role := range standardRoleTypes {
		if role.Type == nil {
			continue
		}

		if *role.Type == resourceId.Resource {
			resource, err := roleResourceV5(ctx, role)
			if err != nil {
				return nil, nil, err
			}
			return resource, nil, nil
		}
	}

	return nil, nil, nil
}

func (o *ciamResourceBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return resourceTypeRole
}

func ciamBuilder(client *okta.Client, clientV5 *oktav5.APIClient, skipSecondaryEmails bool) *ciamResourceBuilder {
	return &ciamResourceBuilder{
		client:              client,
		skipSecondaryEmails: skipSecondaryEmails,
		clientV5:            clientV5,
	}
}
