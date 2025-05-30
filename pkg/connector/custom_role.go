package connector

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/ratelimit"
	sdkEntitlement "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
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
	var nextPageToken string
	bag, _, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeCustomRole.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	var rv []*v2.Resource
	rv, err = o.listCustomRoles(ctx, resourceID, token)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list custom roles: %w", err)
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
	var rv []*v2.Entitlement

	role := &okta.Role{
		Label: resource.DisplayName,
		Type:  resource.Id.Resource,
	}

	en := sdkEntitlement.NewAssignmentEntitlement(resource, "assigned",
		sdkEntitlement.WithDisplayName(fmt.Sprintf("%s Role Member", role.Label)),
		sdkEntitlement.WithDescription(fmt.Sprintf("Has the %s role in Okta", role.Label)),
		sdkEntitlement.WithAnnotation(&v2.V1Identifier{
			Id: V1MembershipEntitlementID(role.Type),
		}),
		sdkEntitlement.WithGrantableTo(resourceTypeUser, resourceTypeGroup),
	)
	rv = append(rv, en)

	return rv, "", nil, nil
}

// listGroupAssignedRoles. List all group role assignments
// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleAssignmentBGroup/#tag/RoleAssignmentBGroup/operation/listGroupAssignedRoles
func listGroupAssignedRoles(ctx context.Context, client *okta.Client, groupId string, qp *query.Params) ([]*Roles, *okta.Response, error) {
	apiPath, err := url.JoinPath(groupsUrl, groupId, "roles")
	if err != nil {
		return nil, nil, err
	}

	reqUrl, err := url.Parse(apiPath)
	if err != nil {
		return nil, nil, err
	}

	var role []*Roles
	resp, err := doRequest(ctx, reqUrl.String(), http.MethodGet, &role, client)
	if err != nil {
		return nil, resp, err
	}

	return role, resp, nil
}

// listAssignedRolesForUser. List all user role assignments.
// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleAssignmentAUser/#tag/RoleAssignmentAUser/operation/listAssignedRolesForUser
func listAssignedRolesForUser(ctx context.Context, client *okta.Client, userId string) ([]*Roles, *okta.Response, error) {
	apiPath, err := url.JoinPath(usersUrl, userId, "roles")
	if err != nil {
		return nil, nil, err
	}

	reqUrl, err := url.Parse(apiPath)
	if err != nil {
		return nil, nil, err
	}

	var role []*Roles
	resp, err := doRequest(ctx, reqUrl.String(), http.MethodGet, &role, client)
	if err != nil {
		return nil, nil, err
	}

	return role, resp, nil
}

func (o *customRoleResourceType) Grants(
	ctx context.Context,
	resource *v2.Resource,
	token *pagination.Token,
) ([]*v2.Grant, string, annotations.Annotations, error) {
	var rv []*v2.Grant

	bag, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeCustomRole.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	qp := queryParams(token.Size, page)

	usersWithRoleAssignments, respCtx, err := listAllUsersWithRoleAssignments(ctx, o.connector.client, token, qp)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list all users with role assignments: %w", err)
	}

	nextPage, annos, err := parseResp(respCtx.OktaResponse)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
	}

	for _, user := range usersWithRoleAssignments {
		userId := user.Id

		userRoles, err := o.getUserRolesFromCache(ctx, userId)
		if err != nil {
			return nil, "", nil, err
		}

		if userRoles == nil {
			userRoles = mapset.NewSet[string]()
			roles, _, err := listAssignedRolesForUser(ctx, o.connector.client, userId)
			if err != nil {
				return nil, "", nil, err
			}
			for _, role := range roles {
				if role.Status == roleStatusInactive || role.AssignmentType != "USER" {
					continue
				}
				if role.Type == roleTypeCustom {
					userRoles.Add(role.Role)
				} else {
					userRoles.Add(role.Type)
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

func (o *customRoleResourceType) listCustomRoles(
	ctx context.Context,
	_ *v2.ResourceId,
	token *pagination.Token,
) ([]*v2.Resource, error) {
	_, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeCustomRole.Id})
	if err != nil {
		return nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	qp := queryParams(token.Size, page)
	roles, _, err := listOktaIamCustomRoles(ctx, o.connector.client, token, qp)
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

	role, respCtx, err := getOktaIamCustomRole(ctx, o.connector.client, resourceId.Resource)
	if err != nil {
		return nil, nil, err
	}

	resp := respCtx.OktaResponse
	if resp != nil {
		if desc, err := ratelimit.ExtractRateLimitData(resp.Response.StatusCode, &resp.Response.Header); err == nil {
			annos.WithRateLimiting(desc)
		}
	}

	resource, err := roleResource(ctx, role, resourceTypeCustomRole)
	if err != nil {
		return nil, annos, err
	}

	return resource, annos, nil
}

func getOktaIamCustomRole(
	ctx context.Context,
	client *okta.Client,
	roleId string,
) (*okta.Role, *responseContext, error) {
	url, err := url.Parse(apiPathListIamCustomRoles)
	if err != nil {
		return nil, nil, err
	}

	url.Path = path.Join(url.Path, roleId)

	rq := client.CloneRequestExecutor()
	req, err := rq.
		WithAccept(ContentType).
		WithContentType(ContentType).
		NewRequest(http.MethodGet, url.String(), nil)
	if err != nil {
		return nil, nil, err
	}

	var role *okta.Role
	resp, err := rq.Do(ctx, req, &role)
	if err != nil {
		return nil, nil, err
	}

	respCtx := &responseContext{
		OktaResponse: resp,
	}

	return role, respCtx, nil
}

func customRoleBuilder(connector *Okta) *customRoleResourceType {
	return &customRoleResourceType{
		resourceType: resourceTypeCustomRole,
		connector:    connector,
	}
}
