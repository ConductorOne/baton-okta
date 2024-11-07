package connector

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	sdkEntitlement "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	sdkGrant "github.com/conductorone/baton-sdk/pkg/types/grant"
	sdkResource "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"go.uber.org/zap"
)

type resourceSetsResourceType struct {
	resourceType *v2.ResourceType
	client       *okta.Client
	domain       string
}

const (
	apiPathListIamResourceSets = "/api/v1/iam/resource-sets"
	roleTypeCustom             = "CUSTOM"
	roleStatusInactive         = "INACTIVE"
	usersUrl                   = "/api/v1/users"
	groupsUrl                  = "/api/v1/groups"
	defaultProtocol            = "https:"
	bindingEntitlement         = "bindings"
)

func (rs *resourceSetsResourceType) ResourceType(ctx context.Context) *v2.ResourceType {
	return rs.resourceType
}

func resourceSetsResource(ctx context.Context, rs *ResourceSets, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	profile := map[string]interface{}{
		"id":          rs.ID,
		"label":       rs.Label,
		"description": rs.Description,
	}

	return sdkResource.NewResource(
		rs.Label,
		resourceTypeResourceSets,
		rs.ID,
		sdkResource.WithParentResourceID(parentResourceID),
		sdkResource.WithAppTrait(
			sdkResource.WithAppProfile(profile),
		),
	)
}

// listResourceSets. List all Resource Sets.
// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleCResourceSet/#tag/RoleCResourceSet/operation/listResourceSets
func listResourceSets(ctx context.Context,
	client *okta.Client,
	token *pagination.Token,
	qp *query.Params,
) ([]ResourceSets, *responseContext, error) {
	uri := apiPathListIamResourceSets
	if qp != nil {
		uri += qp.String()
	}

	reqUrl, err := url.Parse(uri)
	if err != nil {
		return nil, nil, err
	}

	var resourceSets *ResourceSetsAPIData
	resp, err := doRequest(ctx, reqUrl.String(), http.MethodGet, &resourceSets, client)
	if err != nil {
		return nil, nil, err
	}

	respCtx, err := responseToContext(token, resp)
	if err != nil {
		return nil, nil, err
	}

	return resourceSets.ResourceSets, respCtx, nil
}

func (rs *resourceSetsResourceType) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	var rv []*v2.Resource
	bag, page, err := parsePageToken(pToken.Token, &v2.ResourceId{ResourceType: resourceTypeResourceSets.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	qp := queryParams(pToken.Size, page)
	resourceSets, respCtx, err := listResourceSets(ctx, rs.client, pToken, qp)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list resource-sets: %w", err)
	}

	nextPage, _, err := parseResp(respCtx.OktaResponse)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
	}

	for _, resourceSet := range resourceSets {
		resource, err := resourceSetsResource(ctx, &resourceSet, nil)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to create resource-sets: %w", err)
		}

		rv = append(rv, resource)
	}

	pageToken, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, err
	}

	return rv, pageToken, nil, nil
}

func (rs *resourceSetsResourceType) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return []*v2.Entitlement{
		sdkEntitlement.NewAssignmentEntitlement(
			resource,
			bindingEntitlement,
			sdkEntitlement.WithAnnotation(&v2.V1Identifier{
				Id: V1MembershipEntitlementID(resource.Id.GetResource()),
			}),
			sdkEntitlement.WithGrantableTo(resourceTypeResourceSets),
			sdkEntitlement.WithDisplayName(fmt.Sprintf("%s Resource Set Binding", resource.DisplayName)),
			sdkEntitlement.WithDescription(fmt.Sprintf("Member of %s resource-set in Okta", resource.DisplayName)),
		),
	}, "", nil, nil
}

// listAssignedRolesForUser. List all user role assignments.
// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleAssignmentAUser/#tag/RoleAssignmentAUser/operation/listAssignedRolesForUser
func (rs *resourceSetsResourceType) listAssignedRolesForUser(ctx context.Context, userId string, qp *query.Params) ([]*Roles, *okta.Response, error) {
	apiPath, err := url.JoinPath(usersUrl, userId, "roles")
	if err != nil {
		return nil, nil, err
	}

	reqUrl, err := url.Parse(apiPath)
	if err != nil {
		return nil, nil, err
	}

	var role []*Roles
	resp, err := doRequest(ctx, reqUrl.String(), http.MethodGet, &role, rs.client)
	if err != nil {
		return nil, nil, err
	}

	return role, resp, nil
}

// listBindings. List all Role Resource Set Bindings.
// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleDResourceSetBinding/#tag/RoleDResourceSetBinding/operation/listBindings
func listBindings(ctx context.Context,
	client *okta.Client,
	resourceSetId string,
	_ *query.Params) ([]Role, *okta.Response, error) {
	apiPath, err := url.JoinPath(apiPathListIamResourceSets, resourceSetId, "bindings")
	if err != nil {
		return nil, nil, err
	}

	var resourceSetsBindings *ResourceSetsBindingsAPIData
	resp, err := doRequest(ctx, apiPath, http.MethodGet, &resourceSetsBindings, client)
	if err != nil {
		return nil, resp, err
	}

	return resourceSetsBindings.Roles, resp, nil
}

func doRequest(ctx context.Context, url, httpMethod string, res interface{}, client *okta.Client) (*okta.Response, error) {
	rq := client.CloneRequestExecutor()
	req, err := rq.WithAccept(ContentType).
		WithContentType(ContentType).
		NewRequest(httpMethod, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := rq.Do(ctx, req, &res)
	if err != nil {
		return resp, err
	}

	return resp, nil
}

// deleteBinding. Delete a Role Resource Set Binding
// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleDResourceSetBinding/#tag/RoleDResourceSetBinding/operation/deleteBinding
func (rs *resourceSetsResourceType) deleteBinding(ctx context.Context, resourceSetId, roleId string, qp *query.Params) (*okta.Response, error) {
	apiPath, err := url.JoinPath(apiPathListIamResourceSets, resourceSetId, "bindings", roleId)
	if err != nil {
		return nil, err
	}

	reqUrl, err := url.Parse(apiPath)
	if err != nil {
		return nil, err
	}

	resp, err := doRequest(ctx, reqUrl.String(), http.MethodDelete, nil, rs.client)
	if err != nil {
		return resp, err
	}

	return resp, nil
}

func (rs *resourceSetsResourceType) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	var rv []*v2.Grant
	bag, _, err := parsePageToken(pToken.Token, resource.Id)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

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
		users, respUserCtx, err := listUsers(ctx, rs.client, userToken, qp)
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
			roles, _, err := rs.listAssignedRolesForUser(ctx, userId, nil)
			if err != nil {
				return nil, "", nil, err
			}

			for _, role := range roles {
				if role.Status == roleStatusInactive || role.Type != roleTypeCustom || !strings.Contains(resource.Id.Resource, role.ResourceSet) {
					continue
				}

				principal := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeCustomRole.Id, Resource: role.Role}}
				gr := sdkGrant.NewGrant(resource, bindingEntitlement, principal,
					sdkGrant.WithAnnotation(&v2.V1Identifier{
						Id: fmtGrantIdV1(V1MembershipEntitlementID(resource.Id.Resource), resource.Id.Resource),
					}),
				)
				rv = append(rv, gr)
			}
		}

		pageUserToken, err = bagUsers.Marshal()
		if err != nil {
			return nil, "", nil, err
		}
	}

	err = bag.Next(bag.PageToken())
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
	}

	pageToken, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, err
	}

	return rv, pageToken, nil, nil
}

func (rs *resourceSetsResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	// Creating a Binding for the Resource Set, requires Custom Role, and members (Users or Groups)
	// Because of that, We added resource-set-bindings
	return nil, nil
}

func (rs *resourceSetsResourceType) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	entitlement := grant.Entitlement
	principal := grant.Principal
	if principal.Id.ResourceType != resourceTypeCustomRole.Id {
		l.Warn(
			"okta-connector: only custom roles can have role resource-set membership revoked",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("okta-connector:only custom roles can have resource-set membership revoked")
	}

	resourceSetId := entitlement.Resource.Id.Resource
	customRoleId := principal.Id.Resource
	response, err := rs.deleteBinding(ctx, resourceSetId, customRoleId, nil)
	if err != nil {
		return nil, fmt.Errorf("okta-connector: failed to remove roles: %s %s", err.Error(), response.Body)
	}

	if response.StatusCode == http.StatusNoContent {
		l.Warn("Resource Set Membership has been revoked",
			zap.String("Status", response.Status),
		)
	}

	return nil, nil
}

func resourceSetsBuilder(domain string, client *okta.Client, syncCustomRoles bool) *resourceSetsResourceType {
	return &resourceSetsResourceType{
		resourceType: resourceTypeResourceSets,
		domain:       domain,
		client:       client,
	}
}
