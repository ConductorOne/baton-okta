package connector

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	sdkEntitlement "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	sdkGrant "github.com/conductorone/baton-sdk/pkg/types/grant"
	sdkResource "github.com/conductorone/baton-sdk/pkg/types/resource"
	oktav5 "github.com/conductorone/okta-sdk-golang/v5/okta"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"go.uber.org/zap"
)

type resourceSetsResourceType struct {
	resourceType *v2.ResourceType
	clientV5     *oktav5.APIClient
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

func resourceSetsResource(ctx context.Context, rs *oktav5.ResourceSet, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	profile := map[string]interface{}{
		"id":          nullableStr(rs.Id),
		"label":       nullableStr(rs.Label),
		"description": nullableStr(rs.Description),
	}

	return sdkResource.NewResource(
		nullableStr(rs.Label),
		resourceTypeResourceSets,
		nullableStr(rs.Id),
		sdkResource.WithParentResourceID(parentResourceID),
		sdkResource.WithAppTrait(
			sdkResource.WithAppProfile(profile),
		),
	)
}

func resourceSetResource(ctx context.Context, rs *oktav5.ResourceSet, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	profile := map[string]interface{}{
		"id":          *rs.Id,
		"label":       *rs.Label,
		"description": *rs.Description,
	}

	return sdkResource.NewResource(
		*rs.Label,
		resourceTypeResourceSets,
		*rs.Id,
		sdkResource.WithParentResourceID(parentResourceID),
		sdkResource.WithAppTrait(
			sdkResource.WithAppProfile(profile),
		),
	)
}

// listResourceSetsV5. List all Resource Sets.
// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleCResourceSet/#tag/RoleCResourceSet/operation/listResourceSets
func listResourceSetsV5(
	ctx context.Context,
	client *oktav5.APIClient,
	page string,
) (*oktav5.ResourceSets, *oktav5.APIResponse, error) {
	return client.ResourceSetAPI.ListResourceSets(ctx).After(page).Execute()
}

func (rs *resourceSetsResourceType) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	var rv []*v2.Resource
	bag, page, err := parsePageTokenV5(pToken.Token, &v2.ResourceId{ResourceType: resourceTypeResourceSets.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse Page token: %w", err)
	}

	resourceSets, respCtx, err := listResourceSetsV5(ctx, rs.clientV5, page)
	if err != nil {
		anno, err := wrapErrorV5(respCtx, err, errors.New("okta-connectorv2: failed to list resource-sets"))
		return nil, "", anno, err
	}

	nextPage, annos, err := parseRespV5(respCtx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
	}

	for _, resourceSet := range resourceSets.ResourceSets {
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

	return rv, pageToken, annos, nil
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

// listBindings. List all Role Resource Set Bindings.
// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleDResourceSetBinding/#tag/RoleDResourceSetBinding/operation/listBindings
func listBindings(
	ctx context.Context,
	client *okta.Client,
	resourceSetId string,
	_ *query.Params,
) ([]Role, *okta.Response, error) {
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

// listBindingsV5. List all Role Resource Set Bindings.
// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleDResourceSetBinding/#tag/RoleDResourceSetBinding/operation/listBindings
func listBindingsV5(
	ctx context.Context,
	client *oktav5.APIClient,
	resourceSetId string,
	page string,
) (*oktav5.ResourceSetBindings, *oktav5.APIResponse, error) {
	return client.ResourceSetAPI.ListBindings(ctx, resourceSetId).After(page).Execute()
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
func (rs *resourceSetsResourceType) deleteBinding(ctx context.Context, resourceSetId, roleId string, qp *query.Params) (*oktav5.APIResponse, error) {
	resp, err := rs.clientV5.ResourceSetAPI.DeleteBinding(ctx, resourceSetId, roleId).Execute()
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (rs *resourceSetsResourceType) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	var rv []*v2.Grant
	bag, page, err := parsePageTokenV5(pToken.Token, resource.Id)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse Page token: %w", err)
	}

	roles, respCtx, err := listBindingsV5(ctx, rs.clientV5, resource.Id.Resource, page)
	if err != nil {
		anno, err := wrapErrorV5(respCtx, err)
		return nil, "", anno, err
	}

	for _, role := range roles.Roles {
		if role.Id == nil {
			continue
		}

		principal := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeCustomRole.Id, Resource: *role.Id}}
		gr := sdkGrant.NewGrant(resource, bindingEntitlement, principal,
			sdkGrant.WithAnnotation(&v2.V1Identifier{
				Id: fmtGrantIdV1(V1MembershipEntitlementID(resource.Id.Resource), resource.Id.Resource),
			}),
		)
		rv = append(rv, gr)
	}

	nextPage, annos, err := parseRespV5(respCtx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
	}

	pageToken, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, err
	}

	return rv, pageToken, annos, nil
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
		anno, err := wrapErrorV5(response, err, errors.New("okta-connector: failed to remove roles"))
		return anno, err
	}

	if response.StatusCode == http.StatusNoContent {
		l.Warn("Resource Set Membership has been revoked",
			zap.String("Status", response.Status),
		)
	}

	return nil, nil
}

func (rs *resourceSetsResourceType) Get(ctx context.Context, resourceId *v2.ResourceId, parentResourceId *v2.ResourceId) (*v2.Resource, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	l.Debug("getting resource set", zap.String("resource_set_id", resourceId.Resource))

	resourceSet, resp, err := rs.clientV5.ResourceSetAPI.GetResourceSet(ctx, resourceId.Resource).Execute()
	if err != nil {
		anno, err := wrapErrorV5(resp, err)
		return nil, anno, err
	}

	resource, err := resourceSetResource(ctx, resourceSet, parentResourceId)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to create resource-set: %w", err)
	}

	return resource, nil, nil
}

func resourceSetsBuilder(domain string, clientV5 *oktav5.APIClient) *resourceSetsResourceType {
	return &resourceSetsResourceType{
		resourceType: resourceTypeResourceSets,
		domain:       domain,
		clientV5:     clientV5,
	}
}
