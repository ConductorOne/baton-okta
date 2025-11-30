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
	oktav5 "github.com/conductorone/okta-sdk-golang/v5/okta"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"go.uber.org/zap"
)

const (
	entitlementName   = "member"
	resourceUsers     = "users"
	resourceGroups    = "groups"
	firstItem         = 0
	lastItem          = 1
	resourceMaxLength = 2
)

type resourceSetsBindingsResourceType struct {
	resourceType *v2.ResourceType
	client       *okta.Client
	clientV5     *oktav5.APIClient
	domain       string
}

func (rsb *resourceSetsBindingsResourceType) ResourceType(ctx context.Context) *v2.ResourceType {
	return rsb.resourceType
}

func resourceSetsBindingsResource(ctx context.Context, rs *ResourceSets, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	profile := map[string]interface{}{
		"id":          rs.ID,
		"label":       rs.Label,
		"description": rs.Description,
	}

	return sdkResource.NewResource(
		rs.Label,
		resourceTypeResourceSetsBindings,
		rs.ID,
		sdkResource.WithParentResourceID(parentResourceID),
		sdkResource.WithAppTrait(sdkResource.WithAppProfile(profile)),
	)
}

func resourceSetBindingsResource(ctx context.Context, rs *oktav5.ResourceSet, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	profile := map[string]interface{}{
		"id":          rs.GetId(),
		"label":       rs.GetLabel(),
		"description": rs.GetDescription(),
	}

	return sdkResource.NewResource(
		rs.GetLabel(),
		resourceTypeResourceSetsBindings,
		rs.GetId(),
		sdkResource.WithParentResourceID(parentResourceID),
		sdkResource.WithAppTrait(sdkResource.WithAppProfile(profile)),
	)
}
func (rsb *resourceSetsBindingsResourceType) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	var rv []*v2.Resource
	bag, page, err := parsePageToken(pToken.Token, &v2.ResourceId{ResourceType: resourceTypeResourceSets.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	qp := queryParams(pToken.Size, page)
	resourceSets, respCtx, err := listResourceSets(ctx, rsb.client, pToken, qp)
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
		resourceSetCpy := resourceSet
		roles, _, err := listBindings(ctx, rsb.client, resourceSetCpy.ID, nil)
		if err != nil {
			return nil, "", nil, err
		}

		for _, role := range roles {
			resourceSetCpy.ID = getResourceSetBindingID(resourceSet.ID, role.ID)
			resource, err := resourceSetsBindingsResource(ctx, &resourceSetCpy, nil)
			if err != nil {
				return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to create resource-set-binding: %w", err)
			}

			rv = append(rv, resource)
		}
	}

	pageToken, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, err
	}

	return rv, pageToken, nil, nil
}

func getResourceSetBindingID(resourceSetID string, roleID string) string {
	return resourceSetID + ":" + roleID
}

func (rsb *resourceSetsBindingsResourceType) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return []*v2.Entitlement{
		sdkEntitlement.NewAssignmentEntitlement(
			resource,
			entitlementName,
			sdkEntitlement.WithAnnotation(&v2.V1Identifier{
				Id: V1MembershipEntitlementID(resource.Id.GetResource()),
			}),
			sdkEntitlement.WithGrantableTo(resourceTypeResourceSets),
			sdkEntitlement.WithDisplayName(fmt.Sprintf("%s Resource Set Binding Member", resource.DisplayName)),
			sdkEntitlement.WithDescription(fmt.Sprintf("Member of %s resource-set-binding member in Okta", resource.DisplayName)),
		),
	}, "", nil, nil
}

// listMembersOfBinding. List all Role Resource Set Binding Members
// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleDResourceSetBindingMember/#tag/RoleDResourceSetBindingMember/operation/listMembersOfBinding
func (rsb *resourceSetsBindingsResourceType) listMembersOfBinding(
	ctx context.Context,
	client *okta.Client,
	resourceSetId, customRoleId string,
	_ *query.Params,
) ([]MembersDetails, *okta.Response, error) {
	apiPath, err := url.JoinPath(apiPathListIamResourceSets, resourceSetId, "bindings", customRoleId, "members")
	if err != nil {
		return nil, nil, err
	}

	reqUrl, err := url.Parse(apiPath)
	if err != nil {
		return nil, nil, err
	}

	var resourceSetBindings *resourceSetBindingsAPIData
	resp, err := doRequest(ctx, reqUrl.String(), http.MethodGet, &resourceSetBindings, client)
	if err != nil {
		return nil, nil, err
	}

	return resourceSetBindings.Members, resp, nil
}

// createRoleResourceSetBinding. Create a Role Resource Set Binding.
// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleDResourceSetBinding/#tag/RoleDResourceSetBinding/operation/createResourceSetBinding
func (rsb *resourceSetsBindingsResourceType) createRoleResourceSetBinding(ctx context.Context, resourceSetId, roleId string, memberId string) (*okta.Response, error) {
	payload := struct {
		Role    string   `json:"role"`
		Members []string `json:"members"`
	}{
		Role:    roleId,
		Members: []string{memberId},
	}

	apiPath, err := url.JoinPath(apiPathListIamResourceSets, resourceSetId, "bindings")
	if err != nil {
		return nil, err
	}

	reqUrl, err := url.Parse(apiPath)
	if err != nil {
		return nil, err
	}

	rq := rsb.client.CloneRequestExecutor()
	req, err := rq.WithAccept(ContentType).
		WithContentType(ContentType).
		NewRequest(http.MethodPost, reqUrl.String(), payload)
	if err != nil {
		return nil, err
	}

	resp, err := rq.Do(ctx, req, nil)
	if err != nil {
		return resp, err
	}

	return resp, nil
}

// unassignMemberFromBinding. Unassign a Role Resource Set Bindiing Member
// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleDResourceSetBindingMember/#tag/RoleDResourceSetBindingMember/operation/unassignMemberFromBinding
func (rsb *resourceSetsBindingsResourceType) unassignMemberFromBinding(ctx context.Context, resourceSetId, customRoleId, memberId string, qp *query.Params) (*okta.Response, error) {
	apiPath, err := url.JoinPath(apiPathListIamResourceSets, resourceSetId, "bindings", customRoleId, "members", memberId)
	if err != nil {
		return nil, err
	}

	reqUrl, err := url.Parse(apiPath)
	if err != nil {
		return nil, err
	}

	resp, err := doRequest(ctx, reqUrl.String(), http.MethodDelete, nil, rsb.client)
	if err != nil {
		return resp, err
	}

	return resp, nil
}

func (rsb *resourceSetsBindingsResourceType) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	var (
		rv        []*v2.Grant
		principal *v2.Resource
	)
	bag, _, err := parsePageToken(pToken.Token, resource.Id)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	resourceIDs := strings.Split(resource.Id.Resource, ":")
	resourceSetId := resourceIDs[firstItem]
	customRoleId := resourceIDs[lastItem]
	members, _, err := rsb.listMembersOfBinding(ctx, rsb.client, resourceSetId, customRoleId, nil)
	if err != nil {
		return nil, "", nil, err
	}

	for _, member := range members {
		memberHref := strings.Split(member.Links.Self.Href, "/")
		resourceType := memberHref[len(memberHref)-resourceMaxLength]
		resourceId := memberHref[len(memberHref)-lastItem]
		switch resourceType {
		case resourceUsers:
			principal = &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeUser.Id, Resource: resourceId}}
		case resourceGroups:
			principal = &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeGroup.Id, Resource: resourceId}}
		}

		if principal == nil {
			continue
		}

		gr := sdkGrant.NewGrant(resource, entitlementName, principal,
			sdkGrant.WithAnnotation(&v2.V1Identifier{
				Id: fmtGrantIdV1(V1MembershipEntitlementID(resource.Id.Resource), resource.Id.Resource),
			}),
		)
		rv = append(rv, gr)
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

func (rs *resourceSetsBindingsResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	var apiUrl = usersUrl
	l := ctxzap.Extract(ctx)
	if principal.Id.ResourceType != resourceTypeUser.Id && principal.Id.ResourceType != resourceTypeGroup.Id {
		l.Warn(
			"okta-connector: only users or groups can be granted resource-sets membership",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("okta-connector: only users or groups can be granted resource-sets membership")
	}

	entitlementId := entitlement.Resource.Id.Resource
	resourceId := principal.Id.Resource
	resourceIDs := strings.Split(entitlementId, ":")
	if len(resourceIDs) != resourceMaxLength {
		return nil, fmt.Errorf("okta-connector: invalid resourceset-binding-id")
	}

	resourceSetId := resourceIDs[firstItem]
	customRoleId := resourceIDs[lastItem]
	if principal.Id.ResourceType == resourceTypeGroup.Id {
		apiUrl = groupsUrl
	}

	memberUrl, err := url.JoinPath(defaultProtocol, rs.domain, apiUrl, resourceId)
	if err != nil {
		return nil, err
	}

	response, err := rs.createRoleResourceSetBinding(ctx,
		resourceSetId,
		customRoleId,
		memberUrl,
	)
	if err != nil {
		return nil, fmt.Errorf("okta-connector: failed to assign roles: %s", err.Error())
	}

	if response != nil && response.StatusCode == http.StatusOK {
		l.Warn("Resource Set Binding has been granted",
			zap.String("Status", response.Status),
		)
	}

	return nil, nil
}

func (rsb *resourceSetsBindingsResourceType) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	var memberId = ""
	l := ctxzap.Extract(ctx)
	entitlement := grant.Entitlement
	principal := grant.Principal
	if principal.Id.ResourceType != resourceTypeUser.Id && principal.Id.ResourceType != resourceTypeGroup.Id {
		l.Warn(
			"okta-connector: only users or groups can have role membership revoked",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("okta-connector:only users or groups can have role membership revoked")
	}

	entitlementId := entitlement.Resource.Id.Resource
	resourceIDs := strings.Split(entitlementId, ":")
	if len(resourceIDs) != resourceMaxLength {
		return nil, fmt.Errorf("okta-connector: invalid resourceset-binding-id")
	}

	resourceSetId := resourceIDs[firstItem]
	customRoleId := resourceIDs[lastItem]
	members, _, err := rsb.listMembersOfBinding(ctx,
		rsb.client,
		resourceSetId,
		customRoleId,
		nil,
	)
	if err != nil {
		return nil, err
	}

	for _, member := range members {
		memberHref := strings.Split(member.Links.Self.Href, "/")
		resourceId := memberHref[len(memberHref)-1]
		if principal.Id.Resource == resourceId {
			memberId = member.ID
			break
		}
	}

	if memberId != "" {
		response, err := rsb.unassignMemberFromBinding(ctx, resourceSetId, customRoleId, memberId, nil)
		if err != nil {
			return nil, fmt.Errorf("okta-connector: failed to remove roles: %s", err.Error())
		}

		if response != nil && response.StatusCode == http.StatusNoContent {
			l.Warn("Resource Set Binding has been revoked",
				zap.String("Status", response.Status),
			)
		}
	}

	return nil, nil
}

func (rsb *resourceSetsBindingsResourceType) Get(ctx context.Context, resourceId *v2.ResourceId, parentResourceId *v2.ResourceId) (*v2.Resource, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	l.Debug("getting resource set binding", zap.String("resource_set_binding_id", resourceId.Resource))

	resourceIDs := strings.Split(resourceId.Resource, ":")
	resourceSetId := resourceIDs[firstItem]
	customRoleId := resourceIDs[lastItem]

	resp, _, err := rsb.clientV5.ResourceSetAPI.GetBinding(ctx, resourceSetId, customRoleId).Execute()
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to get resource set binding: %w", err)
	}

	if resp == nil {
		return nil, nil, nil
	}

	rsResp, _, err := rsb.clientV5.ResourceSetAPI.GetResourceSet(ctx, resourceSetId).Execute()
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to get resource set: %w", err)
	}

	rsCopy := *rsResp
	rsCopy.SetId(getResourceSetBindingID(resourceSetId, customRoleId))

	resource, err := resourceSetBindingsResource(ctx, &rsCopy, parentResourceId)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to create resource set binding: %w", err)
	}

	return resource, nil, nil
}

func resourceSetsBindingsBuilder(domain string, client *okta.Client, clientV5 *oktav5.APIClient) *resourceSetsBindingsResourceType {
	return &resourceSetsBindingsResourceType{
		resourceType: resourceTypeResourceSetsBindings,
		domain:       domain,
		client:       client,
		clientV5:     clientV5,
	}
}
