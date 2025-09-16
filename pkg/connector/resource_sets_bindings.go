package connector

import (
	"context"
	"errors"
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
	clientV5     *oktav5.APIClient
	domain       string
}

func (rsb *resourceSetsBindingsResourceType) ResourceType(ctx context.Context) *v2.ResourceType {
	return rsb.resourceType
}

func resourceSetsBindingsResource(ctx context.Context, rs *oktav5.ResourceSet, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	profile := map[string]interface{}{
		"id":          nullableStr(rs.Id),
		"label":       nullableStr(rs.Label),
		"description": nullableStr(rs.Description),
	}

	return sdkResource.NewResource(
		nullableStr(rs.Label),
		resourceTypeResourceSetsBindings,
		nullableStr(rs.Id),
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

	type paginationType struct {
		Value         string
		Page          string
		ResourceSetId string
	}

	bag, err := pagination.GenBagFromToken[paginationType](pToken)
	if err != nil {
		return nil, "", nil, err
	}

	if bag.Current() == nil {
		bag.Push(paginationType{
			Value: "RESOURCE_SET",
			Page:  "",
		})

		pageToken, err := bag.Marshal()
		if err != nil {
			return nil, "", nil, err
		}

		return rv, pageToken, nil, nil
	}

	state := bag.Pop()

	if state == nil {
		return nil, "", nil, nil
	}

	switch state.Value {
	case "RESOURCE_SET":
		resourceSets, respCtx, err := listResourceSetsV5(ctx, rsb.clientV5, state.Page)
		if err != nil {
			anno, err := wrapErrorV5(respCtx, err)
			return nil, "", anno, err
		}

		nextPage, anno, err := parseRespV5(respCtx)
		if err != nil {
			return nil, "", anno, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
		}

		if nextPage != "" {
			bag.Push(paginationType{
				Value: "RESOURCE_SET",
				Page:  nextPage,
			})
		}

		for _, set := range resourceSets.ResourceSets {
			if set.Id == nil {
				continue
			}

			bag.Push(paginationType{
				Value:         "RESOURCE_SET_BINDING",
				ResourceSetId: *set.Id,
				Page:          "",
			})
		}
	case "RESOURCE_SET_BINDING":
		resourceSet, resp, err := rsb.clientV5.ResourceSetAPI.GetResourceSet(ctx, state.ResourceSetId).Execute()
		if err != nil {
			anno, err := wrapErrorV5(resp, err)
			return nil, "", anno, err
		}

		roles, resp, err := listBindingsV5(ctx, rsb.clientV5, state.ResourceSetId, state.Page)
		if err != nil {
			anno, err := wrapErrorV5(resp, err)
			return nil, "", anno, err
		}

		nextPage, anno, err := parseRespV5(resp)
		if err != nil {
			return nil, "", anno, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
		}

		for _, role := range roles.Roles {
			if role.Id == nil {
				continue
			}

			tempId := getResourceSetBindingID(state.ResourceSetId, *role.Id)
			resourceSet.Id = &tempId
			resource, err := resourceSetsBindingsResource(ctx, resourceSet, nil)
			if err != nil {
				return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to create resource-set-binding: %w", err)
			}

			rv = append(rv, resource)
		}

		if nextPage != "" {
			bag.Push(paginationType{
				Value:         "RESOURCE_SET_BINDING",
				ResourceSetId: state.ResourceSetId,
				Page:          nextPage,
			})
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

// listMembersOfBindingV5. List all Role Resource Set Binding Members
// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleDResourceSetBindingMember/#tag/RoleDResourceSetBindingMember/operation/listMembersOfBinding
func (rsb *resourceSetsBindingsResourceType) listMembersOfBindingV5(
	ctx context.Context,
	client *oktav5.APIClient,
	resourceSetId, customRoleId string,
) (*oktav5.ResourceSetBindingMembers, *oktav5.APIResponse, error) {
	return client.ResourceSetAPI.ListMembersOfBinding(ctx, resourceSetId, customRoleId).Execute()
}

// createRoleResourceSetBindingV5. Create a Role Resource Set Binding.
// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleDResourceSetBinding/#tag/RoleDResourceSetBinding/operation/createResourceSetBinding
func (rsb *resourceSetsBindingsResourceType) createRoleResourceSetBindingV5(
	ctx context.Context,
	resourceSetId,
	roleId string,
	memberId string,
) (*oktav5.ResourceSetBindingResponse, *oktav5.APIResponse, error) {
	return rsb.clientV5.ResourceSetAPI.CreateResourceSetBinding(ctx, resourceSetId).
		Instance(oktav5.ResourceSetBindingCreateRequest{
			Role:    &roleId,
			Members: []string{memberId},
		}).
		Execute()
}

// unassignMemberFromBindingV5. Unassign a Role Resource Set Bindiing Member
// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleDResourceSetBindingMember/#tag/RoleDResourceSetBindingMember/operation/unassignMemberFromBinding
func (rsb *resourceSetsBindingsResourceType) unassignMemberFromBindingV5(ctx context.Context, resourceSetId, customRoleId, memberId string, qp *query.Params) (*oktav5.APIResponse, error) {
	return rsb.clientV5.ResourceSetAPI.UnassignMemberFromBinding(ctx, resourceSetId, customRoleId, memberId).Execute()
}

func (rsb *resourceSetsBindingsResourceType) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	var (
		rv        []*v2.Grant
		principal *v2.Resource
	)
	bag, _, err := parsePageToken(pToken.Token, resource.Id)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse Page token: %w", err)
	}

	resourceIDs := strings.Split(resource.Id.Resource, ":")
	resourceSetId := resourceIDs[firstItem]
	customRoleId := resourceIDs[lastItem]
	members, resp, err := rsb.listMembersOfBindingV5(ctx, rsb.clientV5, resourceSetId, customRoleId)
	if err != nil {
		anno, err := wrapErrorV5(resp, err)
		return nil, "", anno, err
	}

	for _, member := range members.Members {
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

	_, response, err := rs.createRoleResourceSetBindingV5(
		ctx,
		resourceSetId,
		customRoleId,
		memberUrl,
	)
	if err != nil {
		anno, err := wrapErrorV5(response, err, errors.New("okta-connector: failed to assign roles"))
		return anno, err
	}

	if response.StatusCode == http.StatusOK {
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
	members, resp, err := rsb.listMembersOfBindingV5(
		ctx,
		rsb.clientV5,
		resourceSetId,
		customRoleId,
	)
	if err != nil {
		anno, err := wrapErrorV5(resp, err, errors.New("okta-connector: failed to assign roles"))
		return anno, err
	}

	for _, member := range members.Members {
		if member.Id == nil {
			continue
		}

		memberHref := strings.Split(member.Links.Self.Href, "/")
		resourceId := memberHref[len(memberHref)-1]
		if principal.Id.Resource == resourceId {
			memberId = *member.Id
			break
		}
	}

	if memberId != "" {
		response, err := rsb.unassignMemberFromBindingV5(ctx, resourceSetId, customRoleId, memberId, nil)
		if err != nil {
			anno, err := wrapErrorV5(response, err, errors.New("okta-connector: failed to assign roles"))
			return anno, err
		}

		if response.StatusCode == http.StatusNoContent {
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

func resourceSetsBindingsBuilder(domain string, clientV5 *oktav5.APIClient) *resourceSetsBindingsResourceType {
	return &resourceSetsBindingsResourceType{
		resourceType: resourceTypeResourceSetsBindings,
		domain:       domain,
		clientV5:     clientV5,
	}
}
