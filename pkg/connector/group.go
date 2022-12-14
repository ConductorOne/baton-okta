package connector

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/types/known/structpb"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
)

type groupResourceType struct {
	resourceType *v2.ResourceType
	domain       string
	apiToken     string
	client       *okta.Client
}

func (o *groupResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *groupResourceType) List(
	ctx context.Context,
	resourceID *v2.ResourceId,
	token *pagination.Token,
) ([]*v2.Resource, string, annotations.Annotations, error) {
	bag, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeUser.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	var rv []*v2.Resource
	qp := queryParams(token.Size, page)

	groups, respCtx, err := listGroups(ctx, o.client, token, qp)
	if err != nil {
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

	for _, group := range groups {
		resource, err := groupResource(ctx, group)
		if err != nil {
			return nil, "", nil, err
		}

		rv = append(rv, resource)
	}

	pageToken, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, err
	}

	return rv, pageToken, annos, nil
}

func (o *groupResourceType) Entitlements(
	ctx context.Context,
	resource *v2.Resource,
	token *pagination.Token,
) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement

	rv = append(rv, groupEntitlement(ctx, resource))

	return rv, "", nil, nil
}

func (o *groupResourceType) Grants(
	ctx context.Context,
	resource *v2.Resource,
	token *pagination.Token,
) ([]*v2.Grant, string, annotations.Annotations, error) {
	bag, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeUser.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	var rv []*v2.Grant
	qp := queryParams(token.Size, page)

	users, respCtx, err := listGroupUsers(ctx, o.client, resource.Id.GetResource(), token, qp)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list group users: %w", err)
	}

	nextPage, annos, err := parseResp(respCtx.OktaResponse)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
	}

	for _, user := range users {
		rv = append(rv, groupGrant(resource, user))
	}

	pageToken, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, err
	}

	return rv, pageToken, annos, nil
}

func listGroups(ctx context.Context, client *okta.Client, token *pagination.Token, qp *query.Params) ([]*okta.Group, *responseContext, error) {
	groups, resp, err := client.Group.ListGroups(ctx, qp)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch groups from okta: %w", err)
	}

	reqCtx, err := responseToContext(token, resp)
	if err != nil {
		return nil, nil, err
	}

	return groups, reqCtx, nil
}

func listGroupUsers(ctx context.Context, client *okta.Client, groupID string, token *pagination.Token, qp *query.Params) ([]*okta.User, *responseContext, error) {
	users, resp, err := client.Group.ListGroupUsers(ctx, groupID, qp)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch group users from okta: %w", err)
	}

	reqCtx, err := responseToContext(token, resp)
	if err != nil {
		return nil, nil, err
	}

	return users, reqCtx, nil
}

func groupResource(ctx context.Context, group *okta.Group) (*v2.Resource, error) {
	trait, err := groupTrait(ctx, group)
	if err != nil {
		return nil, err
	}

	var annos annotations.Annotations
	annos.Update(trait)
	annos.Update(&v2.V1Identifier{
		Id: fmtResourceIdV1(group.Id),
	})

	return &v2.Resource{
		Id:          fmtResourceId(resourceTypeGroup.Id, group.Id),
		DisplayName: group.Profile.Name,
		Annotations: annos,
	}, nil
}

func groupTrait(ctx context.Context, group *okta.Group) (*v2.GroupTrait, error) {
	profile, err := structpb.NewStruct(map[string]interface{}{
		"description": group.Profile.Description,
		"name":        group.Profile.Name,
	})
	if err != nil {
		return nil, fmt.Errorf("okta-connectorv2: failed to construct role profile for role trait: %w", err)
	}

	ret := &v2.GroupTrait{
		Profile: profile,
	}

	return ret, nil
}

func groupEntitlement(ctx context.Context, resource *v2.Resource) *v2.Entitlement {
	var annos annotations.Annotations
	annos.Update(&v2.V1Identifier{
		Id: V1MembershipEntitlementID(resource.Id.GetResource()),
	})
	return &v2.Entitlement{
		Id:          fmtResourceRole(resource.Id, resource.Id.GetResource()),
		Resource:    resource,
		DisplayName: fmt.Sprintf("%s Group Member", resource.DisplayName),
		Description: fmt.Sprintf("Member of %s group in Okta", resource.DisplayName),
		Annotations: annos,
		GrantableTo: []*v2.ResourceType{resourceTypeUser},
		Purpose:     v2.Entitlement_PURPOSE_VALUE_ASSIGNMENT,
		Slug:        resource.DisplayName,
	}
}

func groupGrant(resource *v2.Resource, user *okta.User) *v2.Grant {
	groupID := resource.Id.GetResource()
	ur := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeUser.Id, Resource: user.Id}}

	var annos annotations.Annotations
	annos.Update(&v2.V1Identifier{
		Id: fmtGrantIdV1(V1MembershipEntitlementID(resource.Id.Resource), user.Id),
	})

	return &v2.Grant{
		Id: fmtResourceGrant(resource.Id, ur.Id, groupID),
		Entitlement: &v2.Entitlement{
			Id:       fmtResourceRole(resource.Id, groupID),
			Resource: resource,
		},
		Annotations: annos,
		Principal:   ur,
	}
}

func groupBuilder(domain string, apiToken string, client *okta.Client) *groupResourceType {
	return &groupResourceType{
		resourceType: resourceTypeGroup,
		domain:       domain,
		apiToken:     apiToken,
		client:       client,
	}
}
