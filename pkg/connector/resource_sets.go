package connector

import (
	"context"
	"fmt"
	"net/http"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	sdkEntitlement "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	sdkResource "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
)

type resourceSetsResourceType struct {
	resourceType *v2.ResourceType
	client       *okta.Client
}

const apiPathListIamResourceSets = "/api/v1/iam/resource-sets"

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

func listOktaIamResourceSets(ctx context.Context,
	client *okta.Client,
	token *pagination.Token,
	qp *query.Params,
) ([]ResourceSets, *responseContext, error) {
	url := apiPathListIamResourceSets
	if qp != nil {
		url += qp.String()
	}

	rq := client.CloneRequestExecutor()
	req, err := rq.WithAccept(ContentType).
		WithContentType(ContentType).
		NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}

	var rSets *ResourceSetsAPIData
	resp, err := rq.Do(ctx, req, &rSets)
	if err != nil {
		return nil, nil, err
	}

	respCtx, err := responseToContext(token, resp)
	if err != nil {
		return nil, nil, err
	}

	return rSets.ResourceSets, respCtx, nil
}

// List always returns an empty slice, we don't sync users.
func (rs *resourceSetsResourceType) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	var rv []*v2.Resource
	bag, page, err := parsePageToken(pToken.Token, &v2.ResourceId{ResourceType: resourceTypeResourceSets.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	qp := queryParams(pToken.Size, page)
	rSets, respCtx, err := listOktaIamResourceSets(ctx, rs.client, pToken, qp)
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

	for _, rSet := range rSets {
		resource, err := resourceSetsResource(ctx, &rSet, nil)
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
			"member",
			sdkEntitlement.WithAnnotation(&v2.V1Identifier{
				Id: V1MembershipEntitlementID(resource.Id.GetResource()),
			}),
			sdkEntitlement.WithGrantableTo(resourceTypeResourceSets),
			sdkEntitlement.WithDisplayName(fmt.Sprintf("%s Resource Sets Member", resource.DisplayName)),
			sdkEntitlement.WithDescription(fmt.Sprintf("Member of %s group in Okta", resource.DisplayName)),
		),
	}, "", nil, nil
}

func (rs *resourceSetsResourceType) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func resourceSetsBuilder(client *okta.Client) *resourceSetsResourceType {
	return &resourceSetsResourceType{
		resourceType: resourceTypeResourceSets,
		client:       client,
	}
}
