package connector

import (
	"context"
	"fmt"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
	oktav5 "github.com/conductorone/okta-sdk-golang/v5/okta"
)

type apiTokenResourceType struct {
	resourceType *v2.ResourceType
	clientV5     *oktav5.APIClient
}

func (o *apiTokenResourceType) Entitlements(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	// API Token secrets do not have entitlements
	return nil, "", nil, nil
}

func (o *apiTokenResourceType) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	// API Token secrets do not have grants
	return nil, "", nil, nil
}

func (o *apiTokenResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *apiTokenResourceType) List(
	ctx context.Context,
	resourceID *v2.ResourceId,
	token *pagination.Token,
) ([]*v2.Resource, string, annotations.Annotations, error) {
	bag, prevSerializedResp, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeApiToken.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connector-v5: failed to parse page token: %w", err)
	}

	var apiTokens []oktav5.ApiToken
	var resp *oktav5.APIResponse

	if prevSerializedResp == "" {
		apiTokens, resp, err = o.clientV5.ApiTokenAPI.ListApiTokens(ctx).Execute()
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connector-v5: failed to list api tokens: %w", err)
		}
	} else {
		prevResp, err := deserializeOktaResponseV5(prevSerializedResp)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connector-v5: failed to deserialize page token: %w", err)
		}

		localOktaAPIResponse := oktav5.NewAPIResponse(prevResp.Response, o.clientV5, nil)
		if localOktaAPIResponse.HasNextPage() {
			resp, err = localOktaAPIResponse.Next(&apiTokens)
			if err != nil {
				return nil, "", nil, err
			}
		}
	}

	nextPage, annos, err := parseRespV5(resp)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connector-v5: failed to parse response: %w", err)
	}

	ret := make([]*v2.Resource, 0, len(apiTokens))
	for _, apiToken := range apiTokens {
		options := []resource.SecretTraitOption{
			resource.WithSecretExpiresAt(*apiToken.ExpiresAt),
			resource.WithSecretIdentityID(&v2.ResourceId{
				ResourceType:  resourceTypeUser.Id,
				Resource:      *apiToken.UserId,
				BatonResource: false,
			}),
			resource.WithSecretCreatedByID(&v2.ResourceId{
				ResourceType:  resourceTypeUser.Id,
				Resource:      *apiToken.UserId,
				BatonResource: false,
			}),
			resource.WithSecretLastUsedAt(*apiToken.LastUpdated),
			resource.WithSecretCreatedAt(*apiToken.Created),
		}
		rv, err := resource.NewSecretResource(
			apiToken.Name,
			resourceTypeApiToken,
			*apiToken.Id,
			options,
		)
		if err != nil {
			return nil, "", nil, err
		}
		ret = append(ret, rv)
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, "", nil, err
	}

	nextPageToken, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, err
	}

	return ret, nextPageToken, annos, nil
}

func apiTokenBuilder(clientV5 *oktav5.APIClient) *apiTokenResourceType {
	return &apiTokenResourceType{
		resourceType: resourceTypeApiToken,
		clientV5:     clientV5,
	}
}
