package connector

import (
	"context"
	"fmt"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/ratelimit"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
	oktav5 "github.com/conductorone/okta-sdk-golang/v5/okta"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
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
	bag, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeApiToken.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connector-v5: failed to parse page token: %w", err)
	}

	v5, err := paginateV5(ctx, o.clientV5, page, func(ctx2 context.Context) ([]oktav5.ApiToken, *oktav5.APIResponse, error) {
		return o.clientV5.ApiTokenAPI.ListApiTokens(ctx).Execute()
	})
	if err != nil {
		return nil, "", nil, err
	}

	apiTokens := v5.value
	nextPage, annos := v5.nextPage, v5.annos

	ret := make([]*v2.Resource, 0, len(apiTokens))
	for _, apiToken := range apiTokens {
		rv, err := apiTokenResource(&apiToken)
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

func (o *apiTokenResourceType) Get(ctx context.Context, resourceId *v2.ResourceId, parentResourceId *v2.ResourceId) (*v2.Resource, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	l.Debug("getting api token", zap.String("api_token_id", resourceId.Resource))

	var annos annotations.Annotations

	apiToken, resp, err := o.clientV5.ApiTokenAPI.GetApiToken(ctx, resourceId.Resource).Execute()
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connector-v5: failed to get api token: %w", err)
	}

	if desc, err := ratelimit.ExtractRateLimitData(resp.StatusCode, &resp.Header); err == nil {
		annos.WithRateLimiting(desc)
	}

	if apiToken == nil {
		return nil, annos, nil
	}

	resource, err := apiTokenResource(apiToken)
	if err != nil {
		return nil, annos, err
	}

	return resource, annos, nil
}

func apiTokenResource(apiToken *oktav5.ApiToken) (*v2.Resource, error) {
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
		return nil, err
	}

	return rv, nil
}
