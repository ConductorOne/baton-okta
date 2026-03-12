package connector

import (
	"context"
	"fmt"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
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

func (o *apiTokenResourceType) Entitlements(ctx context.Context, resource *v2.Resource, attrs resource.SyncOpAttrs) ([]*v2.Entitlement, *resource.SyncOpResults, error) {
	// API Token secrets do not have entitlements
	return nil, nil, nil
}

func (o *apiTokenResourceType) Grants(ctx context.Context, resource *v2.Resource, attrs resource.SyncOpAttrs) ([]*v2.Grant, *resource.SyncOpResults, error) {
	// API Token secrets do not have grants
	return nil, nil, nil
}

func (o *apiTokenResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *apiTokenResourceType) List(
	ctx context.Context,
	resourceID *v2.ResourceId,
	attrs resource.SyncOpAttrs,
) ([]*v2.Resource, *resource.SyncOpResults, error) {
	token := &attrs.PageToken
	bag, prevSerializedResp, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeApiToken.Id})
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connector-v5: failed to parse page token: %w", err)
	}

	var apiTokens []oktav5.ApiToken
	var resp *oktav5.APIResponse

	if prevSerializedResp == "" {
		apiTokens, resp, err = o.clientV5.ApiTokenAPI.ListApiTokens(ctx).Execute()
		if err != nil {
			return nil, nil, fmt.Errorf("okta-connector-v5: failed to list api tokens: %w", err)
		}
	} else {
		prevResp, err := deserializeOktaResponseV5(prevSerializedResp)
		if err != nil {
			return nil, nil, fmt.Errorf("okta-connector-v5: failed to deserialize page token: %w", err)
		}

		localOktaAPIResponse := oktav5.NewAPIResponse(prevResp.Response, o.clientV5, nil)
		if localOktaAPIResponse.HasNextPage() {
			resp, err = localOktaAPIResponse.Next(&apiTokens)
			if err != nil {
				return nil, nil, err
			}
		}
	}

	nextPage, annos, err := parseRespV5(resp)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connector-v5: failed to parse response: %w", err)
	}

	ret := make([]*v2.Resource, 0, len(apiTokens))
	for _, apiToken := range apiTokens {
		rv, err := apiTokenResource(&apiToken)
		if err != nil {
			return nil, nil, err
		}
		ret = append(ret, rv)
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, nil, err
	}

	nextPageToken, err := bag.Marshal()
	if err != nil {
		return nil, nil, err
	}

	return ret, &resource.SyncOpResults{NextPageToken: nextPageToken, Annotations: annos}, nil
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
