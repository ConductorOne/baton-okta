package connector

import (
	"context"
	"fmt"
	"net/url"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
)

func is4xxResponse(ctx context.Context, response *okta.Response) bool {
	return response != nil && (response.StatusCode >= 400 && response.StatusCode <= 499)
}

func fmtResourceGrant(resourceID *v2.ResourceId, principalId *v2.ResourceId, permission string) string {
	return fmt.Sprintf(
		"%s-grant:%s:%s:%s:%s",
		resourceID.ResourceType,
		resourceID.Resource,
		principalId.ResourceType,
		principalId.Resource,
		permission,
	)
}

func fmtResourceId(resourceTypeID string, id string) *v2.ResourceId {
	return &v2.ResourceId{
		ResourceType: resourceTypeID,
		Resource:     id,
	}
}

func fmtResourceRole(resourceID *v2.ResourceId, role string) string {
	return fmt.Sprintf(
		"%s:%s:role:%s",
		resourceID.ResourceType,
		resourceID.Resource,
		role,
	)
}

func queryParams(size int, after string) *query.Params {
	if size == 0 || size > DefaultLimit {
		size = DefaultLimit
	}
	if after == "" {
		return query.NewQueryParams(query.WithLimit(int64(size)))
	}

	return query.NewQueryParams(query.WithLimit(int64(size)), query.WithAfter(after))
}

func responseToContext(token *pagination.Token, resp *okta.Response) (*ResponseContext, error) {
	u, err := url.Parse(resp.NextPage)
	if err != nil {
		return nil, err
	}

	after := u.Query().Get("after")
	token.Token = after

	ret := &ResponseContext{
		token:        token,
		requestID:    resp.Header.Get(oktaRequestIDHeader),
		status:       resp.Status,
		statusCode:   uint32(resp.StatusCode),
		OktaResponse: resp,
	}

	limit, remaining, reset, hasLimit := getRateLimit(resp)
	ret.rateLimit = limit
	ret.rateLimitRemaining = remaining
	ret.rateLimitReset = time.Unix(reset, 0)
	ret.hasRateLimit = hasLimit

	return ret, nil
}
