package connector

import (
	"fmt"
	"net/url"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
)

const (
	V1MembershipEntitlementIDTemplate = "membership:%s"
	V1GrantIDTemplate                 = "grant:%s:%s"
)

type responseContext struct {
	token *pagination.Token

	requestID string

	status     string
	statusCode uint32

	hasRateLimit       bool
	rateLimit          int64
	rateLimitRemaining int64
	rateLimitReset     time.Time

	OktaResponse *okta.Response
}

func V1MembershipEntitlementID(resourceID string) string {
	return fmt.Sprintf(V1MembershipEntitlementIDTemplate, resourceID)
}

func fmtGrantIdV1(entitlementID string, userID string) string {
	return fmt.Sprintf(V1GrantIDTemplate, entitlementID, userID)
}

func fmtResourceGrant(resourceID *v2.ResourceId, principalId *v2.ResourceId, permission string) string {
	return fmt.Sprintf(
		"%s:%s:%s:%s:%s",
		resourceID.ResourceType,
		resourceID.Resource,
		permission,
		principalId.ResourceType,
		principalId.Resource,
	)
}

func fmtResourceIdV1(id string) string {
	return id
}

func fmtResourceId(resourceTypeID string, id string) *v2.ResourceId {
	return &v2.ResourceId{
		ResourceType: resourceTypeID,
		Resource:     id,
	}
}

func fmtResourceRole(resourceID *v2.ResourceId, role string) string {
	return fmt.Sprintf(
		"%s:%s",
		resourceID.ResourceType,
		resourceID.Resource,
	)
}

func queryParams(size int, after string) *query.Params {
	if size == 0 || size > defaultLimit {
		size = defaultLimit
	}
	if after == "" {
		return query.NewQueryParams(query.WithLimit(int64(size)))
	}

	return query.NewQueryParams(query.WithLimit(int64(size)), query.WithAfter(after))
}

func responseToContext(token *pagination.Token, resp *okta.Response) (*responseContext, error) {
	u, err := url.Parse(resp.NextPage)
	if err != nil {
		return nil, err
	}

	after := u.Query().Get("after")
	token.Token = after

	ret := &responseContext{
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
