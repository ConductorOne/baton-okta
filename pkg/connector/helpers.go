package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	V1MembershipEntitlementIDTemplate = "membership:%s"
	V1GrantIDTemplate                 = "grant:%s:%s"
)

type responseContext struct {
	token *pagination.Token

	requestID string

	status     string
	statusCode int

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

func fmtResourceIdV1(id string) string {
	return id
}

func fmtResourceId(resourceTypeID string, id string) *v2.ResourceId {
	return &v2.ResourceId{
		ResourceType: resourceTypeID,
		Resource:     id,
	}
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

func queryParamsExpand(size int, after string, expand string) *query.Params {
	if size == 0 || size > defaultLimit {
		size = defaultLimit
	}
	if after == "" {
		return query.NewQueryParams(query.WithLimit(int64(size)), query.WithExpand(expand))
	}

	return query.NewQueryParams(query.WithLimit(int64(size)), query.WithAfter(after), query.WithExpand(expand))
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
		statusCode:   resp.StatusCode,
		OktaResponse: resp,
	}

	limit, remaining, reset, hasLimit := getRateLimit(resp)
	ret.rateLimit = limit
	ret.rateLimitRemaining = remaining
	ret.rateLimitReset = time.Unix(reset, 0)
	ret.hasRateLimit = hasLimit

	return ret, nil
}

func getError(response *okta.Response) (okta.Error, error) {
	var errOkta okta.Error
	bytes, err := io.ReadAll(response.Body)
	if err != nil {
		return okta.Error{}, err
	}

	err = json.Unmarshal(bytes, &errOkta)
	if err != nil {
		return okta.Error{}, err
	}

	return errOkta, nil
}

func handleOktaResponseError(resp *okta.Response, err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		if urlErr.Timeout() {
			return status.Error(codes.DeadlineExceeded, fmt.Sprintf("request timeout: %v", urlErr.URL))
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return status.Error(codes.DeadlineExceeded, "request timeout")
	}
	if resp != nil && resp.StatusCode >= 500 {
		return status.Error(codes.Unavailable, "server error")
	}
	return err
}

// https://developer.okta.com/docs/reference/error-codes/?q=not%20found
var oktaNotFoundErrors = map[string]struct{}{
	"E0000007": {},
	"E0000008": {},
}

func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}

	var oktaApiError *okta.Error
	if !errors.As(err, &oktaApiError) {
		return false
	}

	_, ok := oktaNotFoundErrors[oktaApiError.ErrorCode]
	return ok
}
