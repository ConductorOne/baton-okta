package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"

	"github.com/conductorone/baton-sdk/pkg/annotations"

	oktav5 "github.com/conductorone/okta-sdk-golang/v5/okta"

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

	return &responseContext{
		OktaResponse: resp,
	}, nil
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

func getErrorV5(response *oktav5.APIResponse) (oktav5.Error, error) {
	var errOkta oktav5.Error
	bytes, err := io.ReadAll(response.Body)
	if err != nil {
		return oktav5.Error{}, err
	}

	err = json.Unmarshal(bytes, &errOkta)
	if err != nil {
		return oktav5.Error{}, err
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

func convertNotFoundError(err error, message string) error {
	if err == nil {
		return nil
	}

	var oktaApiError *okta.Error
	if !errors.As(err, &oktaApiError) {
		return err
	}

	_, ok := oktaNotFoundErrors[oktaApiError.ErrorCode]
	if !ok {
		return err
	}

	grpcErr := status.Error(codes.NotFound, message)
	allErrs := append([]error{grpcErr}, err)
	return errors.Join(allErrs...)
}

func nullableStr(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

type paginateV5Response[T any] struct {
	value    T
	resp     *oktav5.APIResponse
	annos    annotations.Annotations
	nextPage string
}

func paginateV5[T any](
	ctx context.Context,
	clientV5 *oktav5.APIClient,
	page string,
	act func(ctx2 context.Context) (T, *oktav5.APIResponse, error),
) (*paginateV5Response[T], error) {
	var response T
	var resp *oktav5.APIResponse
	var err error

	l := ctxzap.Extract(ctx)

	if page == "" {
		l.Debug("paginationV5: first page")

		response, resp, err = act(ctx)
		if err != nil {
			return nil, err
		}
	} else {
		l.Debug("paginationV5: paginate", zap.String("page", page))

		prevResp, err := deserializeOktaResponseV5(page)
		if err != nil {
			return nil, err
		}

		previous := oktav5.NewAPIResponse(prevResp.Response, clientV5, nil)
		if previous.HasNextPage() {
			resp, err = previous.Next(&response)
			if err != nil {
				return nil, err
			}
		}
	}

	nextPage, annos, err := parseRespV5(resp)
	if err != nil {
		return nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
	}

	return &paginateV5Response[T]{
		value:    response,
		resp:     resp,
		annos:    annos,
		nextPage: nextPage,
	}, nil
}
