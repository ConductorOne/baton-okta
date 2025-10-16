package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
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

// extractFieldAsString extracts and validates a string field from the arguments struct by key.
// It returns the value string and an error if validation fails.
func extractFieldAsString(args *structpb.Struct, fieldName string) (string, error) {
	if args == nil || args.Fields == nil {
		return "", fmt.Errorf("okta-connectorv2: no arguments provided")
	}

	field, ok := args.Fields[fieldName]
	if !ok || field == nil {
		return "", fmt.Errorf("okta-connectorv2: %s cannot be empty", fieldName)
	}

	value := field.GetStringValue()
	if value == "" {
		return "", fmt.Errorf("okta-connectorv2: %s cannot be empty", fieldName)
	}

	return value, nil
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

func handleOktaResponseError(resp *okta.Response, err error) error {
	return handleOktaResponseErrorWithNotFoundMessage(resp, err, "not found")
}

func handleOktaResponseErrorWithNotFoundMessage(resp *okta.Response, err error, message string) error {
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
	return convertNotFoundError(err, message)
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

// createSuccessResponse creates a standardized success response struct.
// This helper is used by action functions to return consistent success responses.
// The message parameter provides additional context about the action result.
func createSuccessResponse(message string) *structpb.Struct {
	fields := map[string]*structpb.Value{
		"success": structpb.NewBoolValue(true),
	}
	if message != "" {
		fields["message"] = structpb.NewStringValue(message)
	}
	return &structpb.Struct{
		Fields: fields,
	}
}
