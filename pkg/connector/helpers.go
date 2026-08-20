package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/ratelimit"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	V1MembershipEntitlementIDTemplate = "membership:%s"
	V1RoleEntitlementIDTemplate       = "role:%s"
	V1GrantIDTemplate                 = "grant:%s:%s"
)

type responseContext struct {
	OktaResponse *okta.Response
}

func V1MembershipEntitlementID(resourceID string) string {
	return fmt.Sprintf(V1MembershipEntitlementIDTemplate, resourceID)
}

// V1RoleEntitlementID returns the v1 entitlement id for role assignments.
// v1 emitted role grants on the Org resource with this id shape; v2 emits
// them on a Role resource, so we annotate with the v1 form for migration.
func V1RoleEntitlementID(roleType string) string {
	return fmt.Sprintf(V1RoleEntitlementIDTemplate, roleType)
}

func fmtGrantIdV1(entitlementID string, userID string) string {
	return fmt.Sprintf(V1GrantIDTemplate, entitlementID, userID)
}

func fmtResourceIdV1(id string) string {
	return id
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

// https://developer.okta.com/docs/reference/error-codes/
var oktaErrToGRPCError = map[string]codes.Code{
	"E0000006": codes.PermissionDenied,
	"E0000007": codes.NotFound,
	"E0000008": codes.NotFound,
	"E0000011": codes.Unauthenticated,
}

func handleOktaResponseError(resp *okta.Response, err error) error {
	if err == nil {
		return nil
	}

	// TODO: Whenever baton-sdk exposes wrapTransientNetworkError or something like it, use it here.
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		if urlErr.Timeout() {
			return status.Error(codes.DeadlineExceeded, fmt.Sprintf("request timeout: %v", urlErr.URL))
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return status.Error(codes.DeadlineExceeded, "request timeout")
	}

	// A 429 exhausting the v2 SDK's own retries drops the response, leaving only the
	// "too many requests" sentinel; check that before the response-based paths below.
	if isRateLimitError(resp, err) {
		return rateLimitError(resp, err)
	}

	var oktaApiError *okta.Error
	if errors.As(err, &oktaApiError) {
		grpcErrCode, ok := oktaErrToGRPCError[oktaApiError.ErrorCode]
		if ok {
			return errors.Join(status.Error(grpcErrCode, oktaApiError.ErrorSummary), err)
		}
	}

	// Fall back to http status code.
	if resp != nil && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
		grpcCode := uhttp.GrpcCodeFromHTTPStatus(resp.StatusCode)
		return uhttp.WrapErrorsWithRateLimitInfo(grpcCode, resp.Response, err)
	}

	return err
}

// isRevokeNotFoundError reports whether a revoke's failed check means the assignment is
// already gone: an HTTP 404, or a classified codes.NotFound — both mean the same thing.
func isRevokeNotFoundError(resp *okta.Response, err error) bool {
	if resp != nil && resp.StatusCode == http.StatusNotFound {
		return true
	}
	return status.Code(handleOktaResponseError(resp, err)) == codes.NotFound
}

// isRateLimitError reports a 429 from the response status, or from the "too many
// requests" sentinel once the v2 SDK exhausts its own retries and drops the response.
func isRateLimitError(resp *okta.Response, err error) bool {
	if resp != nil && resp.StatusCode == http.StatusTooManyRequests {
		return true
	}
	return err != nil && strings.Contains(err.Error(), "too many requests")
}

// rateLimitError classifies rate limits as codes.Unavailable, not ResourceExhausted:
// baton-sdk's provisioning retryer only waits and retries on Unavailable/DeadlineExceeded.
func rateLimitError(resp *okta.Response, err error) error {
	if resp != nil && resp.Response != nil {
		return uhttp.WrapErrorsWithRateLimitInfo(codes.Unavailable, resp.Response, err)
	}
	return uhttp.WrapErrors(codes.Unavailable, "rate limited by Okta", err)
}

// rateLimitAnnotations extracts rate-limit info from a successful response, nil-safe.
// desc can be a typed-nil *v2.RateLimitDescription that WithRateLimiting won't catch,
// so the nil check happens here instead.
func rateLimitAnnotations(resp *okta.Response) annotations.Annotations {
	var annos annotations.Annotations
	if resp == nil || resp.Response == nil {
		return annos
	}
	if desc, err := ratelimit.ExtractRateLimitData(resp.StatusCode, &resp.Header); err == nil && desc != nil {
		annos.WithRateLimiting(desc)
	}
	return annos
}

// apiValidationFailedErrorCode covers every Create User validation failure, so a
// duplicate login has to be confirmed from errorCauses before treating it as one.
// https://developer.okta.com/docs/reference/error-codes/#E0000001
const apiValidationFailedErrorCode = "E0000001"

// isDuplicateLoginError reports whether err is Okta rejecting a create because the
// login is already taken.
func isDuplicateLoginError(err error) bool {
	var oktaApiError *okta.Error
	if !errors.As(err, &oktaApiError) || oktaApiError.ErrorCode != apiValidationFailedErrorCode {
		return false
	}

	for _, cause := range oktaApiError.ErrorCauses {
		summary, ok := cause["errorSummary"].(string)
		if !ok {
			continue
		}
		if strings.HasPrefix(summary, profileFieldLogin+":") && strings.Contains(summary, "already exists") {
			return true
		}
	}

	return false
}

// createSuccessResponse creates a standardized success response struct.
// This helper is used by action functions to return consistent success responses.
// The message parameter provides additional context about the action result.
func createSuccessResponse(message string) *structpb.Struct {
	fields := map[string]*structpb.Value{
		actionResultSuccess: structpb.NewBoolValue(true),
	}
	if message != "" {
		fields["message"] = structpb.NewStringValue(message)
	}
	return &structpb.Struct{
		Fields: fields,
	}
}
