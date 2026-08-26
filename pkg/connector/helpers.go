package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/conductorone/baton-sdk/pkg/pagination"
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

// errorBodyExcerptLimit caps how much of an unparseable error body is echoed
// back into the returned error.
const errorBodyExcerptLimit = 200

func getError(response *okta.Response) (okta.Error, error) {
	var errOkta okta.Error
	bytes, err := io.ReadAll(response.Body)
	if err != nil {
		return okta.Error{}, bodyReadError(response, "read error body", err)
	}

	// An empty or non-JSON body used to surface as a bare "unexpected end of JSON
	// input" with no status code, which made an empty 400 indistinguishable from
	// an empty 403 in logs.
	err = json.Unmarshal(bytes, &errOkta)
	if err != nil {
		return okta.Error{}, bodyReadError(response, fmt.Sprintf("unparseable error body %q", bodyExcerpt(bytes)), err)
	}

	return errOkta, nil
}

// bodyReadError builds the error getError's callers return verbatim. The gRPC code
// comes from the HTTP status so that an unreadable body and a readable one produce
// the same classification for the same upstream failure -- a parseable body reaches
// handleOktaResponseError and gets a code, and without this an unparseable one
// would surface as codes.Unknown.
func bodyReadError(response *okta.Response, what string, err error) error {
	return uhttp.WrapErrors(
		uhttp.GrpcCodeFromHTTPStatus(response.StatusCode),
		fmt.Sprintf("okta-connectorv2: %s: %s", response.Status, what),
		err,
	)
}

// https://developer.okta.com/docs/reference/error-codes/
var oktaErrToGRPCError = map[string]codes.Code{
	"E0000006": codes.PermissionDenied,
	"E0000007": codes.NotFound,
	"E0000008": codes.NotFound,
	"E0000011": codes.Unauthenticated,
}

func bodyExcerpt(body []byte) string {
	excerpt := strings.TrimSpace(string(body))
	if len(excerpt) > errorBodyExcerptLimit {
		return truncateAtRuneBoundary(excerpt, errorBodyExcerptLimit) + "..."
	}
	return excerpt
}

// truncateAtRuneBoundary cuts s to at most maxBytes without splitting a rune, so
// the excerpt reaching an error message or a log field stays valid UTF-8.
func truncateAtRuneBoundary(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
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
		fields[actionResultMessage] = structpb.NewStringValue(message)
	}
	return &structpb.Struct{
		Fields: fields,
	}
}
