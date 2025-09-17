package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/conductorone/baton-okta/pkg/connector/oktaerrors"
	"google.golang.org/grpc/status"

	"github.com/conductorone/baton-sdk/pkg/annotations"

	oktav5 "github.com/conductorone/okta-sdk-golang/v5/okta"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"google.golang.org/grpc/codes"
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

func asErrorV5(err error) (*oktav5.Error, bool) {
	var oktaGenericErr *oktav5.GenericOpenAPIError

	if errors.As(err, &oktaGenericErr) {
		var oktaErr oktav5.Error
		err := json.Unmarshal(oktaGenericErr.Body(), &oktaErr)
		if err != nil {
			return nil, false
		}

		return &oktaErr, true
	}

	return nil, false
}

// wrapErrorV5 wraps an error into GRPC error if it is an oktav5.Error.
func wrapErrorV5(resp *oktav5.APIResponse, originalErr error, additionalError ...error) (annotations.Annotations, error) {
	_, annon, err := parseRespV5(resp)
	if err != nil {
		return nil, errors.Join(append([]error{originalErr, err}, additionalError...)...)
	}

	if v5Err, ok := asErrorV5(originalErr); ok {
		return annon, toErrorV5(*v5Err, additionalError...)
	}

	return annon, errors.Join(append([]error{originalErr}, additionalError...)...)
}

func toErrorV5(e oktav5.Error, additionalError ...error) error {
	formattedErr := "the API returned an unknown error"
	if e.ErrorSummary != nil {
		formattedErr = fmt.Sprintf("the API returned an error: %s", *e.ErrorSummary)
	}
	if len(e.ErrorCauses) > 0 {
		var causes []string
		for _, cause := range e.ErrorCauses {
			if cause.ErrorSummary == nil {
				continue
			}

			causes = append(causes, fmt.Sprintf("Error cause: %v", *cause.ErrorSummary))
		}
		formattedErr = fmt.Sprintf("%s. Causes: %s", formattedErr, strings.Join(causes, ", "))
	}

	err := errors.New(formattedErr)

	findError := oktaerrors.FindError(nullableStr(e.ErrorCode))
	if findError == nil {
		return err
	}

	// Same as https://github.com/ConductorOne/baton-sdk/blob/main/pkg/uhttp/wrapper.go#L444
	code := codes.Unknown
	switch findError.StatusCode {
	case http.StatusRequestTimeout:
		code = codes.DeadlineExceeded
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		code = codes.Unavailable
	case http.StatusNotFound:
		code = codes.NotFound
	case http.StatusUnauthorized:
		code = codes.Unauthenticated
	case http.StatusForbidden:
		code = codes.PermissionDenied
	case http.StatusConflict:
		code = codes.AlreadyExists
	case http.StatusNotImplemented:
		code = codes.Unimplemented
	}

	if findError.StatusCode >= 500 && findError.StatusCode <= 599 {
		code = codes.Unavailable
	}

	if len(additionalError) > 0 {
		return errors.Join(
			append(
				[]error{
					status.Error(code, formattedErr),
				},
				additionalError...,
			)...,
		)
	}

	return status.Error(code, formattedErr)
}

func nullableStr(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func doV5Request(ctx context.Context, client *oktav5.APIClient, request *http.Request, in any) (*oktav5.APIResponse, error) {
	resp, err := client.Do(ctx, request)
	if err != nil {
		localAPIResponse := oktav5.NewAPIResponse(resp, client, nil)
		return localAPIResponse, err
	}

	localVarBody, err := io.ReadAll(resp.Body)
	if err != nil {
		localAPIResponse := oktav5.NewAPIResponse(resp, client, nil)
		return localAPIResponse, err
	}
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewBuffer(localVarBody))

	localAPIResponse := oktav5.NewAPIResponse(resp, client, nil)

	err = json.Unmarshal(localVarBody, in)
	if err != nil {
		return localAPIResponse, err
	}

	return localAPIResponse, nil
}
