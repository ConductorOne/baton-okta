package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/conductorone/baton-okta/pkg/okta"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/session"
	sdkResource "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRoleGrantsListingErrors(t *testing.T) {
	type grantLister interface {
		Grants(context.Context, *v2.Resource, sdkResource.SyncOpAttrs) ([]*v2.Grant, *sdkResource.SyncOpResults, error)
	}
	roleBuilderForTest := func(custom bool) func(*okta.Client) grantLister {
		return func(client *okta.Client) grantLister {
			connector := &Okta{client: client, SyncCustomRoles: true, userFilters: &userFilterConfig{}}
			if custom {
				return customRoleBuilder(connector)
			}
			return roleBuilder(client, connector)
		}
	}
	roleID := &v2.ResourceId{ResourceType: resourceTypeRole.Id, Resource: "USER_ADMIN"}
	customRoleID := &v2.ResourceId{ResourceType: resourceTypeCustomRole.Id, Resource: "cr1"}
	resourceSetID := &v2.ResourceId{ResourceType: resourceTypeResourceSets.Id, Resource: "rs1"}
	bindingID := &v2.ResourceId{ResourceType: resourceTypeResourceSetsBindings.Id, Resource: "rs1:cr1"}
	assignees := oktaRequestStep{
		method: http.MethodGet, path: apiPathListAllUsersWithRoleAssignments,
		statusCode: http.StatusOK, body: `{"value":[{"id":"` + testOktaUserID + `"}]}`,
	}
	targets := []struct {
		name    string
		build   func(*okta.Client) grantLister
		id      *v2.ResourceId
		path    string
		prelude []oktaRequestStep
	}{
		{name: "role assignees", build: roleBuilderForTest(false), id: roleID, path: apiPathListAllUsersWithRoleAssignments},
		{name: "custom role assignees", build: roleBuilderForTest(true), id: customRoleID, path: apiPathListAllUsersWithRoleAssignments},
		{name: "role user roles", build: roleBuilderForTest(false), id: roleID, path: "/api/v1/users/" + testOktaUserID + "/roles", prelude: []oktaRequestStep{assignees}},
		{name: "custom role user roles", build: roleBuilderForTest(true), id: customRoleID, path: "/api/v1/users/" + testOktaUserID + "/roles", prelude: []oktaRequestStep{assignees}},
		{name: "resource set bindings", build: func(c *okta.Client) grantLister { return &resourceSetsResourceType{client: c} }, id: resourceSetID, path: "/api/v1/iam/resource-sets/rs1/bindings"},
		{
			name: "binding members", build: func(c *okta.Client) grantLister { return &resourceSetsBindingsResourceType{client: c} },
			id: bindingID, path: "/api/v1/iam/resource-sets/rs1/bindings/cr1/members",
		},
	}
	errors := []struct {
		name string
		step oktaRequestStep
		code codes.Code
		skip bool
	}{
		{
			name: "access denied",
			step: oktaRequestStep{statusCode: http.StatusForbidden, body: `{"errorCode":"E0000006","errorSummary":"You do not have permission to perform the requested action"}`},
			skip: true,
		},
		{name: "unauthenticated", step: oktaRequestStep{statusCode: http.StatusUnauthorized, body: `{"errorCode":"E0000011","errorSummary":"Invalid token provided"}`}, code: codes.Unauthenticated},
		{name: "server error", step: oktaRequestStep{statusCode: http.StatusInternalServerError, body: `{"errorCode":"E0000009","errorSummary":"Internal Server Error"}`}, code: codes.Unavailable},
		{name: "bad request", step: oktaRequestStep{statusCode: http.StatusBadRequest, body: `{"errorCode":"E0000001","errorSummary":"Api validation failed"}`}, code: codes.InvalidArgument},
		{name: "non Okta forbidden", step: oktaRequestStep{statusCode: http.StatusForbidden, body: `<html>Forbidden</html>`}, code: codes.PermissionDenied},
		{name: "other forbidden", step: oktaRequestStep{statusCode: http.StatusForbidden, body: `{"errorCode":"E0000015","errorSummary":"Feature not enabled"}`}, code: codes.PermissionDenied},
		{name: "rate limited", step: rateLimitedStep(http.MethodGet, ""), code: codes.Unavailable},
	}
	for _, target := range targets {
		t.Run(target.name, func(t *testing.T) {
			for _, tc := range errors {
				t.Run(tc.name, func(t *testing.T) {
					step := tc.step
					step.method, step.path = http.MethodGet, target.path
					steps := append(append([]oktaRequestStep{}, target.prelude...), step)
					client := newScriptedOktaClient(t, steps...)
					bag := &pagination.Bag{}
					bag.Push(pagination.PageState{ResourceTypeID: target.id.ResourceType, Token: "previous-page"})
					token, err := bag.Marshal()
					require.NoError(t, err)
					var logs bytes.Buffer
					core := zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(&logs), zap.WarnLevel)
					ctx := ctxzap.ToContext(t.Context(), zap.New(core))
					grants, results, err := target.build(client).Grants(ctx, &v2.Resource{Id: target.id}, sdkResource.SyncOpAttrs{
						PageToken: pagination.Token{Token: token}, Session: &session.NoOpSessionStore{},
					})
					require.Empty(t, grants)
					if tc.skip {
						require.NoError(t, err)
						require.NotNil(t, results)
						require.Empty(t, results.NextPageToken)
						require.NotContains(t, logs.String(), "test-token")
						var warnings int
						for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
							var entry map[string]interface{}
							require.NoError(t, json.Unmarshal([]byte(line), &entry))
							if entry["resource_id"] == target.id.Resource {
								warnings++
								require.Equal(t, target.id.ResourceType, entry["resource_type"])
								require.Equal(t, "warn", entry["level"])
							}
						}
						require.Equal(t, 1, warnings)
					} else {
						require.Error(t, err)
						require.Equal(t, tc.code, status.Code(err), "%v", err)
					}
				})
			}
		})
	}
}

func TestRoleGrantsRetryRateLimit(t *testing.T) {
	for _, custom := range []bool{false, true} {
		name := "standard"
		if custom {
			name = "custom"
		}
		t.Run(name, func(t *testing.T) {
			limited := rateLimitedStep(http.MethodGet, apiPathListAllUsersWithRoleAssignments)
			limited.repeat = 1
			client := newScriptedOktaClient(t, limited, oktaRequestStep{
				method: http.MethodGet, path: apiPathListAllUsersWithRoleAssignments,
				statusCode: http.StatusOK, body: `{"value":[]}`,
			})
			connector := &Okta{client: client, userFilters: &userFilterConfig{}}
			resource := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeRole.Id, Resource: "USER_ADMIN"}}
			var grants []*v2.Grant
			var results *sdkResource.SyncOpResults
			var err error
			if custom {
				resource.Id = &v2.ResourceId{ResourceType: resourceTypeCustomRole.Id, Resource: "cr1"}
				grants, results, err = customRoleBuilder(connector).Grants(t.Context(), resource, sdkResource.SyncOpAttrs{})
			} else {
				grants, results, err = roleBuilder(client, connector).Grants(t.Context(), resource, sdkResource.SyncOpAttrs{})
			}
			require.NoError(t, err)
			require.Empty(t, grants)
			require.NotNil(t, results)
			require.Empty(t, results.NextPageToken)
		})
	}
}

func TestRoleProvisioningStillReturnsAccessDenied(t *testing.T) {
	denied := `{"errorCode":"E0000006","errorSummary":"You do not have permission to perform the requested action"}`
	t.Run("grant", func(t *testing.T) {
		client := newScriptedOktaClient(t, oktaRequestStep{
			method: http.MethodPost, path: "/api/v1/users/" + testOktaUserID + "/roles", statusCode: http.StatusForbidden, body: denied,
		})
		_, err := roleBuilder(client, nil).Grant(t.Context(), testUserPrincipal(), roleAssignedEntitlement())
		require.Error(t, err)
		require.Equal(t, codes.PermissionDenied, status.Code(err))
	})
	t.Run("revoke", func(t *testing.T) {
		client := newScriptedOktaClient(t, oktaRequestStep{
			method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID + "/roles", statusCode: http.StatusForbidden, body: denied,
		})
		_, err := roleBuilder(client, nil).Revoke(t.Context(), &v2.Grant{Principal: testUserPrincipal(), Entitlement: roleAssignedEntitlement()})
		require.Error(t, err)
		require.Equal(t, codes.PermissionDenied, status.Code(err))
	})
}
