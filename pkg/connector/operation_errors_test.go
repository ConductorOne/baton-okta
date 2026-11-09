package connector

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	sdkResource "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

func operationArgs(t *testing.T, values map[string]any) *structpb.Struct {
	t.Helper()
	args, err := structpb.NewStruct(values)
	if err != nil {
		t.Fatal(err)
	}
	return args
}

// Each case reaches a real SDK request, including multi-request actions whose
// initial read or creation succeeds before the operation being tested fails.
func TestOperationErrorClassification(t *testing.T) {
	const groupBody = `{"id":"` + testGroupID + `","type":"OKTA_GROUP","profile":{"name":"old name","description":"test group"}}`
	type operation struct {
		name   string
		method string
		path   string
		before []oktaRequestStep
		call   func(*testing.T, *okta.Client) error
	}
	createAccount := func(t *testing.T, client *okta.Client, suppressEmail bool) error {
		profile := operationArgs(t, map[string]any{
			"first_name": "Test", "last_name": "User", "email": "test@example.com", "login": "test@example.com",
			"send_activation_email": !suppressEmail,
		})
		_, _, _, err := userBuilder(&Okta{client: client}).CreateAccount(t.Context(), &v2.AccountInfo{Profile: profile},
			v2.LocalCredentialOptions_builder{NoPassword: &v2.LocalCredentialOptions_NoPassword{}}.Build())
		return err
	}
	operations := []operation{
		{
			name: "create account", method: http.MethodPost, path: "/api/v1/users",
			call: func(t *testing.T, client *okta.Client) error { return createAccount(t, client, false) },
		},
		{
			name: "activate created account", method: http.MethodPost, path: "/api/v1/users/" + testOktaUserID + "/lifecycle/activate",
			before: []oktaRequestStep{{method: http.MethodPost, path: "/api/v1/users", statusCode: http.StatusOK, body: oktaUserResponse(userStatusStaged)}},
			call:   func(t *testing.T, client *okta.Client) error { return createAccount(t, client, true) },
		},
		{
			name: "create group", method: http.MethodPost, path: "/api/v1/groups",
			call: func(t *testing.T, client *okta.Client) error {
				_, _, err := groupBuilder(&Okta{client: client}).handleCreateGroupAction(t.Context(), operationArgs(t, map[string]any{"name": "test group"}))
				return err
			},
		},
		{
			name: "read group for modification", method: http.MethodGet, path: "/api/v1/groups/" + testGroupID,
			call: func(t *testing.T, client *okta.Client) error {
				_, _, err := groupBuilder(&Okta{client: client}).handleModifyGroupAction(t.Context(), operationArgs(t, map[string]any{"group_id": testGroupID, "name": "new name"}))
				return err
			},
		},
		{
			name: "update group", method: http.MethodPut, path: "/api/v1/groups/" + testGroupID,
			before: []oktaRequestStep{{method: http.MethodGet, path: "/api/v1/groups/" + testGroupID, statusCode: http.StatusOK, body: groupBody}},
			call: func(t *testing.T, client *okta.Client) error {
				_, _, err := groupBuilder(&Okta{client: client}).handleModifyGroupAction(t.Context(), operationArgs(t, map[string]any{"group_id": testGroupID, "name": "new name"}))
				return err
			},
		},
		{
			name: "add initial group member", method: http.MethodPut, path: "/api/v1/groups/" + testGroupID + "/users/" + testOktaUserID,
			before: []oktaRequestStep{{method: http.MethodPost, path: "/api/v1/groups", statusCode: http.StatusOK, body: groupBody}},
			call: func(t *testing.T, client *okta.Client) error {
				_, _, err := groupBuilder(&Okta{client: client}).handleCreateGroupAction(t.Context(), operationArgs(t, map[string]any{
					"name": "test group", "userMembers": []any{map[string]any{"resource_type_id": userResourceTypeID, "resource_id": testOktaUserID}},
				}))
				return err
			},
		},
	}
	for _, lifecycle := range []struct {
		name    string
		status  string
		enabled bool
	}{
		{name: "suspend", status: userStatusActive},
		{name: "unsuspend", status: userStatusSuspended, enabled: true},
		{name: "activate", status: userStatusStaged, enabled: true},
	} {
		operations = append(operations, operation{
			name: lifecycle.name + " action", method: http.MethodPost, path: "/api/v1/users/" + testOktaUserID + "/lifecycle/" + lifecycle.name,
			before: []oktaRequestStep{{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaUserResponse(lifecycle.status)}},
			call: func(t *testing.T, client *okta.Client) error {
				_, _, err := (&Okta{client: client}).applyUserLifecycle(t.Context(), operationArgs(t, map[string]any{"user_id": testOktaUserID}), lifecycle.enabled)
				return err
			},
		})
	}
	failures := []struct {
		name       string
		statusCode int
		body       string
		want       codes.Code
	}{
		{name: "rate limited", statusCode: http.StatusTooManyRequests, want: codes.Unavailable},
		{name: "permission denied", statusCode: http.StatusForbidden, body: `{"errorCode":"E0000006","errorSummary":"Permission denied"}`, want: codes.PermissionDenied},
		{
			name:       "typed permission error overrides server status",
			statusCode: http.StatusInternalServerError,
			body:       `{"errorCode":"E0000006","errorSummary":"Permission denied"}`,
			want:       codes.PermissionDenied,
		},
		{name: "unauthenticated", statusCode: http.StatusUnauthorized, body: `{"errorCode":"E0000011","errorSummary":"Invalid token"}`, want: codes.Unauthenticated},
		{name: "invalid request", statusCode: http.StatusBadRequest, body: `{"errorCode":"E0000001","errorSummary":"Invalid request"}`, want: codes.InvalidArgument},
		{name: "not implemented", statusCode: http.StatusNotImplemented, body: `{"errorCode":"E0000099","errorSummary":"Not implemented"}`, want: codes.Unimplemented},
		{name: "server failure", statusCode: http.StatusInternalServerError, body: `{"errorCode":"E0000099","errorSummary":"Server failure"}`, want: codes.Unavailable},
	}
	for _, op := range operations {
		t.Run(op.name, func(t *testing.T) {
			for _, failure := range failures {
				t.Run(failure.name, func(t *testing.T) {
					step := oktaRequestStep{method: op.method, path: op.path, statusCode: failure.statusCode, body: failure.body, headers: map[string]string{"X-Okta-Request-Id": "test-request-id"}}
					if failure.statusCode == http.StatusTooManyRequests {
						step = rateLimitedStep(op.method, op.path)
					}
					steps := append(append([]oktaRequestStep{}, op.before...), step)
					err := op.call(t, newScriptedOktaClient(t, steps...))
					if status.Code(err) != failure.want {
						t.Fatalf("status = %s, want %s: %v", status.Code(err), failure.want, err)
					}
					if failure.statusCode == http.StatusTooManyRequests {
						assertOperationRetryDetail(t, err)
					} else {
						var vendorErr *okta.Error
						if !errors.As(err, &vendorErr) {
							t.Fatalf("error lost Okta error: %v", err)
						}
						if failure.statusCode == http.StatusInternalServerError && !strings.Contains(err.Error(), "test-request-id") {
							t.Fatalf("error lost Okta request ID: %v", err)
						}
					}
				})
			}
		})
	}
}

func assertOperationRetryDetail(t *testing.T, err error) {
	t.Helper()
	for _, detail := range status.Convert(err).Details() {
		if rateLimit, ok := detail.(*v2.RateLimitDescription); ok && rateLimit.GetResetAt() != nil {
			return
		}
	}
	t.Fatalf("error has no rate-limit retry detail: %v", err)
}

func TestRawReadErrorClassification(t *testing.T) {
	reads := []struct {
		name string
		path string
		call func(context.Context, *okta.Client) error
	}{
		{name: "users", path: "/api/v1/users", call: func(ctx context.Context, client *okta.Client) error {
			_, _, err := listUsers(ctx, client, &pagination.Token{}, query.NewQueryParams())
			return err
		}},
		{name: "custom roles", path: "/api/v1/iam/roles", call: func(ctx context.Context, client *okta.Client) error {
			_, _, err := listOktaIamCustomRoles(ctx, client, &pagination.Token{}, nil)
			return err
		}},
		{name: "role assignees", path: "/api/v1/iam/assignees/users", call: func(ctx context.Context, client *okta.Client) error {
			_, _, err := listAllUsersWithRoleAssignments(ctx, client, &pagination.Token{}, nil)
			return err
		}},
		{name: "user roles", path: "/api/v1/users/" + testOktaUserID + "/roles", call: func(ctx context.Context, client *okta.Client) error {
			_, _, err := listAssignedRolesForUser(ctx, client, testOktaUserID)
			return err
		}},
		{name: "group roles", path: "/api/v1/groups/" + testGroupID + "/roles", call: func(ctx context.Context, client *okta.Client) error {
			_, _, err := listGroupAssignedRoles(ctx, client, testGroupID)
			return err
		}},
		{name: "custom role", path: "/api/v1/iam/roles/test-role", call: func(ctx context.Context, client *okta.Client) error {
			_, _, err := getOktaIamCustomRole(ctx, client, "test-role")
			return err
		}},
		{name: "resource sets", path: "/api/v1/iam/resource-sets", call: func(ctx context.Context, client *okta.Client) error {
			_, _, err := listResourceSets(ctx, client, &pagination.Token{}, nil)
			return err
		}},
		{name: "resource set bindings", path: "/api/v1/iam/resource-sets/test-set/bindings", call: func(ctx context.Context, client *okta.Client) error {
			_, _, err := listBindings(ctx, client, "test-set")
			return err
		}},
		{name: "group", path: "/api/v1/groups/" + testGroupID, call: func(ctx context.Context, client *okta.Client) error {
			_, _, err := groupBuilder(&Okta{client: client}).GetGroupWithParams(ctx, testGroupID)
			return err
		}},
	}
	for _, read := range reads {
		t.Run(read.name, func(t *testing.T) {
			err := read.call(t.Context(), newScriptedOktaClient(t, rateLimitedStep(http.MethodGet, read.path)))
			if status.Code(err) != codes.Unavailable {
				t.Fatalf("status = %s, want Unavailable: %v", status.Code(err), err)
			}
			assertOperationRetryDetail(t, err)
		})
	}
}

func TestGroupRoleReadErrorPropagation(t *testing.T) {
	bag := &pagination.Bag{}
	bag.Push(pagination.PageState{ResourceTypeID: resourceTypeRole.Id})
	token, err := bag.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/groups/" + testGroupID + "/roles"
	tests := []struct {
		name string
		step oktaRequestStep
		want codes.Code
	}{
		{name: "rate limited", step: rateLimitedStep(http.MethodGet, path), want: codes.Unavailable},
		{name: "server failure", step: oktaRequestStep{
			method: http.MethodGet, path: path, statusCode: http.StatusInternalServerError,
			body:    `{"errorCode":"E0000099","errorSummary":"Server failure"}`,
			headers: map[string]string{"X-Okta-Request-Id": "test-group-role-request"},
		}, want: codes.Unavailable},
		{name: "unreadable error body", step: oktaRequestStep{
			method: http.MethodGet, path: path, statusCode: http.StatusServiceUnavailable, body: "Service unavailable",
		}, want: codes.Unavailable},
		// Compatibility coverage for a known gap, not the intended permission-error contract:
		// group-role enumeration currently treats AccessDenied as an empty result.
		// Changing that sync behavior is separate from preserving error classification.
		{name: "access denied retains empty result", step: oktaRequestStep{
			method: http.MethodGet, path: path, statusCode: http.StatusForbidden,
			body: `{"errorCode":"E0000006","errorSummary":"Permission denied"}`,
		}, want: codes.OK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newScriptedOktaClient(t, test.step)
			grants, _, err := groupBuilder(&Okta{client: client}).Grants(t.Context(),
				&v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeGroup.Id, Resource: testGroupID}},
				sdkResource.SyncOpAttrs{PageToken: pagination.Token{Token: token}})
			if status.Code(err) != test.want {
				t.Fatalf("Grants() status = %s, want %s: %v", status.Code(err), test.want, err)
			}
			if len(grants) != 0 {
				t.Fatalf("Grants() returned %d grants on failed role read", len(grants))
			}
			if test.name == "server failure" && !strings.Contains(err.Error(), "test-group-role-request") {
				t.Fatalf("Grants() lost request ID: %v", err)
			}
		})
	}
}

func TestRoleGrantUnreadableErrorBodyPreservesVendorError(t *testing.T) {
	client := newScriptedOktaClient(t, oktaRequestStep{
		method: http.MethodPost, path: "/api/v1/users/" + testOktaUserID + "/roles",
		statusCode: http.StatusServiceUnavailable, body: "Service unavailable",
	})
	_, err := roleBuilder(client, nil).Grant(t.Context(), testUserPrincipal(), roleAssignedEntitlement())
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("Grant() status = %s, want Unavailable: %v", status.Code(err), err)
	}
	var vendorErr *okta.Error
	if !errors.As(err, &vendorErr) {
		t.Fatalf("Grant() lost original Okta error after reading invalid error body: %v", err)
	}
}
