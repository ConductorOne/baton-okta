package connector

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const testGroupRoleType = "USER_ADMIN"

func groupRoleAssignedEntitlement() *v2.Entitlement {
	return &v2.Entitlement{
		Resource: &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeRole.Id, Resource: testGroupRoleType}},
		Slug:     "assigned",
	}
}

func groupRoleRateLimitHeaders() map[string]string {
	return map[string]string{
		"X-Rate-Limit-Limit":     "250",
		"X-Rate-Limit-Remaining": "17",
		"X-Rate-Limit-Reset":     strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10),
	}
}

func assertGroupRoleRateLimit(t *testing.T, annos annotations.Annotations) {
	t.Helper()
	desc := &v2.RateLimitDescription{}
	found, err := annos.Pick(desc)
	if err != nil || !found {
		t.Fatalf("rate-limit annotation missing: found=%v error=%v", found, err)
	}
	if desc.GetLimit() != 250 || desc.GetRemaining() != 17 {
		t.Fatalf("rate limit = %d/%d, want 17/250", desc.GetRemaining(), desc.GetLimit())
	}
}

func TestStandardRoleGroupGrant(t *testing.T) {
	path := "/api/v1/groups/" + testGroupID + "/roles"
	for _, tc := range []struct {
		name          string
		step          oktaRequestStep
		wantCode      codes.Code
		alreadyExists bool
	}{
		{
			name: "assigns the requested role",
			step: oktaRequestStep{statusCode: http.StatusOK, body: `{"id":"group-role-assignment","type":"USER_ADMIN","status":"ACTIVE"}`},
		},
		{
			name:          "already assigned is successful",
			step:          oktaRequestStep{statusCode: http.StatusBadRequest, body: `{"errorCode":"E0000090","errorSummary":"You have specified a role that is already assigned to the group"}`},
			alreadyExists: true,
		},
		{
			name:     "permission denied remains an error",
			step:     oktaRequestStep{statusCode: http.StatusForbidden, body: `{"errorCode":"E0000006","errorSummary":"You do not have permission to perform the requested action"}`},
			wantCode: codes.PermissionDenied,
		},
		{
			name:     "invalid credentials remain an error",
			step:     oktaRequestStep{statusCode: http.StatusUnauthorized, body: `{"errorCode":"E0000011","errorSummary":"Invalid token provided"}`},
			wantCode: codes.Unauthenticated,
		},
		{
			name:     "exhausted rate limit is retryable",
			step:     rateLimitedStep(http.MethodPost, path),
			wantCode: codes.Unavailable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			step := tc.step
			step.method = http.MethodPost
			step.path = path
			if step.headers == nil {
				step.headers = groupRoleRateLimitHeaders()
			}
			step.checkRequest = func(r *http.Request) {
				var body struct {
					Type string `json:"type"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("decode role assignment: %v", err)
				}
				if body.Type != testGroupRoleType {
					t.Errorf("assigned role type = %q, want %q", body.Type, testGroupRoleType)
				}
			}
			client := newScriptedOktaClient(t, step)
			annos, err := roleBuilder(client, nil).Grant(t.Context(), appGroupPrincipal(), groupRoleAssignedEntitlement())
			if status.Code(err) != tc.wantCode {
				t.Fatalf("Grant() status = %s, want %s (error: %v)", status.Code(err), tc.wantCode, err)
			}
			if tc.wantCode != codes.OK {
				return
			}
			if got := annos.Contains(&v2.GrantAlreadyExists{}); got != tc.alreadyExists {
				t.Errorf("GrantAlreadyExists = %v, want %v", got, tc.alreadyExists)
			}
			assertGroupRoleRateLimit(t, annos)
		})
	}
}

func TestStandardRoleGroupRevoke(t *testing.T) {
	rolesPath := "/api/v1/groups/" + testGroupID + "/roles"
	assignmentPath := rolesPath + "/group-role-assignment"
	roles := `[{"id":"different-role","type":"READ_ONLY_ADMIN","status":"ACTIVE"},` +
		`{"id":"inactive-role","type":"USER_ADMIN","status":"INACTIVE"},` +
		`{"id":"group-role-assignment","type":"USER_ADMIN","status":"ACTIVE"}]`
	listStep := oktaRequestStep{method: http.MethodGet, path: rolesPath, statusCode: http.StatusOK, body: roles}
	for _, tc := range []struct {
		name           string
		steps          []oktaRequestStep
		wantCode       codes.Code
		alreadyRevoked bool
	}{
		{
			name: "removes the matching active assignment",
			steps: []oktaRequestStep{
				listStep,
				{method: http.MethodDelete, path: assignmentPath, statusCode: http.StatusNoContent},
			},
		},
		{
			name:           "no assignments is already revoked",
			steps:          []oktaRequestStep{{method: http.MethodGet, path: rolesPath, statusCode: http.StatusOK, body: `[]`}},
			alreadyRevoked: true,
		},
		{
			name: "unrelated and inactive assignments are not removed",
			steps: []oktaRequestStep{{
				method:     http.MethodGet,
				path:       rolesPath,
				statusCode: http.StatusOK,
				body:       `[{"id":"different-role","type":"READ_ONLY_ADMIN","status":"ACTIVE"},{"id":"inactive-role","type":"USER_ADMIN","status":"INACTIVE"}]`,
			}},
			alreadyRevoked: true,
		},
		{
			name:           "missing group is already revoked",
			steps:          []oktaRequestStep{{method: http.MethodGet, path: rolesPath, statusCode: http.StatusNotFound, body: oktaNotFoundResponse()}},
			alreadyRevoked: true,
		},
		{
			name: "assignment removed after lookup is already revoked",
			steps: []oktaRequestStep{
				listStep,
				{method: http.MethodDelete, path: assignmentPath, statusCode: http.StatusNotFound, body: oktaNotFoundResponse()},
			},
			alreadyRevoked: true,
		},
		{
			name: "lookup permission denied remains an error",
			steps: []oktaRequestStep{{
				method:     http.MethodGet,
				path:       rolesPath,
				statusCode: http.StatusForbidden,
				body:       `{"errorCode":"E0000006","errorSummary":"You do not have permission to perform the requested action"}`,
			}},
			wantCode: codes.PermissionDenied,
		},
		{
			name: "delete permission denied remains an error",
			steps: []oktaRequestStep{
				listStep,
				{
					method:     http.MethodDelete,
					path:       assignmentPath,
					statusCode: http.StatusForbidden,
					body:       `{"errorCode":"E0000006","errorSummary":"You do not have permission to perform the requested action"}`,
				},
			},
			wantCode: codes.PermissionDenied,
		},
		{
			name:     "lookup rate limit is retryable",
			steps:    []oktaRequestStep{rateLimitedStep(http.MethodGet, rolesPath)},
			wantCode: codes.Unavailable,
		},
		{
			name:     "delete rate limit is retryable",
			steps:    []oktaRequestStep{listStep, rateLimitedStep(http.MethodDelete, assignmentPath)},
			wantCode: codes.Unavailable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			steps := append([]oktaRequestStep(nil), tc.steps...)
			for i := range steps {
				if steps[i].headers == nil {
					steps[i].headers = groupRoleRateLimitHeaders()
				}
			}
			client := newScriptedOktaClient(t, steps...)
			grant := &v2.Grant{Principal: appGroupPrincipal(), Entitlement: groupRoleAssignedEntitlement()}
			annos, err := roleBuilder(client, nil).Revoke(t.Context(), grant)
			if status.Code(err) != tc.wantCode {
				t.Fatalf("Revoke() status = %s, want %s (error: %v)", status.Code(err), tc.wantCode, err)
			}
			if tc.wantCode != codes.OK {
				return
			}
			if got := annos.Contains(&v2.GrantAlreadyRevoked{}); got != tc.alreadyRevoked {
				t.Errorf("GrantAlreadyRevoked = %v, want %v", got, tc.alreadyRevoked)
			}
			assertGroupRoleRateLimit(t, annos)
		})
	}
}

func TestStandardRoleRejectsUnsupportedPrincipal(t *testing.T) {
	for _, operation := range []string{"grant", "revoke"} {
		t.Run(operation, func(t *testing.T) {
			client := newScriptedOktaClient(t)
			builder := roleBuilder(client, nil)
			principal := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeApp.Id, Resource: "unsupported-principal"}}
			var err error
			if operation == "grant" {
				_, err = builder.Grant(t.Context(), principal, roleAssignedEntitlement())
			} else {
				_, err = builder.Revoke(t.Context(), &v2.Grant{Principal: principal, Entitlement: roleAssignedEntitlement()})
			}
			if err == nil {
				t.Fatal("unsupported principal unexpectedly accepted")
			}
		})
	}
}
