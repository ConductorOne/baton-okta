package connector

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	sdkActions "github.com/conductorone/baton-sdk/pkg/actions"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const testOktaUserID = "00u1abc2def3GHI4jk5"

type oktaRequestStep struct {
	method     string
	path       string
	query      map[string]string
	statusCode int
	body       string
	// headers are written before the body; use Link with rel="next" to make the
	// Okta SDK report a next page.
	headers map[string]string
}

func newScriptedOktaClient(t *testing.T, steps ...oktaRequestStep) *okta.Client {
	t.Helper()

	var mu sync.Mutex
	next := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		if next >= len(steps) {
			t.Errorf("unexpected Okta request: %s %s", r.Method, r.URL.RequestURI())
			writeOktaTestResponse(w, http.StatusInternalServerError, "")
			return
		}

		step := steps[next]
		next++
		if r.Method != step.method {
			t.Errorf("request %d method = %s, want %s", next, r.Method, step.method)
		}
		if r.URL.Path != step.path {
			t.Errorf("request %d path = %s, want %s", next, r.URL.Path, step.path)
		}
		for key, want := range step.query {
			if got := r.URL.Query().Get(key); got != want {
				t.Errorf("request %d query %s = %q, want %q", next, key, got, want)
			}
		}
		for k, v := range step.headers {
			w.Header().Set(k, v)
		}
		writeOktaTestResponse(w, step.statusCode, step.body)
	}))
	t.Cleanup(func() {
		server.Close()
		mu.Lock()
		defer mu.Unlock()
		if next != len(steps) {
			t.Errorf("received %d Okta requests, want %d", next, len(steps))
		}
	})

	_, client, err := okta.NewClient(
		context.Background(),
		okta.WithOrgUrl(server.URL),
		okta.WithToken("test-token"),
		okta.WithHttpClientPtr(server.Client()),
		okta.WithTestingDisableHttpsCheck(true),
		okta.WithRateLimitMaxRetries(0),
	)
	if err != nil {
		t.Fatalf("create Okta test client: %v", err)
	}
	return client
}

func writeOktaTestResponse(w http.ResponseWriter, statusCode int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if body != "" {
		_, _ = w.Write([]byte(body))
	}
}

func oktaUserResponse(status string) string {
	return fmt.Sprintf(`{"id":%q,"status":%q,"profile":{"login":"test@example.com"}}`, testOktaUserID, status)
}

func oktaNotFoundResponse() string {
	return `{"errorCode":"E0000007","errorSummary":"Not found: Resource not found","errorLink":"E0000007","errorId":"test","errorCauses":[]}`
}

func oktaLifecycleErrorResponse() string {
	return `{"errorCode":"E0000001","errorSummary":"Api validation failed","errorLink":"E0000001","errorId":"test","errorCauses":[]}`
}

func userResourceID() *v2.ResourceId {
	return &v2.ResourceId{ResourceType: userResourceTypeID, Resource: testOktaUserID}
}

func userActionArgs(t *testing.T) *structpb.Struct {
	t.Helper()
	args, err := structpb.NewStruct(map[string]any{
		"user_id": map[string]any{
			"resource_type_id": userResourceTypeID,
			"resource_id":      testOktaUserID,
		},
	})
	if err != nil {
		t.Fatalf("build action args: %v", err)
	}
	return args
}

func TestUserResourceDelete(t *testing.T) {
	t.Run("active user is deactivated then deleted", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaUserResponse(userStatusActive)},
			oktaRequestStep{method: http.MethodPost, path: "/api/v1/users/" + testOktaUserID + "/lifecycle/deactivate", query: map[string]string{"sendEmail": "false"}, statusCode: http.StatusOK},
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaUserResponse(userStatusDeprovisioned)},
			oktaRequestStep{method: http.MethodDelete, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusNoContent},
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusNotFound, body: oktaNotFoundResponse()},
		)

		builder := userBuilder(&Okta{client: client})
		if _, err := builder.Delete(t.Context(), userResourceID(), nil); err != nil {
			t.Fatalf("Delete() error: %v", err)
		}
	})

	t.Run("asynchronous deactivation is confirmed before delete", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaUserResponse(userStatusActive)},
			oktaRequestStep{method: http.MethodPost, path: "/api/v1/users/" + testOktaUserID + "/lifecycle/deactivate", query: map[string]string{"sendEmail": "false"}, statusCode: http.StatusOK},
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaUserResponse(userStatusActive)},
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaUserResponse(userStatusDeprovisioned)},
			oktaRequestStep{method: http.MethodDelete, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusNoContent},
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusNotFound, body: oktaNotFoundResponse()},
		)

		builder := userBuilder(&Okta{client: client})
		if _, err := builder.Delete(t.Context(), userResourceID(), nil); err != nil {
			t.Fatalf("Delete() error: %v", err)
		}
	})

	t.Run("deprovisioned user skips deactivate", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaUserResponse(userStatusDeprovisioned)},
			oktaRequestStep{method: http.MethodDelete, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusNoContent},
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusNotFound, body: oktaNotFoundResponse()},
		)

		builder := userBuilder(&Okta{client: client})
		if _, err := builder.Delete(t.Context(), userResourceID(), nil); err != nil {
			t.Fatalf("Delete() error: %v", err)
		}
	})

	t.Run("first delete that only deactivates is followed by a second delete", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaUserResponse(userStatusDeprovisioned)},
			oktaRequestStep{method: http.MethodDelete, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusNoContent},
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaUserResponse(userStatusDeprovisioned)},
			oktaRequestStep{method: http.MethodDelete, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusNoContent},
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusNotFound, body: oktaNotFoundResponse()},
		)

		builder := userBuilder(&Okta{client: client})
		if _, err := builder.Delete(t.Context(), userResourceID(), nil); err != nil {
			t.Fatalf("Delete() error: %v", err)
		}
	})

	t.Run("two deletes without absence return a retryable error", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaUserResponse(userStatusDeprovisioned)},
			oktaRequestStep{method: http.MethodDelete, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusNoContent},
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaUserResponse(userStatusDeprovisioned)},
			oktaRequestStep{method: http.MethodDelete, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusNoContent},
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaUserResponse(userStatusDeprovisioned)},
		)

		builder := userBuilder(&Okta{client: client})
		_, err := builder.Delete(t.Context(), userResourceID(), nil)
		if status.Code(err) != codes.Unavailable {
			t.Fatalf("Delete() status = %s, want %s (error: %v)", status.Code(err), codes.Unavailable, err)
		}
	})

	t.Run("post-delete verification catches a lifecycle race", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaUserResponse(userStatusDeprovisioned)},
			oktaRequestStep{method: http.MethodDelete, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusNoContent},
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaUserResponse(userStatusActive)},
		)

		builder := userBuilder(&Okta{client: client})
		_, err := builder.Delete(t.Context(), userResourceID(), nil)
		if status.Code(err) != codes.Unavailable {
			t.Fatalf("Delete() status = %s, want %s (error: %v)", status.Code(err), codes.Unavailable, err)
		}
	})

	t.Run("stale cached status is bypassed", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaUserResponse(userStatusDeprovisioned)},
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaUserResponse(userStatusActive)},
			oktaRequestStep{method: http.MethodPost, path: "/api/v1/users/" + testOktaUserID + "/lifecycle/deactivate", query: map[string]string{"sendEmail": "false"}, statusCode: http.StatusOK},
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaUserResponse(userStatusDeprovisioned)},
			oktaRequestStep{method: http.MethodDelete, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusNoContent},
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusNotFound, body: oktaNotFoundResponse()},
		)

		if got, err := getUserStatus(t.Context(), client, testOktaUserID); err != nil || got != userStatusDeprovisioned {
			t.Fatalf("prime cached user status = %q, %v; want %q, nil", got, err, userStatusDeprovisioned)
		}

		builder := userBuilder(&Okta{client: client})
		if _, err := builder.Delete(t.Context(), userResourceID(), nil); err != nil {
			t.Fatalf("Delete() error: %v", err)
		}
	})

	t.Run("missing user is an idempotent success", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusNotFound, body: oktaNotFoundResponse()},
		)

		builder := userBuilder(&Okta{client: client})
		if _, err := builder.Delete(t.Context(), userResourceID(), nil); err != nil {
			t.Fatalf("Delete() error: %v", err)
		}
	})

	t.Run("concurrent deactivation is reconciled", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaUserResponse(userStatusActive)},
			oktaRequestStep{
				method:     http.MethodPost,
				path:       "/api/v1/users/" + testOktaUserID + "/lifecycle/deactivate",
				query:      map[string]string{"sendEmail": "false"},
				statusCode: http.StatusBadRequest,
				body:       oktaLifecycleErrorResponse(),
			},
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaUserResponse(userStatusDeprovisioned)},
			oktaRequestStep{method: http.MethodDelete, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusNoContent},
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusNotFound, body: oktaNotFoundResponse()},
		)

		builder := userBuilder(&Okta{client: client})
		if _, err := builder.Delete(t.Context(), userResourceID(), nil); err != nil {
			t.Fatalf("Delete() error: %v", err)
		}
	})

	t.Run("concurrent deletion is an idempotent success", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaUserResponse(userStatusDeprovisioned)},
			oktaRequestStep{method: http.MethodDelete, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusNotFound, body: oktaNotFoundResponse()},
		)

		builder := userBuilder(&Okta{client: client})
		if _, err := builder.Delete(t.Context(), userResourceID(), nil); err != nil {
			t.Fatalf("Delete() error: %v", err)
		}
	})
}

func TestEnsureUserDeactivatedPreservesMutationError(t *testing.T) {
	t.Run("reconcile sees a non-deprovisioned status", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaUserResponse(userStatusActive)},
			oktaRequestStep{
				method:     http.MethodPost,
				path:       "/api/v1/users/" + testOktaUserID + "/lifecycle/deactivate",
				query:      map[string]string{"sendEmail": "false"},
				statusCode: http.StatusBadRequest,
				body:       oktaLifecycleErrorResponse(),
			},
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaUserResponse(userStatusActive)},
		)

		changed, missing, err := ensureUserDeactivated(t.Context(), client, testOktaUserID)
		if err == nil || changed || missing {
			t.Fatalf("ensureUserDeactivated() = changed %t, missing %t, error %v; want false, false, mutation error", changed, missing, err)
		}
		if !strings.Contains(err.Error(), "failed to deactivate user") {
			t.Fatalf("ensureUserDeactivated() error = %v, want original deactivate error", err)
		}
	})

	t.Run("reconcile read fails", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaUserResponse(userStatusActive)},
			oktaRequestStep{
				method:     http.MethodPost,
				path:       "/api/v1/users/" + testOktaUserID + "/lifecycle/deactivate",
				query:      map[string]string{"sendEmail": "false"},
				statusCode: http.StatusBadRequest,
				body:       oktaLifecycleErrorResponse(),
			},
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusInternalServerError, body: oktaLifecycleErrorResponse()},
		)

		changed, missing, err := ensureUserDeactivated(t.Context(), client, testOktaUserID)
		if err == nil || changed || missing {
			t.Fatalf("ensureUserDeactivated() = changed %t, missing %t, error %v; want false, false, mutation error", changed, missing, err)
		}
		if status.Code(err) == codes.Unavailable || !strings.Contains(err.Error(), "failed to deactivate user") {
			t.Fatalf("ensureUserDeactivated() error = %v, want original deactivate error rather than reconcile error", err)
		}
	})
}

func TestUserResourceDeleteRejectsInvalidIDs(t *testing.T) {
	builder := userBuilder(&Okta{})
	tests := []struct {
		name       string
		resourceID *v2.ResourceId
	}{
		{name: "nil"},
		{name: "wrong resource type", resourceID: &v2.ResourceId{ResourceType: "group", Resource: testOktaUserID}},
		{name: "empty user ID", resourceID: &v2.ResourceId{ResourceType: userResourceTypeID}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := builder.Delete(t.Context(), tt.resourceID, nil)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("Delete() status = %s, want %s (error: %v)", status.Code(err), codes.InvalidArgument, err)
			}
		})
	}
}

func TestUserDeprovisioningActions(t *testing.T) {
	t.Run("deactivate active user", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaUserResponse(userStatusActive)},
			oktaRequestStep{method: http.MethodPost, path: "/api/v1/users/" + testOktaUserID + "/lifecycle/deactivate", query: map[string]string{"sendEmail": "false"}, statusCode: http.StatusOK},
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaUserResponse(userStatusDeprovisioned)},
		)

		result, _, err := userBuilder(&Okta{client: client}).deactivateUserAction(t.Context(), userActionArgs(t))
		assertSuccessfulActionResult(t, result, err, "successfully deactivated")
	})

	t.Run("deactivate already-deprovisioned user", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaUserResponse(userStatusDeprovisioned)},
		)

		result, _, err := userBuilder(&Okta{client: client}).deactivateUserAction(t.Context(), userActionArgs(t))
		assertSuccessfulActionResult(t, result, err, "already deactivated")
	})

	t.Run("deactivate missing user returns not found", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusNotFound, body: oktaNotFoundResponse()},
		)

		_, _, err := userBuilder(&Okta{client: client}).deactivateUserAction(t.Context(), userActionArgs(t))
		if status.Code(err) != codes.NotFound {
			t.Fatalf("deactivateUserAction status = %s, want %s (error: %v)", status.Code(err), codes.NotFound, err)
		}
	})

	t.Run("delete active user", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaUserResponse(userStatusActive)},
			oktaRequestStep{method: http.MethodPost, path: "/api/v1/users/" + testOktaUserID + "/lifecycle/deactivate", query: map[string]string{"sendEmail": "false"}, statusCode: http.StatusOK},
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusOK, body: oktaUserResponse(userStatusDeprovisioned)},
			oktaRequestStep{method: http.MethodDelete, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusNoContent},
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusNotFound, body: oktaNotFoundResponse()},
		)

		result, _, err := userBuilder(&Okta{client: client}).deleteUserAction(t.Context(), userActionArgs(t))
		assertSuccessfulActionResult(t, result, err, "permanently deleted")
	})

	t.Run("delete missing user is idempotent", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID, statusCode: http.StatusNotFound, body: oktaNotFoundResponse()},
		)

		result, _, err := userBuilder(&Okta{client: client}).deleteUserAction(t.Context(), userActionArgs(t))
		assertSuccessfulActionResult(t, result, err, "already deleted")
	})
}

func TestUserDeprovisioningActionSchemas(t *testing.T) {
	manager := sdkActions.NewActionManager(t.Context())
	registry, err := manager.GetTypeRegistry(t.Context(), userResourceTypeID)
	if err != nil {
		t.Fatalf("GetTypeRegistry() error: %v", err)
	}
	if err := userBuilder(&Okta{}).ResourceActions(t.Context(), registry); err != nil {
		t.Fatalf("ResourceActions() error: %v", err)
	}

	schemas, _, err := manager.ListActionSchemas(t.Context(), userResourceTypeID)
	if err != nil {
		t.Fatalf("ListActionSchemas() error: %v", err)
	}

	wantSchemaNames := map[string]bool{
		deactivateUserActionSchema.GetName(): true,
		deleteUserActionSchema.GetName():     true,
		updateUserProfileSchema.GetName():    true,
	}
	if len(schemas) != len(wantSchemaNames) {
		t.Fatalf("user action schema count = %d, want %d (names: %v)", len(schemas), len(wantSchemaNames), wantSchemaNames)
	}
	for _, schema := range schemas {
		if !wantSchemaNames[schema.GetName()] {
			t.Errorf("unexpected user action schema %q", schema.GetName())
		}
	}

	// This test is scoped to the deprovisioning actions (deactivate_user,
	// delete_user); other resource-scoped actions on the user resource type
	// (e.g. update_profile) have a different shape and are covered by their
	// own tests, so they're skipped here rather than asserted against.
	wantActionTypes := map[string]v2.ActionType{
		deactivateUserActionSchema.GetName(): v2.ActionType_ACTION_TYPE_RESOURCE_DISABLE,
		deleteUserActionSchema.GetName():     v2.ActionType_ACTION_TYPE_RESOURCE_DELETE,
	}
	for _, schema := range schemas {
		name := schema.GetName()
		wantActionType, ok := wantActionTypes[name]
		if !ok {
			continue
		}
		delete(wantActionTypes, name)

		if schema.GetDisplayName() == "" || schema.GetDescription() == "" {
			t.Errorf("schema %q must have a display name and description", name)
		}
		if schema.GetResourceTypeId() != userResourceTypeID {
			t.Errorf("schema %q resource type = %q, want %q", name, schema.GetResourceTypeId(), userResourceTypeID)
		}
		if !slices.Equal(schema.GetActionType(), []v2.ActionType{wantActionType}) {
			t.Errorf("schema %q action types = %v, want %v", name, schema.GetActionType(), wantActionType)
		}
		if len(schema.GetArguments()) != 1 {
			t.Fatalf("schema %q arguments = %d, want 1", name, len(schema.GetArguments()))
		}
		argument := schema.GetArguments()[0]
		if argument.GetName() != "user_id" || !argument.GetIsRequired() {
			t.Errorf("schema %q user argument = %#v, want required user_id", name, argument)
		}
		resourceField := argument.GetResourceIdField()
		if resourceField == nil || resourceField.GetRules() == nil || !slices.Equal(resourceField.GetRules().GetAllowedResourceTypeIds(), []string{userResourceTypeID}) {
			t.Errorf("schema %q user_id must be a user ResourceIdField", name)
		}
		if len(schema.GetReturnTypes()) != 2 || schema.GetReturnTypes()[0].GetName() != actionResultSuccess || schema.GetReturnTypes()[1].GetName() != "message" {
			t.Errorf("schema %q return types = %v, want success and message", name, schema.GetReturnTypes())
		}
	}
	if len(wantActionTypes) != 0 {
		t.Errorf("missing user action schemas: %v", wantActionTypes)
	}
}

func TestUserDeprovisioningActionRejectsInvalidResource(t *testing.T) {
	args, err := structpb.NewStruct(map[string]any{
		"user_id": map[string]any{
			"resource_type_id": "group",
			"resource_id":      testOktaUserID,
		},
	})
	if err != nil {
		t.Fatalf("build action args: %v", err)
	}

	_, _, err = userBuilder(&Okta{}).deleteUserAction(t.Context(), args)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("deleteUserAction status = %s, want %s (error: %v)", status.Code(err), codes.InvalidArgument, err)
	}
}

func assertSuccessfulActionResult(t *testing.T, result *structpb.Struct, err error, messageContains string) {
	t.Helper()
	if err != nil {
		t.Fatalf("action error: %v", err)
	}
	if result == nil || !result.GetFields()[actionResultSuccess].GetBoolValue() {
		t.Fatalf("action result = %v, want success", result)
	}
	message := result.GetFields()["message"].GetStringValue()
	if !strings.Contains(message, messageContains) {
		t.Errorf("action message = %q, want substring %q", message, messageContains)
	}
}
