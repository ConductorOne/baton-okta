package connector

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
)

// roleTestHeaders carries the rate-limit headers the vendored SDK turns into a
// RateLimitDescription; without them the assertion would be vacuous (see
// TestAlreadyExistsRoutesReportRateLimit).
var roleTestHeaders = map[string]string{
	"X-Rate-Limit-Limit":     "250",
	"X-Rate-Limit-Remaining": "17",
	"X-Rate-Limit-Reset":     strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10),
}

// assertReportsRoleLimit checks that a Grant/Revoke result carries both the
// already-exists/already-revoked marker (when wanted) and a rate-limit descriptor,
// asserting the full annotation set rather than just err == nil.
func assertReportsRoleLimit(t *testing.T, annos annotations.Annotations, err error, wantRevoked bool) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if wantRevoked {
		if !annos.Contains(&v2.GrantAlreadyRevoked{}) {
			t.Fatalf("annotations = %v, want GrantAlreadyRevoked", annos)
		}
	} else if !annos.Contains(&v2.GrantAlreadyExists{}) {
		t.Fatalf("annotations = %v, want GrantAlreadyExists", annos)
	}

	desc := &v2.RateLimitDescription{}
	ok, pickErr := annos.Pick(desc)
	if pickErr != nil {
		t.Fatalf("Pick() error: %v", pickErr)
	}
	if !ok {
		t.Fatalf("annotations = %v, want a RateLimitDescription alongside it", annos)
	}
	if desc.GetLimit() != 250 || desc.GetRemaining() != 17 {
		t.Fatalf("rate limit = %d/%d, want 17/250", desc.GetRemaining(), desc.GetLimit())
	}
}

// assertRoleSuccess checks only the rate-limit descriptor for the plain success rows.
func assertRoleSuccess(t *testing.T, annos annotations.Annotations, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	desc := &v2.RateLimitDescription{}
	ok, pickErr := annos.Pick(desc)
	if pickErr != nil {
		t.Fatalf("Pick() error: %v", pickErr)
	}
	if !ok {
		t.Fatalf("annotations = %v, want a RateLimitDescription", annos)
	}
	if desc.GetLimit() != 250 || desc.GetRemaining() != 17 {
		t.Fatalf("rate limit = %d/%d, want 17/250", desc.GetRemaining(), desc.GetLimit())
	}
}

// TestRoleGrantGroupSuccess drives the group and user grant paths side by side: both
// must reach their SDK call and hand back what quota is left.
func TestRoleGrantGroupSuccess(t *testing.T) {
	t.Run("group principal: grant succeeds", func(t *testing.T) {
		client := newScriptedOktaClient(t, oktaRequestStep{
			method:     http.MethodPost,
			path:       "/api/v1/groups/" + testGroupID + "/roles",
			statusCode: http.StatusOK,
			headers:    roleTestHeaders,
			body:       `{"id":"` + testRoleType + `","status":"ACTIVE","label":"Super Administrator","type":"SUPER_ADMIN"}`,
		})

		annos, err := roleBuilder(client, nil).Grant(t.Context(), appGroupPrincipal(), roleAssignedEntitlement())
		assertRoleSuccess(t, annos, err)
	})

	t.Run("user principal: grant succeeds", func(t *testing.T) {
		client := newScriptedOktaClient(t, oktaRequestStep{
			method:     http.MethodPost,
			path:       "/api/v1/users/" + testOktaUserID + "/roles",
			statusCode: http.StatusOK,
			headers:    roleTestHeaders,
			body:       `{"id":"` + testRoleType + `","status":"ACTIVE","label":"Super Administrator","type":"SUPER_ADMIN"}`,
		})

		annos, err := roleBuilder(client, nil).Grant(t.Context(), testUserPrincipal(), roleAssignedEntitlement())
		assertRoleSuccess(t, annos, err)
	})
}

// TestRoleGrantGroupIdempotency pins the already-assigned no-op for both principal
// types: E0000090 must route to GrantAlreadyExists plus rate-limit annotations, never
// a wrapped error.
func TestRoleGrantGroupIdempotency(t *testing.T) {
	t.Run("group principal: already assigned is a no-op", func(t *testing.T) {
		client := newScriptedOktaClient(t, oktaRequestStep{
			method:     http.MethodPost,
			path:       "/api/v1/groups/" + testGroupID + "/roles",
			statusCode: http.StatusBadRequest,
			headers:    roleTestHeaders,
			body:       `{"errorCode":"E0000090","errorSummary":"You have specified a role that is already assigned to the group"}`,
		})

		annos, err := roleBuilder(client, nil).Grant(t.Context(), appGroupPrincipal(), roleAssignedEntitlement())
		assertReportsRoleLimit(t, annos, err, false)
	})

	t.Run("user principal: already assigned is a no-op", func(t *testing.T) {
		client := newScriptedOktaClient(t, oktaRequestStep{
			method:     http.MethodPost,
			path:       "/api/v1/users/" + testOktaUserID + "/roles",
			statusCode: http.StatusBadRequest,
			headers:    roleTestHeaders,
			body:       `{"errorCode":"E0000090","errorSummary":"You have specified a role that is already assigned to the user"}`,
		})

		annos, err := roleBuilder(client, nil).Grant(t.Context(), testUserPrincipal(), roleAssignedEntitlement())
		assertReportsRoleLimit(t, annos, err, false)
	})
}

// TestRoleRevokeGroupHeldRole covers revoking a role the principal actually holds:
// list finds the active match, the delete returns 204, and quota is reported.
func TestRoleRevokeGroupHeldRole(t *testing.T) {
	listBody := `[{"id":"` + testRoleType + `","status":"ACTIVE","type":"SUPER_ADMIN","label":"Super Administrator"}]`

	t.Run("group principal: revoke held role", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{
				method: http.MethodGet, path: "/api/v1/groups/" + testGroupID + "/roles",
				statusCode: http.StatusOK, headers: roleTestHeaders, body: listBody,
			},
			oktaRequestStep{
				method: http.MethodDelete, path: "/api/v1/groups/" + testGroupID + "/roles/" + testRoleType,
				statusCode: http.StatusNoContent, headers: roleTestHeaders,
			},
		)
		grant := &v2.Grant{Principal: appGroupPrincipal(), Entitlement: roleAssignedEntitlement()}

		annos, err := roleBuilder(client, nil).Revoke(t.Context(), grant)
		assertRoleSuccess(t, annos, err)
	})

	t.Run("user principal: revoke held role", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{
				method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID + "/roles",
				statusCode: http.StatusOK, headers: roleTestHeaders, body: listBody,
			},
			oktaRequestStep{
				method: http.MethodDelete, path: "/api/v1/users/" + testOktaUserID + "/roles/" + testRoleType,
				statusCode: http.StatusNoContent, headers: roleTestHeaders,
			},
		)
		grant := &v2.Grant{Principal: testUserPrincipal(), Entitlement: roleAssignedEntitlement()}

		annos, err := roleBuilder(client, nil).Revoke(t.Context(), grant)
		assertRoleSuccess(t, annos, err)
	})
}

// TestRoleRevokeGroupAlreadyRemoved pins the idempotent revoke: the list step is
// mandatory (the group branch always lists before deleting) and the 404 on the delete
// must route through revokeNotFoundOrError to GrantAlreadyRevoked plus quota, for both
// principal types.
func TestRoleRevokeGroupAlreadyRemoved(t *testing.T) {
	listBody := `[{"id":"` + testRoleType + `","status":"ACTIVE","type":"SUPER_ADMIN","label":"Super Administrator"}]`

	t.Run("group principal: already removed is a no-op", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{
				method: http.MethodGet, path: "/api/v1/groups/" + testGroupID + "/roles",
				statusCode: http.StatusOK, headers: roleTestHeaders, body: listBody,
			},
			oktaRequestStep{
				method: http.MethodDelete, path: "/api/v1/groups/" + testGroupID + "/roles/" + testRoleType,
				statusCode: http.StatusNotFound, headers: roleTestHeaders,
				body: `{"errorCode":"E0000007","errorSummary":"The requested resource was not found"}`,
			},
		)
		grant := &v2.Grant{Principal: appGroupPrincipal(), Entitlement: roleAssignedEntitlement()}

		annos, err := roleBuilder(client, nil).Revoke(t.Context(), grant)
		assertReportsRoleLimit(t, annos, err, true)
	})

	t.Run("user principal: already removed is a no-op", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{
				method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID + "/roles",
				statusCode: http.StatusOK, headers: roleTestHeaders, body: listBody,
			},
			oktaRequestStep{
				method: http.MethodDelete, path: "/api/v1/users/" + testOktaUserID + "/roles/" + testRoleType,
				statusCode: http.StatusNotFound, headers: roleTestHeaders,
				body: `{"errorCode":"E0000007","errorSummary":"The requested resource was not found"}`,
			},
		)
		grant := &v2.Grant{Principal: testUserPrincipal(), Entitlement: roleAssignedEntitlement()}

		annos, err := roleBuilder(client, nil).Revoke(t.Context(), grant)
		assertReportsRoleLimit(t, annos, err, true)
	})
}

// TestRoleGrantGuardRejectsOtherPrincipalTypes pins the widened guards: a principal
// that is neither user nor group still fails with the corrected texts. The guard fires
// before any client call, so no HTTP steps are needed.
func TestRoleGrantGuardRejectsOtherPrincipalTypes(t *testing.T) {
	appPrincipal := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeApp.Id, Resource: testAppID}}

	t.Run("grant rejects app principal", func(t *testing.T) {
		client := newScriptedOktaClient(t)

		_, err := roleBuilder(client, nil).Grant(t.Context(), appPrincipal, roleAssignedEntitlement())
		if err == nil {
			t.Fatalf("Grant() = nil error, want guard rejection")
		}
		if !strings.Contains(err.Error(), "only users or groups can be granted role membership") {
			t.Fatalf("Grant() error = %q, want corrected guard text", err.Error())
		}
	})

	t.Run("revoke rejects app principal", func(t *testing.T) {
		client := newScriptedOktaClient(t)
		grant := &v2.Grant{Principal: appPrincipal, Entitlement: roleAssignedEntitlement()}

		_, err := roleBuilder(client, nil).Revoke(t.Context(), grant)
		if err == nil {
			t.Fatalf("Revoke() = nil error, want guard rejection")
		}
		if !strings.Contains(err.Error(), "okta-connector: only users or groups can have role membership revoked") {
			t.Fatalf("Revoke() error = %q, want corrected guard text", err.Error())
		}
	})
}


// TestRoleRevokeNoActiveRoleMatch pins the fail-open short-circuit: when the list
// step finds no active matching role, both branches must return GrantAlreadyRevoked
// WITHOUT issuing a delete (the scripted client's cleanup assertion fails if the
// DELETE step is consumed) — the D5 fail-open surface.
func TestRoleRevokeNoActiveRoleMatch(t *testing.T) {
	t.Run("group principal: no active match revokes nothing", func(t *testing.T) {
		client := newScriptedOktaClient(t, oktaRequestStep{
			method: http.MethodGet, path: "/api/v1/groups/" + testGroupID + "/roles",
			statusCode: http.StatusOK, headers: roleTestHeaders, body: `[]`,
		})
		grant := &v2.Grant{Principal: appGroupPrincipal(), Entitlement: roleAssignedEntitlement()}

		annos, err := roleBuilder(client, nil).Revoke(t.Context(), grant)
		if err != nil {
			t.Fatalf("Revoke() error: %v", err)
		}
		if !annos.Contains(&v2.GrantAlreadyRevoked{}) {
			t.Fatalf("annotations = %v, want GrantAlreadyRevoked", annos)
		}
		// No delete step was scripted: newScriptedOktaClient's cleanup fails the
		// test if the branch issues an unexpected DELETE.
	})

	t.Run("user principal: no active match revokes nothing", func(t *testing.T) {
		client := newScriptedOktaClient(t, oktaRequestStep{
			method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID + "/roles",
			statusCode: http.StatusOK, headers: roleTestHeaders, body: `[]`,
		})
		grant := &v2.Grant{Principal: testUserPrincipal(), Entitlement: roleAssignedEntitlement()}

		annos, err := roleBuilder(client, nil).Revoke(t.Context(), grant)
		if err != nil {
			t.Fatalf("Revoke() error: %v", err)
		}
		if !annos.Contains(&v2.GrantAlreadyRevoked{}) {
			t.Fatalf("annotations = %v, want GrantAlreadyRevoked", annos)
		}
	})
}

// TestRoleRevokeServerErrorFailsClosed pins the fail-closed direction of the
// idempotency classification: a server error on the delete must stay a wrapped
// error, never degrade into GrantAlreadyRevoked.
func TestRoleRevokeServerErrorFailsClosed(t *testing.T) {
	listBody := `[{"id":"` + testRoleType + `","status":"ACTIVE","type":"SUPER_ADMIN","label":"Super Administrator"}]`

	t.Run("group principal: delete 500 is an error", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{
				method: http.MethodGet, path: "/api/v1/groups/" + testGroupID + "/roles",
				statusCode: http.StatusOK, headers: roleTestHeaders, body: listBody,
			},
			oktaRequestStep{
				method: http.MethodDelete, path: "/api/v1/groups/" + testGroupID + "/roles/" + testRoleType,
				statusCode: http.StatusInternalServerError, headers: roleTestHeaders,
				body:       `{"errorCode":"E0000001","errorSummary":"Internal Server Error"}`,
			},
		)
		grant := &v2.Grant{Principal: appGroupPrincipal(), Entitlement: roleAssignedEntitlement()}

		annos, err := roleBuilder(client, nil).Revoke(t.Context(), grant)
		if err == nil {
			t.Fatalf("Revoke() = nil error, want wrapped server error")
		}
		if annos.Contains(&v2.GrantAlreadyRevoked{}) {
			t.Fatalf("annotations = %v, must not report GrantAlreadyRevoked on a server error", annos)
		}
	})

	t.Run("user principal: delete 500 is an error", func(t *testing.T) {
		client := newScriptedOktaClient(t,
			oktaRequestStep{
				method: http.MethodGet, path: "/api/v1/users/" + testOktaUserID + "/roles",
				statusCode: http.StatusOK, headers: roleTestHeaders, body: listBody,
			},
			oktaRequestStep{
				method: http.MethodDelete, path: "/api/v1/users/" + testOktaUserID + "/roles/" + testRoleType,
				statusCode: http.StatusInternalServerError, headers: roleTestHeaders,
				body:       `{"errorCode":"E0000001","errorSummary":"Internal Server Error"}`,
			},
		)
		grant := &v2.Grant{Principal: testUserPrincipal(), Entitlement: roleAssignedEntitlement()}

		annos, err := roleBuilder(client, nil).Revoke(t.Context(), grant)
		if err == nil {
			t.Fatalf("Revoke() = nil error, want wrapped server error")
		}
		if annos.Contains(&v2.GrantAlreadyRevoked{}) {
			t.Fatalf("annotations = %v, must not report GrantAlreadyRevoked on a server error", annos)
		}
	})
}
