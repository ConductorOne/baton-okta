package connector_test

// Black-box regression tests for actions, account lifecycle, events,
// connector-level operations (Validate, GetMetadata) and transport behavior
// (429 retries, response cache, error classification, auth modes).
//
// Every helper in this file is prefixed "ops" so it cannot collide with the
// helpers other black-box test files define in this package.

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	cfg "github.com/conductorone/baton-okta/pkg/config"
)

// ---------------------------------------------------------------------------
// Fake org: a stateful user store
// ---------------------------------------------------------------------------

const opsOktaNotFound = `{"errorCode":"E0000007","errorSummary":"Not found: Resource not found: %s (User)","errorLink":"E0000007","errorId":"oaeOpsNotFound","errorCauses":[]}`

func opsUserJSON(id, status, login string) string {
	return fmt.Sprintf(`{
  "id": %q,
  "status": %q,
  "created": "2024-01-02T03:04:05.000Z",
  "activated": "2024-01-02T03:04:06.000Z",
  "statusChanged": "2024-02-02T03:04:05.000Z",
  "lastLogin": null,
  "lastUpdated": "2024-02-02T03:04:05.000Z",
  "passwordChanged": null,
  "type": {"id": "otyops00000000001"},
  "profile": {"firstName": "Ops", "lastName": "User", "email": %q, "login": %q},
  "credentials": {"provider": {"type": "OKTA", "name": "OKTA"}},
  "_links": {"self": {"href": "https://example.okta.com/api/v1/users/%s"}}
}`, id, status, login, login, id)
}

// opsOrg is a tiny stateful Okta user directory: GET reports the current
// status, lifecycle POSTs move it, DELETE deactivates a live user and removes
// a DEPROVISIONED one (Okta's two-step delete).
type opsOrg struct {
	mu    sync.Mutex
	users map[string]string
}

func newOpsOrg(f *fakeOkta, users map[string]string) *opsOrg {
	o := &opsOrg{users: users}
	f.Handle(http.MethodGet, `/api/v1/users/([^/]+)`, func(w http.ResponseWriter, r *http.Request, m []string) {
		o.mu.Lock()
		st, ok := o.users[m[1]]
		o.mu.Unlock()
		if !ok {
			writeJSON(w, http.StatusNotFound, fmt.Sprintf(opsOktaNotFound, m[1]))
			return
		}
		writeJSON(w, http.StatusOK, opsUserJSON(m[1], st, m[1]+"@example.com"))
	})
	f.Handle(http.MethodPost, `/api/v1/users/([^/]+)/lifecycle/([a-z]+)`, func(w http.ResponseWriter, r *http.Request, m []string) {
		o.mu.Lock()
		defer o.mu.Unlock()
		if _, ok := o.users[m[1]]; !ok {
			writeJSON(w, http.StatusNotFound, fmt.Sprintf(opsOktaNotFound, m[1]))
			return
		}
		switch m[2] {
		case "deactivate":
			o.users[m[1]] = "DEPROVISIONED"
		case "activate":
			o.users[m[1]] = "ACTIVE"
			writeJSON(w, http.StatusOK, `{"activationUrl":"https://example.okta.com/welcome/token"}`)
			return
		case "suspend":
			o.users[m[1]] = "SUSPENDED"
		case "unsuspend":
			o.users[m[1]] = "ACTIVE"
		}
		writeJSON(w, http.StatusOK, `{}`)
	})
	f.Handle(http.MethodDelete, `/api/v1/users/([^/]+)`, func(w http.ResponseWriter, r *http.Request, m []string) {
		o.mu.Lock()
		defer o.mu.Unlock()
		st, ok := o.users[m[1]]
		if !ok {
			writeJSON(w, http.StatusNotFound, fmt.Sprintf(opsOktaNotFound, m[1]))
			return
		}
		if st == "DEPROVISIONED" {
			delete(o.users, m[1])
		} else {
			o.users[m[1]] = "DEPROVISIONED"
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return o
}

// ---------------------------------------------------------------------------
// Connector call helpers
// ---------------------------------------------------------------------------

func opsRID(rt, id string) map[string]any {
	return map[string]any{"resource_type_id": rt, "resource_id": id}
}

// opsInvoke invokes an action synchronously and records the outcome. The
// action invocation id is a random UUID and is cleared.
func opsInvoke(t *testing.T, g *golden, srv types.ConnectorServer, step, name, resourceType string, args map[string]any) *v2.InvokeActionResponse {
	t.Helper()
	s, err := structpb.NewStruct(args)
	require.NoError(t, err)
	resp, err := srv.InvokeAction(context.Background(), &v2.InvokeActionRequest{
		Name:           name,
		Args:           s,
		ResourceTypeId: resourceType,
		InlineWait:     durationpb.New(20 * time.Second),
	})
	if resp != nil {
		resp = proto.Clone(resp).(*v2.InvokeActionResponse)
		resp.Id = ""
	}
	g.Step(step, stripSessionUsage(resp), err)
	return resp
}

// opsListSchemas records the action schemas for a resource type, sorted by name:
// the SDK lists them in Go map order.
func opsListSchemas(t *testing.T, g *golden, srv types.ConnectorServer, step, resourceType string) {
	t.Helper()
	resp, err := srv.ListActionSchemas(context.Background(), &v2.ListActionSchemasRequest{ResourceTypeId: resourceType})
	if resp != nil {
		resp = proto.Clone(resp).(*v2.ListActionSchemasResponse)
		sort.Slice(resp.Schemas, func(i, j int) bool { return resp.Schemas[i].GetName() < resp.Schemas[j].GetName() })
	}
	g.Step(step, stripSessionUsage(resp), err)
}

func opsNoPassword() *v2.CredentialOptions {
	return &v2.CredentialOptions{Options: &v2.CredentialOptions_NoPassword_{NoPassword: &v2.CredentialOptions_NoPassword{}}}
}

func opsRandomPassword(length int64) *v2.CredentialOptions {
	return &v2.CredentialOptions{Options: &v2.CredentialOptions_RandomPassword_{RandomPassword: &v2.CredentialOptions_RandomPassword{Length: length}}}
}

func opsCreateAccount(t *testing.T, g *golden, srv types.ConnectorServer, step string, profile map[string]any, cred *v2.CredentialOptions) *v2.CreateAccountResponse {
	t.Helper()
	p, err := structpb.NewStruct(profile)
	require.NoError(t, err)
	resp, err := srv.CreateAccount(context.Background(), &v2.CreateAccountRequest{
		AccountInfo:       &v2.AccountInfo{Profile: p},
		CredentialOptions: cred,
		ResourceTypeId:    "user",
	})
	g.Step(step, stripSessionUsage(resp), err)
	return resp
}

func opsDelete(t *testing.T, g *golden, srv types.ConnectorServer, step, rt, id string) {
	t.Helper()
	resp, err := srv.DeleteResourceV2(context.Background(), &v2.DeleteResourceV2Request{
		ResourceId: &v2.ResourceId{ResourceType: rt, Resource: id},
	})
	g.Step(step, stripSessionUsage(resp), err)
}

func opsGetUser(t *testing.T, g *golden, srv types.ConnectorServer, step, id string) {
	t.Helper()
	resp, err := srv.GetResource(context.Background(), &v2.ResourceGetterServiceGetResourceRequest{
		ResourceId:   &v2.ResourceId{ResourceType: "user", Resource: id},
		ActiveSyncId: testSyncID,
	})
	g.Step(step, stripSessionUsage(resp), err)
}

func opsValidate(t *testing.T, g *golden, srv types.ConnectorServer, step string) {
	t.Helper()
	resp, err := srv.Validate(context.Background(), &v2.ConnectorServiceValidateRequest{})
	if resp != nil {
		resp = proto.Clone(resp).(*v2.ConnectorServiceValidateResponse)
		resp.SdkVersion = ""
	}
	g.Step(step, stripSessionUsage(resp), err)
}

// opsRequestCount counts recorded requests for a method and exact path.
func opsRequestCount(f *fakeOkta, method, path string) int {
	n := 0
	for _, r := range f.Requests() {
		if r.Method == method && r.Path == path {
			n++
		}
	}
	return n
}

// opsErr is a canned Okta error body.
func opsErr(code, summary string, causes string) string {
	if causes == "" {
		causes = "[]"
	}
	return fmt.Sprintf(`{"errorCode":%q,"errorSummary":%q,"errorLink":%q,"errorId":"oaeOps","errorCauses":%s}`, code, summary, code, causes)
}

var opsAtomRe = regexp.MustCompile(`[A-Za-z.]+ eq "[^"]*"`)

// opsNormalizeFilter makes a System Log filter comparable across runs. The
// connector builds each sub-filter from a Go set, so the order of OR/AND
// operands inside one group differs run to run; the order of the groups
// themselves is fixed. Each top-level group is rewritten as its sorted atoms.
func opsNormalizeFilter(filter string) string {
	var groups []string
	depth, start := 0, 0
	flush := func(end int) {
		g := strings.TrimSpace(filter[start:end])
		if g != "" {
			atoms := opsAtomRe.FindAllString(g, -1)
			sort.Strings(atoms)
			groups = append(groups, "{"+strings.Join(atoms, "; ")+"}")
		}
	}
	for i := 0; i < len(filter); i++ {
		switch filter[i] {
		case '(':
			depth++
		case ')':
			depth--
		case ' ':
			if depth == 0 && strings.HasPrefix(filter[i:], " or ") {
				flush(i)
				start = i + 4
			}
		}
	}
	flush(len(filter))
	return fmt.Sprintf("len=%d groups=%d %s", len(filter), len(groups), strings.Join(groups, " | "))
}

// opsCheck is golden.Check with the nondeterministic System Log filter
// normalized (see opsNormalizeFilter).
func opsCheck(g *golden) {
	g.t.Helper()
	for i, r := range g.f.reqs {
		if f := r.Query["filter"]; len(f) == 1 && r.Path == "/api/v1/logs" {
			q := map[string][]string{}
			for k, v := range r.Query {
				q[k] = v
			}
			q["filter"] = []string{opsNormalizeFilter(f[0])}
			g.f.reqs[i].Query = q
		}
	}
	g.Check()
}

// ---------------------------------------------------------------------------
// Action schemas
// ---------------------------------------------------------------------------

func TestBlackboxOpsActionSchemas(t *testing.T) {
	f := newFakeOkta(t)
	srv := newServer(t, f)
	g := newGolden(t, f)

	opsListSchemas(t, g, srv, "global schemas", "")
	opsListSchemas(t, g, srv, "user schemas", "user")
	opsListSchemas(t, g, srv, "group schemas", "group")
	opsListSchemas(t, g, srv, "app schemas", "app")
	opsListSchemas(t, g, srv, "unknown type schemas", "nonexistent")
	g.Check()
}

// ---------------------------------------------------------------------------
// Global lifecycle actions: enable_user / disable_user
// ---------------------------------------------------------------------------

func TestBlackboxOpsEnableDisableUser(t *testing.T) {
	f := newFakeOkta(t)
	newOpsOrg(f, map[string]string{
		"00uactive": "ACTIVE", "00ustaged": "STAGED", "00ususpended": "SUSPENDED",
		"00udeprov": "DEPROVISIONED", "00ulocked": "LOCKED_OUT", "00uprov": "PROVISIONED",
		"00uactive2": "ACTIVE", "00ustaged2": "STAGED", "00uforbid": "ACTIVE", "00ubadreq": "SUSPENDED",
	})
	srv := newServer(t, f)
	g := newGolden(t, f)

	// enable_user
	opsInvoke(t, g, srv, "enable ACTIVE is a no-op", "enable_user", "", map[string]any{"user_id": "00uactive"})
	opsInvoke(t, g, srv, "enable PROVISIONED is a no-op", "enable_user", "", map[string]any{"user_id": "00uprov"})
	opsInvoke(t, g, srv, "enable LOCKED_OUT is a no-op", "enable_user", "", map[string]any{"user_id": "00ulocked"})
	opsInvoke(t, g, srv, "enable STAGED activates with sendEmail=false", "enable_user", "", map[string]any{"user_id": "00ustaged"})
	opsInvoke(t, g, srv, "enable SUSPENDED unsuspends", "enable_user", "", map[string]any{"user_id": "00ususpended"})
	opsInvoke(t, g, srv, "enable DEPROVISIONED is unsupported", "enable_user", "", map[string]any{"user_id": "00udeprov"})
	opsInvoke(t, g, srv, "enable unknown user is 404", "enable_user", "", map[string]any{"user_id": "00unobody"})
	opsInvoke(t, g, srv, "enable missing user_id", "enable_user", "", map[string]any{})

	// disable_user
	opsInvoke(t, g, srv, "disable ACTIVE suspends", "disable_user", "", map[string]any{"user_id": "00uactive2"})
	opsInvoke(t, g, srv, "disable SUSPENDED is a no-op", "disable_user", "", map[string]any{"user_id": "00ususpended"})
	opsInvoke(t, g, srv, "disable DEPROVISIONED is a no-op", "disable_user", "", map[string]any{"user_id": "00udeprov"})
	opsInvoke(t, g, srv, "disable STAGED is a no-op", "disable_user", "", map[string]any{"user_id": "00ustaged2"})
	opsInvoke(t, g, srv, "disable unknown user is 404", "disable_user", "", map[string]any{"user_id": "00unobody"})

	// Okta error responses on the transition call itself.
	f.JSON(http.MethodPost, `/api/v1/users/00uforbid/lifecycle/suspend`, http.StatusForbidden,
		opsErr("E0000006", "You do not have permission to perform the requested action", ""))
	opsInvoke(t, g, srv, "disable suspend 403", "disable_user", "", map[string]any{"user_id": "00uforbid"})
	f.JSON(http.MethodPost, `/api/v1/users/00ubadreq/lifecycle/unsuspend`, http.StatusBadRequest,
		opsErr("E0000001", "Api validation failed", `[{"errorSummary":"transition not allowed"}]`))
	opsInvoke(t, g, srv, "enable unsuspend 400 E0000001", "enable_user", "", map[string]any{"user_id": "00ubadreq"})
	g.Check()
}

// ---------------------------------------------------------------------------
// Resource actions: deactivate_user / delete_user
// ---------------------------------------------------------------------------

func TestBlackboxOpsDeactivateDeleteUserActions(t *testing.T) {
	f := newFakeOkta(t)
	newOpsOrg(f, map[string]string{
		"00uactive": "ACTIVE", "00udeprov": "DEPROVISIONED", "00ubye": "ACTIVE",
		"00udeprov2": "DEPROVISIONED", "00uforbid": "ACTIVE", "00ugone": "ACTIVE",
	})
	srv := newServer(t, f)
	g := newGolden(t, f)

	opsInvoke(t, g, srv, "deactivate ACTIVE", "deactivate_user", "user", map[string]any{"user_id": opsRID("user", "00uactive")})
	opsInvoke(t, g, srv, "deactivate DEPROVISIONED is a no-op", "deactivate_user", "user", map[string]any{"user_id": opsRID("user", "00udeprov")})
	opsInvoke(t, g, srv, "deactivate unknown user", "deactivate_user", "user", map[string]any{"user_id": opsRID("user", "00unobody")})
	opsInvoke(t, g, srv, "deactivate wrong resource type", "deactivate_user", "user", map[string]any{"user_id": opsRID("group", "00g1")})
	opsInvoke(t, g, srv, "deactivate missing arg", "deactivate_user", "user", map[string]any{})
	opsInvoke(t, g, srv, "deactivate plain string arg is rejected", "deactivate_user", "user", map[string]any{"user_id": "00uactive"})

	f.JSON(http.MethodPost, `/api/v1/users/00uforbid/lifecycle/deactivate`, http.StatusForbidden,
		opsErr("E0000006", "You do not have permission to perform the requested action", ""))
	opsInvoke(t, g, srv, "deactivate 403", "deactivate_user", "user", map[string]any{"user_id": opsRID("user", "00uforbid")})

	opsInvoke(t, g, srv, "delete ACTIVE deactivates then deletes", "delete_user", "user", map[string]any{"user_id": opsRID("user", "00ubye")})
	opsInvoke(t, g, srv, "delete DEPROVISIONED deletes", "delete_user", "user", map[string]any{"user_id": opsRID("user", "00udeprov2")})
	opsInvoke(t, g, srv, "delete already gone", "delete_user", "user", map[string]any{"user_id": opsRID("user", "00ubye")})
	opsInvoke(t, g, srv, "delete wrong resource type", "delete_user", "user", map[string]any{"user_id": opsRID("app", "0oa1")})
	opsInvoke(t, g, srv, "delete deactivate 403", "delete_user", "user", map[string]any{"user_id": opsRID("user", "00uforbid")})
	g.Check()
}

// ---------------------------------------------------------------------------
// Profile update actions: update_user (global) / update_profile (resource)
// ---------------------------------------------------------------------------

func TestBlackboxOpsUpdateUserActions(t *testing.T) {
	f := newFakeOkta(t)
	f.Handle(http.MethodPost, `/api/v1/users/(00u[a-z0-9]+)`, func(w http.ResponseWriter, r *http.Request, m []string) {
		writeJSON(w, http.StatusOK, opsUserJSON(m[1], "ACTIVE", m[1]+"@example.com"))
	})
	f.JSON(http.MethodPost, `/api/v1/users/00ugone`, http.StatusNotFound, fmt.Sprintf(opsOktaNotFound, "00ugone"))
	f.JSON(http.MethodPost, `/api/v1/users/00ubad`, http.StatusBadRequest,
		opsErr("E0000001", "Api validation failed: login", `[{"errorSummary":"login: An object with this field already exists in the current organization"}]`))
	f.JSON(http.MethodPost, `/api/v1/users/00uforbid`, http.StatusForbidden,
		opsErr("E0000006", "You do not have permission to perform the requested action", ""))
	srv := newServer(t, f)
	g := newGolden(t, f)

	// update_user (global)
	opsInvoke(t, g, srv, "update_user JSON string profile", "update_user", "", map[string]any{
		"user_id": "00uone", "user_profile": `{"title":"Staff Engineer","department":"Platform","costCenter":null,"flag":true,"level":3,"tags":["a","b"]}`,
	})
	opsInvoke(t, g, srv, "update_user struct profile", "update_user", "", map[string]any{
		"user_id": "00uone", "user_profile": map[string]any{"city": "Denver"},
	})
	opsInvoke(t, g, srv, "update_user invalid JSON", "update_user", "", map[string]any{"user_id": "00uone", "user_profile": `{nope`})
	opsInvoke(t, g, srv, "update_user empty profile", "update_user", "", map[string]any{"user_id": "00uone", "user_profile": `{}`})
	opsInvoke(t, g, srv, "update_user nested object rejected", "update_user", "", map[string]any{"user_id": "00uone", "user_profile": `{"address":{"city":"x"}}`})
	opsInvoke(t, g, srv, "update_user mixed array rejected", "update_user", "", map[string]any{"user_id": "00uone", "user_profile": `{"tags":["a",1]}`})
	opsInvoke(t, g, srv, "update_user missing profile", "update_user", "", map[string]any{"user_id": "00uone"})
	opsInvoke(t, g, srv, "update_user missing user_id", "update_user", "", map[string]any{"user_profile": `{"title":"x"}`})
	opsInvoke(t, g, srv, "update_user 404", "update_user", "", map[string]any{"user_id": "00ugone", "user_profile": `{"title":"x"}`})
	opsInvoke(t, g, srv, "update_user 400 E0000001", "update_user", "", map[string]any{"user_id": "00ubad", "user_profile": `{"login":"dup@example.com"}`})
	opsInvoke(t, g, srv, "update_user 403", "update_user", "", map[string]any{"user_id": "00uforbid", "user_profile": `{"title":"x"}`})

	// update_profile (user resource action)
	opsInvoke(t, g, srv, "update_profile named fields", "update_profile", "user", map[string]any{
		"user_id": opsRID("user", "00uone"), "firstName": "Grace", "lastName": "Hopper", "title": "Rear Admiral", "managerId": "00uboss",
	})
	opsInvoke(t, g, srv, "update_profile empty string is forwarded", "update_profile", "user", map[string]any{
		"user_id": opsRID("user", "00uone"), "middleName": "",
	})
	opsInvoke(t, g, srv, "update_profile additionalAttributes", "update_profile", "user", map[string]any{
		"user_id": opsRID("user", "00uone"), "additionalAttributes": map[string]any{"nickName": "Gracie", "badge": float64(7), "roles": []any{"x", "y"}},
	})
	opsInvoke(t, g, srv, "update_profile additionalAttributes cannot override named", "update_profile", "user", map[string]any{
		"user_id": opsRID("user", "00uone"), "firstName": "G", "additionalAttributes": map[string]any{"firstName": "Other"},
	})
	opsInvoke(t, g, srv, "update_profile additionalAttributes nested rejected", "update_profile", "user", map[string]any{
		"user_id": opsRID("user", "00uone"), "additionalAttributes": map[string]any{"bad": map[string]any{"x": "y"}},
	})
	opsInvoke(t, g, srv, "update_profile non-string named field", "update_profile", "user", map[string]any{
		"user_id": opsRID("user", "00uone"), "title": float64(5),
	})
	opsInvoke(t, g, srv, "update_profile no fields", "update_profile", "user", map[string]any{"user_id": opsRID("user", "00uone")})
	opsInvoke(t, g, srv, "update_profile wrong resource type", "update_profile", "user", map[string]any{"user_id": opsRID("group", "00g1"), "title": "x"})
	opsInvoke(t, g, srv, "update_profile 404", "update_profile", "user", map[string]any{"user_id": opsRID("user", "00ugone"), "title": "x"})
	opsInvoke(t, g, srv, "update_profile 400 E0000001", "update_profile", "user", map[string]any{"user_id": opsRID("user", "00ubad"), "login": "dup@example.com"})
	opsInvoke(t, g, srv, "update_profile 403", "update_profile", "user", map[string]any{"user_id": opsRID("user", "00uforbid"), "title": "x"})
	g.Check()
}

// ---------------------------------------------------------------------------
// Group actions: create / modify_group, and group delete
// ---------------------------------------------------------------------------

func TestBlackboxOpsGroupActions(t *testing.T) {
	f := newFakeOkta(t)
	f.Fixture(http.MethodPost, `/api/v1/groups`, "ops_group_created.json")
	f.Fixture(http.MethodGet, `/api/v1/groups/00gops000000000001`, "ops_group.json")
	f.Fixture(http.MethodPut, `/api/v1/groups/00gops000000000001`, "ops_group_renamed.json")
	f.JSON(http.MethodGet, `/api/v1/groups/00ggone`, http.StatusNotFound,
		opsErr("E0000007", "Not found: Resource not found: 00ggone (UserGroup)", ""))
	f.Fixture(http.MethodGet, `/api/v1/groups/00gupdbad`, "ops_group.json")
	f.JSON(http.MethodPut, `/api/v1/groups/00gupdbad`, http.StatusBadRequest,
		opsErr("E0000001", "Api validation failed: name", `[{"errorSummary":"name: A group with name 'Taken' already exists"}]`))
	f.Handle(http.MethodPut, `/api/v1/groups/00gops000000000002/users/(00u[a-z0-9]+)`, func(w http.ResponseWriter, r *http.Request, m []string) {
		if m[1] == "00umissing" {
			writeJSON(w, http.StatusNotFound, fmt.Sprintf(opsOktaNotFound, m[1]))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	srv := newServer(t, f)
	g := newGolden(t, f)

	opsInvoke(t, g, srv, "create group", "create", "group", map[string]any{"name": "Security Reviewers", "description": "Reviews security changes"})
	opsInvoke(t, g, srv, "create group with members", "create", "group", map[string]any{
		"name":        "Security Reviewers",
		"userMembers": []any{opsRID("user", "00uops000000000001"), opsRID("user", "00uops000000000002")},
	})
	opsInvoke(t, g, srv, "create group member add fails", "create", "group", map[string]any{
		"name": "Security Reviewers", "userMembers": []any{opsRID("user", "00uops000000000001"), opsRID("user", "00umissing")},
	})
	opsInvoke(t, g, srv, "create group missing name", "create", "group", map[string]any{"description": "x"})
	f.JSON(http.MethodPost, `/api/v1/groups`, http.StatusBadRequest,
		opsErr("E0000001", "Api validation failed: name", `[{"errorSummary":"name: A group with name 'Taken' already exists"}]`))
	opsInvoke(t, g, srv, "create group 400", "create", "group", map[string]any{"name": "Taken"})
	f.JSON(http.MethodPost, `/api/v1/groups`, http.StatusForbidden, opsErr("E0000006", "You do not have permission to perform the requested action", ""))
	opsInvoke(t, g, srv, "create group 403", "create", "group", map[string]any{"name": "Nope"})

	opsInvoke(t, g, srv, "modify group name", "modify_group", "group", map[string]any{"group_id": "00gops000000000001", "name": "Platform Engineering"})
	opsInvoke(t, g, srv, "modify group no change is idempotent", "modify_group", "group", map[string]any{
		"group_id": "00gops000000000001", "name": "Platform Engineers", "description": "Platform engineering team",
	})
	opsInvoke(t, g, srv, "modify group description only", "modify_group", "group", map[string]any{"group_id": "00gops000000000001", "description": "New description"})
	opsInvoke(t, g, srv, "modify group nothing provided", "modify_group", "group", map[string]any{"group_id": "00gops000000000001"})
	opsInvoke(t, g, srv, "modify group missing id", "modify_group", "group", map[string]any{"name": "x"})
	opsInvoke(t, g, srv, "modify group 404", "modify_group", "group", map[string]any{"group_id": "00ggone", "name": "x"})
	opsInvoke(t, g, srv, "modify group update 400", "modify_group", "group", map[string]any{"group_id": "00gupdbad", "name": "Taken"})

	// DeleteResourceV2 for groups.
	f.JSON(http.MethodDelete, `/api/v1/groups/00gdel`, http.StatusNoContent, "")
	f.JSON(http.MethodDelete, `/api/v1/groups/00ggone`, http.StatusNotFound, opsErr("E0000007", "Not found: Resource not found: 00ggone (UserGroup)", ""))
	f.JSON(http.MethodDelete, `/api/v1/groups/00gforbid`, http.StatusForbidden, opsErr("E0000006", "You do not have permission to perform the requested action", ""))
	opsDelete(t, g, srv, "delete group", "group", "00gdel")
	opsDelete(t, g, srv, "delete group 404", "group", "00ggone")
	opsDelete(t, g, srv, "delete group 403", "group", "00gforbid")
	g.Check()
}

// ---------------------------------------------------------------------------
// DeleteResourceV2 for users
// ---------------------------------------------------------------------------

func TestBlackboxOpsDeleteUser(t *testing.T) {
	t.Run("active user is deactivated then deleted", func(t *testing.T) {
		f := newFakeOkta(t)
		newOpsOrg(f, map[string]string{"00uactive": "ACTIVE"})
		srv := newServer(t, f)
		g := newGolden(t, f)
		opsDelete(t, g, srv, "delete active", "user", "00uactive")
		g.Check()
	})
	t.Run("deprovisioned user is deleted without deactivation", func(t *testing.T) {
		f := newFakeOkta(t)
		newOpsOrg(f, map[string]string{"00udeprov": "DEPROVISIONED"})
		srv := newServer(t, f)
		g := newGolden(t, f)
		opsDelete(t, g, srv, "delete deprovisioned", "user", "00udeprov")
		g.Check()
	})
	t.Run("already gone", func(t *testing.T) {
		f := newFakeOkta(t)
		newOpsOrg(f, map[string]string{})
		srv := newServer(t, f)
		g := newGolden(t, f)
		opsDelete(t, g, srv, "delete missing", "user", "00ugone")
		g.Check()
	})
	t.Run("delete returns 404 after the status read", func(t *testing.T) {
		f := newFakeOkta(t)
		newOpsOrg(f, map[string]string{"00urace": "DEPROVISIONED"})
		f.JSON(http.MethodDelete, `/api/v1/users/00urace`, http.StatusNotFound, fmt.Sprintf(opsOktaNotFound, "00urace"))
		srv := newServer(t, f)
		g := newGolden(t, f)
		opsDelete(t, g, srv, "delete raced away", "user", "00urace")
		g.Check()
	})
	t.Run("user still exists after delete", func(t *testing.T) {
		// DELETE keeps answering 204 but the user never leaves DEPROVISIONED, so the
		// connector deletes twice and then reports Unavailable.
		f := newFakeOkta(t)
		newOpsOrg(f, map[string]string{"00ustuck": "DEPROVISIONED"})
		f.JSON(http.MethodDelete, `/api/v1/users/00ustuck`, http.StatusNoContent, "")
		srv := newServer(t, f)
		g := newGolden(t, f)
		opsDelete(t, g, srv, "delete stuck", "user", "00ustuck")
		require.Equal(t, 2, opsRequestCount(f, http.MethodDelete, "/api/v1/users/00ustuck"))
		g.Check()
	})
	t.Run("deactivation never lands", func(t *testing.T) {
		// Deactivate answers 200 but the status stays ACTIVE: four confirmation reads
		// 500ms apart, then Unavailable.
		f := newFakeOkta(t)
		newOpsOrg(f, map[string]string{"00uslow": "ACTIVE"})
		f.JSON(http.MethodPost, `/api/v1/users/00uslow/lifecycle/deactivate`, http.StatusOK, `{}`)
		srv := newServer(t, f)
		g := newGolden(t, f)
		opsDelete(t, g, srv, "delete never deprovisions", "user", "00uslow")
		g.Check()
	})
	t.Run("deactivate forbidden and reconciliation read shows ACTIVE", func(t *testing.T) {
		f := newFakeOkta(t)
		newOpsOrg(f, map[string]string{"00uforbid": "ACTIVE"})
		f.JSON(http.MethodPost, `/api/v1/users/00uforbid/lifecycle/deactivate`, http.StatusForbidden,
			opsErr("E0000006", "You do not have permission to perform the requested action", ""))
		srv := newServer(t, f)
		g := newGolden(t, f)
		opsDelete(t, g, srv, "delete forbidden", "user", "00uforbid")
		g.Check()
	})
	t.Run("deactivate errors but reconcile shows DEPROVISIONED", func(t *testing.T) {
		f := newFakeOkta(t)
		org := newOpsOrg(f, map[string]string{"00uconc": "ACTIVE"})
		f.Handle(http.MethodPost, `/api/v1/users/00uconc/lifecycle/deactivate`, func(w http.ResponseWriter, r *http.Request, _ []string) {
			// A concurrent actor wins the race: user is DEPROVISIONED but our call errors.
			org.mu.Lock()
			org.users["00uconc"] = "DEPROVISIONED"
			org.mu.Unlock()
			writeJSON(w, http.StatusBadRequest, opsErr("E0000001", "Api validation failed", ""))
		})
		srv := newServer(t, f)
		g := newGolden(t, f)
		opsDelete(t, g, srv, "delete concurrent deactivation", "user", "00uconc")
		g.Check()
	})
	t.Run("invalid resource ids", func(t *testing.T) {
		f := newFakeOkta(t)
		srv := newServer(t, f)
		g := newGolden(t, f)
		opsDelete(t, g, srv, "empty user id", "user", "")
		g.Check()
	})
}

// ---------------------------------------------------------------------------
// CreateAccount
// ---------------------------------------------------------------------------

func opsCreateRoute(f *fakeOkta, status string) {
	f.Handle(http.MethodPost, `/api/v1/users`, func(w http.ResponseWriter, r *http.Request, _ []string) {
		writeJSON(w, http.StatusOK, opsUserJSON("00ucreated0001", status, "new.user@example.com"))
	})
}

func opsBaseProfile(extra map[string]any) map[string]any {
	p := map[string]any{"first_name": "New", "last_name": "User", "email": "new.user@example.com"}
	for k, v := range extra {
		p[k] = v
	}
	return p
}

func TestBlackboxOpsCreateAccountCapabilities(t *testing.T) {
	f := newFakeOkta(t)
	srv := newServer(t, f)
	g := newGolden(t, f)
	rts, err := srv.ListResourceTypes(context.Background(), &v2.ResourceTypesServiceListResourceTypesRequest{})
	if rts != nil {
		sort.Slice(rts.List, func(i, j int) bool { return rts.List[i].GetId() < rts.List[j].GetId() })
	}
	g.Step("ListResourceTypes", stripSessionUsage(rts), err)
	g.Check()
}

func TestBlackboxOpsCreateAccount(t *testing.T) {
	type tc struct {
		name    string
		profile map[string]any
		cred    *v2.CredentialOptions
		status  string // status of the created user returned by Okta
	}
	cases := []tc{
		{"no password default", opsBaseProfile(nil), opsNoPassword(), "PROVISIONED"},
		{"login differs from email", opsBaseProfile(map[string]any{"login": "nuser"}), opsNoPassword(), "PROVISIONED"},
		{"random password", opsBaseProfile(nil), opsRandomPassword(16), "ACTIVE"},
		{"random password length below minimum", opsBaseProfile(nil), opsRandomPassword(5), "ACTIVE"},
		{"random password change on login", opsBaseProfile(map[string]any{"password_change_on_login_required": "true"}), opsRandomPassword(12), "PASSWORD_EXPIRED"},
		{"no password ignores change on login", opsBaseProfile(map[string]any{"password_change_on_login_required": true}), opsNoPassword(), "PROVISIONED"},
		{"create inactive", opsBaseProfile(map[string]any{"create_inactive": "true"}), opsNoPassword(), "STAGED"},
		{"create inactive wins over send_activation_email false", opsBaseProfile(map[string]any{"create_inactive": true, "send_activation_email": false}), opsNoPassword(), "STAGED"},
		{"send activation email true explicit", opsBaseProfile(map[string]any{"send_activation_email": "true"}), opsNoPassword(), "PROVISIONED"},
		{"federation provider", opsBaseProfile(map[string]any{"provider_type": "federation"}), opsNoPassword(), "ACTIVE"},
		{"explicit OKTA provider", opsBaseProfile(map[string]any{"provider_type": " okta "}), opsNoPassword(), "PROVISIONED"},
		{
			"additional attributes",
			opsBaseProfile(map[string]any{"additionalAttributes": map[string]any{"department": "Eng", "badge": float64(42), "tags": []any{"a"}}}),
			opsNoPassword(), "PROVISIONED",
		},
		// Validation errors, none of which reach Okta.
		{"missing first name", map[string]any{"last_name": "User", "email": "a@example.com"}, opsNoPassword(), ""},
		{"missing last name", map[string]any{"first_name": "New", "email": "a@example.com"}, opsNoPassword(), ""},
		{"missing email", map[string]any{"first_name": "New", "last_name": "User"}, opsNoPassword(), ""},
		{"unsupported credential option", opsBaseProfile(nil), &v2.CredentialOptions{Options: &v2.CredentialOptions_Sso{Sso: &v2.CredentialOptions_SSO{SsoProvider: "okta"}}}, ""},
		{"federation with random password", opsBaseProfile(map[string]any{"provider_type": "FEDERATION"}), opsRandomPassword(12), ""},
		{"unsupported provider type", opsBaseProfile(map[string]any{"provider_type": "SOCIAL"}), opsNoPassword(), ""},
		{"provider type not a string", opsBaseProfile(map[string]any{"provider_type": float64(3)}), opsNoPassword(), ""},
		{"protected additional attribute email", opsBaseProfile(map[string]any{"additionalAttributes": map[string]any{"email": "evil@example.com"}}), opsNoPassword(), ""},
		{"protected additional attribute login", opsBaseProfile(map[string]any{"additionalAttributes": map[string]any{"login": "evil"}}), opsNoPassword(), ""},
		{"protected additional attribute firstName", opsBaseProfile(map[string]any{"additionalAttributes": map[string]any{"firstName": "Evil"}}), opsNoPassword(), ""},
		{"additional attributes not an object", opsBaseProfile(map[string]any{"additionalAttributes": "department=Eng"}), opsNoPassword(), ""},
		{"invalid bool string", opsBaseProfile(map[string]any{"create_inactive": "maybe"}), opsNoPassword(), ""},
		{"bool wrong type", opsBaseProfile(map[string]any{"send_activation_email": float64(1)}), opsNoPassword(), ""},
		{
			"send_activation_email false conflicts with change on login",
			opsBaseProfile(map[string]any{"send_activation_email": false, "password_change_on_login_required": true}),
			opsRandomPassword(12), "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeOkta(t)
			if c.status != "" {
				opsCreateRoute(f, c.status)
			}
			srv := newServer(t, f)
			g := newGolden(t, f)
			opsCreateAccount(t, g, srv, "CreateAccount", c.profile, c.cred)
			g.Check()
		})
	}

	t.Run("send activation email false stages, activates silently and re-reads", func(t *testing.T) {
		f := newFakeOkta(t)
		opsCreateRoute(f, "STAGED")
		f.JSON(http.MethodPost, `/api/v1/users/00ucreated0001/lifecycle/activate`, http.StatusOK, `{"activationUrl":"https://example.okta.com/welcome/x"}`)
		f.JSON(http.MethodGet, `/api/v1/users/00ucreated0001`, http.StatusOK, opsUserJSON("00ucreated0001", "PROVISIONED", "new.user@example.com"))
		srv := newServer(t, f)
		g := newGolden(t, f)
		opsCreateAccount(t, g, srv, "CreateAccount", opsBaseProfile(map[string]any{"send_activation_email": false}), opsNoPassword())
		g.Check()
	})
	t.Run("send activation email false with random password", func(t *testing.T) {
		f := newFakeOkta(t)
		opsCreateRoute(f, "STAGED")
		f.JSON(http.MethodPost, `/api/v1/users/00ucreated0001/lifecycle/activate`, http.StatusOK, `{}`)
		f.JSON(http.MethodGet, `/api/v1/users/00ucreated0001`, http.StatusOK, opsUserJSON("00ucreated0001", "ACTIVE", "new.user@example.com"))
		srv := newServer(t, f)
		g := newGolden(t, f)
		opsCreateAccount(t, g, srv, "CreateAccount", opsBaseProfile(map[string]any{"send_activation_email": "false"}), opsRandomPassword(12))
		g.Check()
	})
	t.Run("send activation email false re-read fails keeps created user", func(t *testing.T) {
		f := newFakeOkta(t)
		opsCreateRoute(f, "STAGED")
		f.JSON(http.MethodPost, `/api/v1/users/00ucreated0001/lifecycle/activate`, http.StatusOK, `{}`)
		f.JSON(http.MethodGet, `/api/v1/users/00ucreated0001`, http.StatusInternalServerError, opsErr("E0000009", "Internal Server Error", ""))
		srv := newServer(t, f)
		g := newGolden(t, f)
		opsCreateAccount(t, g, srv, "CreateAccount", opsBaseProfile(map[string]any{"send_activation_email": false}), opsNoPassword())
		g.Check()
	})
	t.Run("send activation email false activation fails", func(t *testing.T) {
		f := newFakeOkta(t)
		opsCreateRoute(f, "STAGED")
		f.JSON(http.MethodPost, `/api/v1/users/00ucreated0001/lifecycle/activate`, http.StatusForbidden,
			opsErr("E0000006", "You do not have permission to perform the requested action", ""))
		srv := newServer(t, f)
		g := newGolden(t, f)
		opsCreateAccount(t, g, srv, "CreateAccount", opsBaseProfile(map[string]any{"send_activation_email": false}), opsNoPassword())
		g.Check()
	})

	dupBody := opsErr("E0000001", "Api validation failed: login", `[{"errorSummary":"login: An object with this field already exists in the current organization"}]`)
	t.Run("duplicate login returns the existing active user", func(t *testing.T) {
		f := newFakeOkta(t)
		f.JSON(http.MethodPost, `/api/v1/users`, http.StatusBadRequest, dupBody)
		f.JSON(http.MethodGet, `/api/v1/users/new.user@example.com`, http.StatusOK, opsUserJSON("00uexisting01", "ACTIVE", "new.user@example.com"))
		srv := newServer(t, f)
		g := newGolden(t, f)
		opsCreateAccount(t, g, srv, "CreateAccount", opsBaseProfile(nil), opsNoPassword())
		g.Check()
	})
	t.Run("duplicate login returns the existing staged user untouched", func(t *testing.T) {
		f := newFakeOkta(t)
		f.JSON(http.MethodPost, `/api/v1/users`, http.StatusBadRequest, dupBody)
		f.JSON(http.MethodGet, `/api/v1/users/new.user@example.com`, http.StatusOK, opsUserJSON("00uexisting02", "STAGED", "new.user@example.com"))
		srv := newServer(t, f)
		g := newGolden(t, f)
		opsCreateAccount(t, g, srv, "CreateAccount", opsBaseProfile(map[string]any{"send_activation_email": false}), opsNoPassword())
		g.Check()
	})
	t.Run("duplicate login on deprovisioned user", func(t *testing.T) {
		f := newFakeOkta(t)
		f.JSON(http.MethodPost, `/api/v1/users`, http.StatusBadRequest, dupBody)
		f.JSON(http.MethodGet, `/api/v1/users/new.user@example.com`, http.StatusOK, opsUserJSON("00uexisting03", "DEPROVISIONED", "new.user@example.com"))
		srv := newServer(t, f)
		g := newGolden(t, f)
		opsCreateAccount(t, g, srv, "CreateAccount", opsBaseProfile(nil), opsNoPassword())
		g.Check()
	})
	t.Run("duplicate login lookup fails", func(t *testing.T) {
		f := newFakeOkta(t)
		f.JSON(http.MethodPost, `/api/v1/users`, http.StatusBadRequest, dupBody)
		f.JSON(http.MethodGet, `/api/v1/users/new.user@example.com`, http.StatusNotFound, fmt.Sprintf(opsOktaNotFound, "new.user@example.com"))
		srv := newServer(t, f)
		g := newGolden(t, f)
		opsCreateAccount(t, g, srv, "CreateAccount", opsBaseProfile(nil), opsNoPassword())
		g.Check()
	})
	t.Run("duplicate login looked up by explicit login", func(t *testing.T) {
		f := newFakeOkta(t)
		f.JSON(http.MethodPost, `/api/v1/users`, http.StatusBadRequest, dupBody)
		f.JSON(http.MethodGet, `/api/v1/users/nuser`, http.StatusOK, opsUserJSON("00uexisting04", "ACTIVE", "nuser"))
		srv := newServer(t, f)
		g := newGolden(t, f)
		opsCreateAccount(t, g, srv, "CreateAccount", opsBaseProfile(map[string]any{"login": "nuser"}), opsNoPassword())
		g.Check()
	})
	t.Run("E0000001 without a duplicate login cause is a plain error", func(t *testing.T) {
		f := newFakeOkta(t)
		f.JSON(http.MethodPost, `/api/v1/users`, http.StatusBadRequest,
			opsErr("E0000001", "Api validation failed: email", `[{"errorSummary":"email: Does not match required pattern"}]`))
		srv := newServer(t, f)
		g := newGolden(t, f)
		opsCreateAccount(t, g, srv, "CreateAccount", opsBaseProfile(nil), opsNoPassword())
		g.Check()
	})
	t.Run("create 403", func(t *testing.T) {
		f := newFakeOkta(t)
		f.JSON(http.MethodPost, `/api/v1/users`, http.StatusForbidden, opsErr("E0000006", "You do not have permission to perform the requested action", ""))
		srv := newServer(t, f)
		g := newGolden(t, f)
		opsCreateAccount(t, g, srv, "CreateAccount", opsBaseProfile(nil), opsNoPassword())
		g.Check()
	})
	t.Run("create returns non-200 success", func(t *testing.T) {
		f := newFakeOkta(t)
		f.JSON(http.MethodPost, `/api/v1/users`, http.StatusCreated, opsUserJSON("00ucreated0001", "PROVISIONED", "new.user@example.com"))
		srv := newServer(t, f)
		g := newGolden(t, f)
		opsCreateAccount(t, g, srv, "CreateAccount", opsBaseProfile(nil), opsNoPassword())
		g.Check()
	})
	t.Run("create 500 without JSON body", func(t *testing.T) {
		f := newFakeOkta(t)
		f.Handle(http.MethodPost, `/api/v1/users`, func(w http.ResponseWriter, r *http.Request, _ []string) {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("upstream exploded"))
		})
		srv := newServer(t, f)
		g := newGolden(t, f)
		opsCreateAccount(t, g, srv, "CreateAccount", opsBaseProfile(nil), opsNoPassword())
		g.Check()
	})
	t.Run("private key auth", func(t *testing.T) {
		f := newFakeOkta(t)
		opsCreateRoute(f, "PROVISIONED")
		srv := newServer(t, f, privateKeyConn(t, f))
		g := newGolden(t, f)
		opsCreateAccount(t, g, srv, "CreateAccount", opsBaseProfile(nil), opsNoPassword())
		g.Check()
	})
}

// ---------------------------------------------------------------------------
// Events (System Log)
// ---------------------------------------------------------------------------

func opsListEvents(t *testing.T, g *golden, srv types.ConnectorServer, step, cursor string, startAt *timestamppb.Timestamp, pageSize uint32) *v2.ListEventsResponse {
	t.Helper()
	resp, err := srv.ListEvents(context.Background(), &v2.ListEventsRequest{Cursor: cursor, StartAt: startAt, PageSize: pageSize})
	g.Step(step, stripSessionUsage(resp), err)
	return resp
}

func TestBlackboxOpsListEvents(t *testing.T) {
	f := newFakeOkta(t)
	f.FixturePages("/api/v1/logs", "ops_logs_page1.json", "ops_logs_page2.json", "ops_logs_empty.json")
	srv := newServer(t, f)
	g := newGolden(t, f)

	feeds, err := srv.ListEventFeeds(context.Background(), &v2.ListEventFeedsRequest{})
	g.Step("ListEventFeeds", stripSessionUsage(feeds), err)

	start := timestamppb.New(time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC))
	cursor := ""
	for page := 1; page <= 5; page++ {
		resp := opsListEvents(t, g, srv, fmt.Sprintf("ListEvents page %d", page), cursor, start, 50)
		if resp == nil || !resp.GetHasMore() {
			break
		}
		cursor = resp.GetCursor()
	}
	// Explicit event feed id, no start time, default page size.
	resp, err := srv.ListEvents(context.Background(), &v2.ListEventsRequest{EventFeedId: "baton_feed_event"})
	g.Step("ListEvents explicit legacy feed, no start", stripSessionUsage(resp), err)
	resp, err = srv.ListEvents(context.Background(), &v2.ListEventsRequest{EventFeedId: "nope"})
	g.Step("ListEvents unknown feed", stripSessionUsage(resp), err)
	opsCheck(g)
}

func TestBlackboxOpsListEventsEdgeCases(t *testing.T) {
	t.Run("empty page", func(t *testing.T) {
		f := newFakeOkta(t)
		f.FixturePages("/api/v1/logs", "ops_logs_empty.json")
		srv := newServer(t, f)
		g := newGolden(t, f)
		opsListEvents(t, g, srv, "ListEvents empty", "", nil, 10)
		opsCheck(g)
	})
	t.Run("cursor repeated by Okta means no more pages", func(t *testing.T) {
		// Okta's documented contract is an empty next link at the end; in practice it
		// echoes the request cursor. The connector treats an unchanged cursor as done.
		f := newFakeOkta(t)
		f.Handle(http.MethodGet, "/api/v1/logs", func(w http.ResponseWriter, r *http.Request, _ []string) {
			w.Header().Add("Link", fmt.Sprintf(`<%s>; rel="self"`, f.URL(r.URL.RequestURI())))
			w.Header().Add("Link", fmt.Sprintf(`<%s>; rel="next"`, f.URL(r.URL.RequestURI())))
			writeJSON(w, http.StatusOK, fixture(t, "ops_logs_empty.json"))
		})
		srv := newServer(t, f)
		g := newGolden(t, f)
		opsListEvents(t, g, srv, "ListEvents first (no cursor)", "", nil, 10)
		opsListEvents(t, g, srv, "ListEvents repeated cursor", "cursorX", nil, 10)
		opsCheck(g)
	})
	t.Run("since is sent as RFC3339 and cursor as after", func(t *testing.T) {
		f := newFakeOkta(t)
		f.FixturePages("/api/v1/logs", "ops_logs_page1.json", "ops_logs_empty.json")
		srv := newServer(t, f)
		g := newGolden(t, f)
		opsListEvents(t, g, srv, "ListEvents with since", "", timestamppb.New(time.Date(2026, 1, 5, 9, 30, 15, 0, time.UTC)), 7)
		opsListEvents(t, g, srv, "ListEvents second page", "cursor1", timestamppb.New(time.Date(2026, 1, 5, 9, 30, 15, 0, time.UTC)), 7)
		opsCheck(g)
	})
	t.Run("log events error responses", func(t *testing.T) {
		for _, c := range []struct {
			name   string
			status int
			body   string
		}{
			{"403", http.StatusForbidden, opsErr("E0000006", "You do not have permission to perform the requested action", "")},
			{"401", http.StatusUnauthorized, opsErr("E0000011", "Invalid token provided", "")},
			{"400", http.StatusBadRequest, opsErr("E0000031", "Invalid filter", "")},
			{"500 plain", http.StatusInternalServerError, "oops"},
		} {
			t.Run(c.name, func(t *testing.T) {
				f := newFakeOkta(t)
				f.JSON(http.MethodGet, "/api/v1/logs", c.status, c.body)
				srv := newServer(t, f)
				g := newGolden(t, f)
				opsListEvents(t, g, srv, "ListEvents error", "", nil, 10)
				opsCheck(g)
			})
		}
	})
}

// ---------------------------------------------------------------------------
// Validate and GetMetadata
// ---------------------------------------------------------------------------

func TestBlackboxOpsValidateAndMetadata(t *testing.T) {
	t.Run("healthy org", func(t *testing.T) {
		f := newFakeOkta(t)
		f.Fixture(http.MethodGet, "/api/v1/org", "ops_org.json")
		srv := newServer(t, f)
		g := newGolden(t, f)
		opsValidate(t, g, srv, "Validate")
		md, err := srv.GetMetadata(context.Background(), &v2.ConnectorServiceGetMetadataRequest{})
		g.Step("GetMetadata", stripSessionUsage(md), err)
		g.Check()
	})
	for _, c := range []struct {
		name   string
		status int
		body   string
	}{
		{"401 unauthenticated", http.StatusUnauthorized, opsErr("E0000011", "Invalid token provided", "")},
		{"403 forbidden", http.StatusForbidden, opsErr("E0000006", "You do not have permission to perform the requested action", "")},
		{"404", http.StatusNotFound, opsErr("E0000007", "Not found: Resource not found: org (Org)", "")},
		{"202 accepted is non-200", http.StatusAccepted, `{}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeOkta(t)
			f.JSON(http.MethodGet, "/api/v1/org", c.status, c.body)
			srv := newServer(t, f)
			g := newGolden(t, f)
			opsValidate(t, g, srv, "Validate")
			md, err := srv.GetMetadata(context.Background(), &v2.ConnectorServiceGetMetadataRequest{})
			g.Step("GetMetadata", stripSessionUsage(md), err)
			g.Check()
		})
	}
	t.Run("private key auth skips the org call", func(t *testing.T) {
		f := newFakeOkta(t)
		srv := newServer(t, f, privateKeyConn(t, f))
		g := newGolden(t, f)
		opsValidate(t, g, srv, "Validate")
		md, err := srv.GetMetadata(context.Background(), &v2.ConnectorServiceGetMetadataRequest{})
		g.Step("GetMetadata", stripSessionUsage(md), err)
		g.Check()
	})
}

// ---------------------------------------------------------------------------
// Transport: 429 retry, exhaustion, cache, error bodies, auth modes
// ---------------------------------------------------------------------------

// opsRateLimited answers n times with a 429 whose Date and X-Rate-Limit-Reset
// are both "now", so the SDK backs off for about a second per retry, then
// defers to next.
func opsRateLimited(n int, next func(w http.ResponseWriter, r *http.Request, m []string)) func(w http.ResponseWriter, r *http.Request, m []string) {
	var mu sync.Mutex
	seen := 0
	return func(w http.ResponseWriter, r *http.Request, m []string) {
		mu.Lock()
		seen++
		limited := n < 0 || seen <= n
		mu.Unlock()
		if !limited {
			next(w, r, m)
			return
		}
		now := time.Now().UTC()
		w.Header().Set("Date", now.Format("Mon, 02 Jan 2006 15:04:05 GMT"))
		w.Header().Set("X-Rate-Limit-Reset", fmt.Sprint(now.Unix()))
		w.Header().Set("X-Rate-Limit-Remaining", "0")
		writeJSON(w, http.StatusTooManyRequests, opsErr("E0000047", "API call exceeded rate limit due to too many requests.", ""))
	}
}

func TestBlackboxOpsRateLimitRetrySucceeds(t *testing.T) {
	f := newFakeOkta(t)
	ok := func(w http.ResponseWriter, r *http.Request, m []string) {
		writeJSON(w, http.StatusOK, opsUserJSON("00url", "ACTIVE", "rl@example.com"))
	}
	f.Handle(http.MethodGet, `/api/v1/users/00url`, opsRateLimited(2, ok))
	srv := newServer(t, f)
	g := newGolden(t, f)
	opsGetUser(t, g, srv, "GetResource after two 429s", "00url")
	reqs := f.Requests()
	require.Len(t, reqs, 3)
	require.Equal(t, "1", reqs[1].Headers["X-Okta-Retry-Count"])
	require.NotEmpty(t, reqs[1].Headers["X-Okta-Retry-For"])
	g.Check()
}

func TestBlackboxOpsRateLimitExhausted(t *testing.T) {
	f := newFakeOkta(t)
	f.Handle(http.MethodGet, `/api/v1/users/00url`, opsRateLimited(-1, nil))
	srv := newServer(t, f)
	g := newGolden(t, f)
	opsGetUser(t, g, srv, "GetResource with endless 429s", "00url")
	g.Check()
}

func TestBlackboxOpsRateLimitMissingHeaders(t *testing.T) {
	f := newFakeOkta(t)
	f.Handle(http.MethodGet, `/api/v1/users/00url`, func(w http.ResponseWriter, r *http.Request, _ []string) {
		// No usable Date/X-Rate-Limit-Reset pair: the SDK gives up without retrying.
		w.Header().Set("X-Rate-Limit-Reset", "")
		writeJSON(w, http.StatusTooManyRequests, opsErr("E0000047", "API call exceeded rate limit due to too many requests.", ""))
	})
	srv := newServer(t, f)
	g := newGolden(t, f)
	opsGetUser(t, g, srv, "GetResource 429 without reset header", "00url")
	require.Len(t, f.Requests(), 1)
	g.Check()
}

func TestBlackboxOpsResponseCache(t *testing.T) {
	run := func(t *testing.T, cache bool) {
		f := newFakeOkta(t)
		newOpsOrg(f, map[string]string{"00ucache": "ACTIVE", "00uflip": "ACTIVE"})
		srv := newServer(t, f, withConfig(func(c *cfg.Okta) { c.Cache = cache }))
		g := newGolden(t, f)

		opsGetUser(t, g, srv, "GetResource first", "00ucache")
		opsGetUser(t, g, srv, "GetResource second", "00ucache")
		// disable_user reads status through the cache: after the first call suspends the
		// user, the second still sees the cached ACTIVE status when caching is on.
		opsInvoke(t, g, srv, "disable first", "disable_user", "", map[string]any{"user_id": "00uflip"})
		opsInvoke(t, g, srv, "disable second", "disable_user", "", map[string]any{"user_id": "00uflip"})

		getsCache := opsRequestCount(f, http.MethodGet, "/api/v1/users/00ucache")
		if cache {
			require.Equal(t, 1, getsCache)
			require.Equal(t, 1, opsRequestCount(f, http.MethodGet, "/api/v1/users/00uflip"))
			require.Equal(t, 2, opsRequestCount(f, http.MethodPost, "/api/v1/users/00uflip/lifecycle/suspend"))
		} else {
			require.Equal(t, 2, getsCache)
			require.Equal(t, 2, opsRequestCount(f, http.MethodGet, "/api/v1/users/00uflip"))
			require.Equal(t, 1, opsRequestCount(f, http.MethodPost, "/api/v1/users/00uflip/lifecycle/suspend"))
		}
		g.Check()
	}
	t.Run("cache on", func(t *testing.T) { run(t, true) })
	t.Run("cache off", func(t *testing.T) { run(t, false) })
}

func TestBlackboxOpsErrorClassification(t *testing.T) {
	f := newFakeOkta(t)
	for id, c := range map[string]struct {
		status int
		ctype  string
		body   string
	}{
		"00u500json":    {500, "application/json", opsErr("E0000009", "Internal Server Error", "")},
		"00u500text":    {500, "text/plain", "upstream exploded"},
		"00u500empty":   {500, "", ""},
		"00u502html":    {502, "text/html", "<html><body>Bad Gateway</body></html>"},
		"00u503json":    {503, "application/json", opsErr("E0000009", "Service unavailable", "")},
		"00u400":        {400, "application/json", opsErr("E0000001", "Api validation failed", `[{"errorSummary":"bad"}]`)},
		"00u400empty":   {400, "", ""},
		"00u401":        {401, "application/json", opsErr("E0000011", "Invalid token provided", "")},
		"00u403":        {403, "application/json", opsErr("E0000006", "You do not have permission to perform the requested action", "")},
		"00u403empty":   {403, "", ""},
		"00u404":        {404, "application/json", fmt.Sprintf(opsOktaNotFound, "00u404")},
		"00u404html":    {404, "text/html", "<html>nope</html>"},
		"00u408":        {408, "application/json", opsErr("E0000009", "timeout", "")},
		"00u200garbage": {200, "application/json", "not json at all"},
	} {
		c := c
		f.Handle(http.MethodGet, `/api/v1/users/`+id, func(w http.ResponseWriter, r *http.Request, _ []string) {
			if c.ctype != "" {
				w.Header().Set("Content-Type", c.ctype)
			}
			w.WriteHeader(c.status)
			_, _ = w.Write([]byte(c.body))
		})
	}
	srv := newServer(t, f)
	g := newGolden(t, f)
	for _, id := range []string{
		"00u500json", "00u500text", "00u500empty", "00u502html", "00u503json", "00u400", "00u400empty",
		"00u401", "00u403", "00u403empty", "00u404", "00u404html", "00u408", "00u200garbage",
	} {
		opsGetUser(t, g, srv, "GetResource "+id, id)
	}
	g.Check()
}

func TestBlackboxOpsPrivateKeyAuthActions(t *testing.T) {
	f := newFakeOkta(t)
	newOpsOrg(f, map[string]string{"00uactive": "ACTIVE", "00ubye": "ACTIVE"})
	srv := newServer(t, f, privateKeyConn(t, f))
	g := newGolden(t, f)
	opsInvoke(t, g, srv, "disable_user", "disable_user", "", map[string]any{"user_id": "00uactive"})
	opsInvoke(t, g, srv, "delete_user", "delete_user", "user", map[string]any{"user_id": opsRID("user", "00ubye")})
	g.Check()
}

func TestBlackboxOpsApiTokenAuthHeader(t *testing.T) {
	f := newFakeOkta(t)
	f.Fixture(http.MethodGet, "/api/v1/org", "ops_org.json")
	srv := newServer(t, f)
	g := newGolden(t, f)
	opsValidate(t, g, srv, "Validate")
	reqs := f.Requests()
	require.Len(t, reqs, 1)
	require.Equal(t, "SSWS "+testAPIToken, reqs[0].Headers["Authorization"])
	g.Check()
}

// TestBlackboxOpsResponseCacheSemantics pins the observable rules of the
// connector's GET response cache (config cache, cache-ttl, cache-tti):
//   - an entry expires cache-ttl seconds after it was stored, and cache-ttl 0
//     means entries never expire;
//   - only successful GET responses are stored, keyed by full URL, and that
//     includes list pages;
//   - a non-GET request evicts only the entry for its own URL;
//   - the lifecycle reconciliation in Delete reads the user fresh.
//
// cache-tti only sets how often expired entries are purged from memory, which
// is not observable through the connector.
func TestBlackboxOpsResponseCacheSemantics(t *testing.T) {
	cacheConf := func(ttl, tti int) connOpt {
		return withConfig(func(c *cfg.Okta) { c.Cache = true; c.CacheTtl = ttl; c.CacheTti = tti })
	}

	t.Run("entries expire after cache-ttl", func(t *testing.T) {
		f := newFakeOkta(t)
		newOpsOrg(f, map[string]string{"00uttl": "ACTIVE"})
		srv := newServer(t, f, cacheConf(1, 1))
		g := newGolden(t, f)
		opsGetUser(t, g, srv, "GetResource first", "00uttl")
		opsGetUser(t, g, srv, "GetResource cached", "00uttl")
		require.Equal(t, 1, opsRequestCount(f, http.MethodGet, "/api/v1/users/00uttl"))
		time.Sleep(1500 * time.Millisecond)
		opsGetUser(t, g, srv, "GetResource after ttl", "00uttl")
		require.Equal(t, 2, opsRequestCount(f, http.MethodGet, "/api/v1/users/00uttl"))
		g.Check()
	})

	t.Run("cache-ttl 0 never expires", func(t *testing.T) {
		f := newFakeOkta(t)
		newOpsOrg(f, map[string]string{"00uttl": "ACTIVE"})
		srv := newServer(t, f, cacheConf(0, 1))
		g := newGolden(t, f)
		opsGetUser(t, g, srv, "GetResource first", "00uttl")
		time.Sleep(1500 * time.Millisecond)
		opsGetUser(t, g, srv, "GetResource later", "00uttl")
		require.Equal(t, 1, opsRequestCount(f, http.MethodGet, "/api/v1/users/00uttl"))
		g.Check()
	})

	t.Run("error responses are not cached", func(t *testing.T) {
		f := newFakeOkta(t)
		var mu sync.Mutex
		calls := 0
		f.Handle(http.MethodGet, `/api/v1/users/00uflaky`, func(w http.ResponseWriter, r *http.Request, _ []string) {
			mu.Lock()
			calls++
			n := calls
			mu.Unlock()
			if n == 1 {
				writeJSON(w, http.StatusNotFound, fmt.Sprintf(opsOktaNotFound, "00uflaky"))
				return
			}
			writeJSON(w, http.StatusOK, opsUserJSON("00uflaky", "ACTIVE", "00uflaky@example.com"))
		})
		srv := newServer(t, f)
		g := newGolden(t, f)
		opsGetUser(t, g, srv, "GetResource 404", "00uflaky")
		opsGetUser(t, g, srv, "GetResource 200", "00uflaky")
		opsGetUser(t, g, srv, "GetResource cached 200", "00uflaky")
		require.Equal(t, 2, opsRequestCount(f, http.MethodGet, "/api/v1/users/00uflaky"))
		g.Check()
	})

	t.Run("list pages are cached by full URL", func(t *testing.T) {
		f := newFakeOkta(t)
		f.Pages(`/api/v1/users`,
			"["+opsUserJSON("00ulist1", "ACTIVE", "list1@example.com")+"]",
			"["+opsUserJSON("00ulist2", "ACTIVE", "list2@example.com")+"]",
		)
		srv := newServer(t, f)
		g := newGolden(t, f)
		require.Len(t, listAllResources(t, g, srv, "user", nil, 1), 2)
		require.Len(t, listAllResources(t, g, srv, "user", nil, 1), 2)
		require.Equal(t, 2, opsRequestCount(f, http.MethodGet, "/api/v1/users"))
		require.Len(t, listAllResources(t, g, srv, "user", nil, 2), 2)
		g.Check()
	})

	t.Run("writes evict only their own URL and Delete reads fresh", func(t *testing.T) {
		f := newFakeOkta(t)
		newOpsOrg(f, map[string]string{"00ugone": "ACTIVE", "00ususp": "ACTIVE"})
		srv := newServer(t, f)
		g := newGolden(t, f)
		// The suspend POST targets .../lifecycle/suspend, so the cached user read stays.
		opsGetUser(t, g, srv, "GetResource before suspend", "00ususp")
		opsInvoke(t, g, srv, "suspend", "disable_user", "", map[string]any{"user_id": "00ususp"})
		opsGetUser(t, g, srv, "GetResource after suspend", "00ususp")
		require.Equal(t, 1, opsRequestCount(f, http.MethodGet, "/api/v1/users/00ususp"))
		// DELETE /api/v1/users/{id} shares the user read's URL and evicts it.
		opsGetUser(t, g, srv, "GetResource before delete", "00ugone")
		opsDelete(t, g, srv, "Delete", "user", "00ugone")
		opsGetUser(t, g, srv, "GetResource after delete", "00ugone")
		g.Check()
	})
}

// Every Okta request, including the OAuth token exchange in private-key mode,
// identifies the connector in its User-Agent.
func TestBlackboxOpsUserAgent(t *testing.T) {
	run := func(t *testing.T, privateKey bool) {
		f := newFakeOkta(t)
		newOpsOrg(f, map[string]string{"00uagent": "ACTIVE"})
		var opts []connOpt
		if privateKey {
			opts = append(opts, privateKeyConn(t, f))
		}
		var mu sync.Mutex
		agents := map[string]string{}
		skip := f.skipRecord
		f.skipRecord = func(r *http.Request) bool {
			mu.Lock()
			agents[r.Method+" "+r.URL.Path] = r.UserAgent()
			mu.Unlock()
			return skip != nil && skip(r)
		}
		srv := newServer(t, f, opts...)
		g := newGolden(t, f)
		opsGetUser(t, g, srv, "GetResource", "00uagent")
		mu.Lock()
		defer mu.Unlock()
		require.Contains(t, agents, "GET /api/v1/users/00uagent")
		if privateKey {
			require.Contains(t, agents, "POST /oauth2/v1/token")
		}
		for req, ua := range agents {
			require.Regexp(t, `^baton-okta baton-sdk/\S+$`, ua, req)
		}
	}
	t.Run("api token", func(t *testing.T) { run(t, false) })
	t.Run("private key", func(t *testing.T) { run(t, true) })
}
