package connector

// End-to-end source-cache replay harness for the lastMembershipUpdated
// dirty-scope model (group_type_scoped.go).
//
// Runs the real connector against a strict mock Okta org (exact query
// verification, unknown requests fail the test) through the real SDK sync
// loop on the Pebble engine, chaining each sync's c1z as the next sync's
// replay source. Timestamps follow the semantics probed live
// (docs/replay-probe-results.md): member add/remove and user deletion bump
// lastMembershipUpdated; profile changes bump only lastUpdated; user
// deactivation bumps neither and the user stays in the member listing.
//
// The paramount assertion is equivalence: after every warm sync a control
// sync (no previous c1z) runs against the same org state and the two must
// be identical at the v2 reader surface. Request-count ceilings assert the
// point of the exercise: clean groups spend ZERO member-listing requests.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/connectorclient"
	"github.com/conductorone/baton-sdk/pkg/dotc1z"
	"github.com/conductorone/baton-sdk/pkg/logging"
	"github.com/conductorone/baton-sdk/pkg/sourcecache"
	sdkSync "github.com/conductorone/baton-sdk/pkg/sync"
	"github.com/conductorone/baton-sdk/pkg/types"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// --- mock Okta org -----------------------------------------------------------

// mockPageSize forces pagination everywhere (groups listing, member
// listings) so multi-page scopes and the planner's cross-page SpawnCursors
// path are always exercised.
const mockPageSize = 2

var mockTimeBase = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// Test-local constants for repeated literals (keeps package-wide goconst
// counts at their pre-existing baseline).
const (
	mockStatusActive    = "ACTIVE"
	mockErrNotFound     = "E0000007"
	roleTypeUserAdmin   = "USER_ADMIN"
	roleTypeHelpDesk    = "HELP_DESK_ADMIN"
	roleLabelGroupAdmin = "Group Administrator"
	mockKeyStatus       = "status"
)

type mockOktaUser struct {
	ID        string
	FirstName string
	LastName  string
	Email     string
	Status    string // ACTIVE | DEPROVISIONED | ...
}

type mockOktaGroupRole struct {
	AssignmentID string
	Type         string // e.g. USER_ADMIN
	Label        string
}

type mockOktaGroup struct {
	ID          string
	Name        string
	Description string
	Type        string // OKTA_GROUP | APP_GROUP | BUILT_IN
	Members     []string
	Roles       []mockOktaGroupRole

	lastMembershipUpdated int64 // logical seconds since mockTimeBase
	lastUpdated           int64
}

type mockOkta struct {
	mu   sync.Mutex
	t    *testing.T
	base string // server URL, for Link headers

	clock int64

	users     map[string]*mockOktaUser
	userOrder []string

	groups     map[string]*mockOktaGroup
	groupOrder []string

	counts map[string]int
}

func newMockOkta(t *testing.T) *mockOkta {
	return &mockOkta{
		t:      t,
		users:  map[string]*mockOktaUser{},
		groups: map[string]*mockOktaGroup{},
		counts: map[string]int{},
	}
}

func (m *mockOkta) tick() int64 {
	m.clock++
	return m.clock
}

func mockTS(n int64) string {
	return mockTimeBase.Add(time.Duration(n) * time.Second).Format("2006-01-02T15:04:05.000Z")
}

func (m *mockOkta) addUser(u *mockOktaUser) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u.Status == "" {
		u.Status = mockStatusActive
	}
	m.users[u.ID] = u
	m.userOrder = append(m.userOrder, u.ID)
}

// deactivateUser flips the user's status. Probed live: the DEPROVISIONED
// user REMAINS in group member listings and no group timestamp bumps.
func (m *mockOkta) deactivateUser(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[id].Status = "DEPROVISIONED"
}

// deleteUser removes the user from the org and from every group's member
// list, bumping those groups' lastMembershipUpdated (probed live).
func (m *mockOkta) deleteUser(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.users, id)
	for i, uid := range m.userOrder {
		if uid == id {
			m.userOrder = append(m.userOrder[:i], m.userOrder[i+1:]...)
			break
		}
	}
	for _, g := range m.groups {
		for i, mid := range g.Members {
			if mid == id {
				g.Members = append(g.Members[:i], g.Members[i+1:]...)
				g.lastMembershipUpdated = m.tick()
				break
			}
		}
	}
}

func (m *mockOkta) addGroup(g *mockOktaGroup) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if g.Type == "" {
		g.Type = oktaGroupType
	}
	now := m.tick()
	g.lastMembershipUpdated = now
	g.lastUpdated = now
	m.groups[g.ID] = g
	m.groupOrder = append(m.groupOrder, g.ID)
}

func (m *mockOkta) deleteGroup(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.groups, id)
	for i, gid := range m.groupOrder {
		if gid == id {
			m.groupOrder = append(m.groupOrder[:i], m.groupOrder[i+1:]...)
			break
		}
	}
}

func (m *mockOkta) addMember(groupID, userID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g := m.groups[groupID]
	g.Members = append(g.Members, userID)
	g.lastMembershipUpdated = m.tick()
}

func (m *mockOkta) removeMember(groupID, userID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g := m.groups[groupID]
	for i, mid := range g.Members {
		if mid == userID {
			g.Members = append(g.Members[:i], g.Members[i+1:]...)
			g.lastMembershipUpdated = m.tick()
			return
		}
	}
	m.t.Fatalf("removeMember: %s not in %s", userID, groupID)
}

// touchGroup bumps lastMembershipUpdated without changing the member set —
// the validator-regression case (e.g. an add+remove that nets to zero, or
// a rule re-evaluation). The connector must re-enumerate and produce
// identical rows.
func (m *mockOkta) touchGroup(groupID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.groups[groupID].lastMembershipUpdated = m.tick()
}

// renameGroup bumps only lastUpdated (probed live): the member scope's
// validator must NOT rotate.
func (m *mockOkta) renameGroup(groupID, name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g := m.groups[groupID]
	g.Name = name
	g.lastUpdated = m.tick()
}

// assignGroupRole attaches an admin role to the group. Probed live: role
// assignment changes NEITHER group timestamp.
func (m *mockOkta) assignGroupRole(groupID string, role mockOktaGroupRole) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g := m.groups[groupID]
	g.Roles = append(g.Roles, role)
}

func (m *mockOkta) revokeGroupRole(groupID string, roleType string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g := m.groups[groupID]
	for i, r := range g.Roles {
		if r.Type == roleType {
			g.Roles = append(g.Roles[:i], g.Roles[i+1:]...)
			return
		}
	}
	m.t.Fatalf("revokeGroupRole: %s has no %s", groupID, roleType)
}

// snapshotCounts returns a copy of the request counters and resets them.
func (m *mockOkta) snapshotCounts() map[string]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]int{}
	for k, v := range m.counts {
		out[k] = v
	}
	m.counts = map[string]int{}
	return out
}

func (m *mockOkta) userJSON(u *mockOktaUser) map[string]any {
	return map[string]any{
		"id":          u.ID,
		mockKeyStatus: u.Status,
		"created":     mockTS(0),
		"lastUpdated": mockTS(0),
		"profile": map[string]any{
			"firstName": u.FirstName,
			"lastName":  u.LastName,
			"email":     u.Email,
			"login":     u.Email,
		},
	}
}

func (m *mockOkta) groupJSON(g *mockOktaGroup, withStats bool) map[string]any {
	obj := map[string]any{
		"id":                    g.ID,
		groupTypeProfileKey:     g.Type,
		"created":               mockTS(0),
		"lastUpdated":           mockTS(g.lastUpdated),
		"lastMembershipUpdated": mockTS(g.lastMembershipUpdated),
		"profile": map[string]any{
			"name":        g.Name,
			"description": g.Description,
		},
	}
	if withStats {
		obj["_embedded"] = map[string]any{
			"stats": map[string]any{
				"usersCount":             float64(len(g.Members)),
				"appsCount":              float64(0),
				"groupPushMappingsCount": float64(0),
			},
		}
	}
	return obj
}

// pageOf slices order after the given cursor. The cursor is the last id of
// the previous page (Okta's after-cursor is opaque; ids work fine).
func pageOf(order []string, after string, size int) ([]string, string) {
	start := 0
	if after != "" {
		for i, id := range order {
			if id == after {
				start = i + 1
				break
			}
		}
	}
	end := start + size
	if end >= len(order) {
		return order[start:], ""
	}
	return order[start:end], order[end-1]
}

func mockWriteJSON(w http.ResponseWriter, obj any) {
	w.Header().Set("Content-Type", "application/json")
	data, err := json.Marshal(obj)
	if err != nil {
		panic(err)
	}
	_, _ = w.Write(data)
}

// requireQueryKeys fails the test when the request carries query params
// outside the allowed set — the strict-mock discipline that catches scope
// signature drift and unexpected request shapes.
func (m *mockOkta) requireQueryKeys(r *http.Request, allowed ...string) {
	q := r.URL.Query()
	for k := range q {
		ok := false
		for _, a := range allowed {
			if k == a {
				ok = true
				break
			}
		}
		if !ok {
			m.t.Errorf("mock okta: unexpected query param %q on %s (allowed: %v)", k, r.URL.String(), allowed)
		}
	}
}

func (m *mockOkta) linkNext(w http.ResponseWriter, path string, next string) {
	if next == "" {
		return
	}
	w.Header().Set("Link", fmt.Sprintf("<%s%s?after=%s&limit=%d>; rel=\"next\"", m.base, path, url.QueryEscape(next), mockPageSize))
}

func (m *mockOkta) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()

		if r.Method != http.MethodGet {
			m.t.Errorf("mock okta: unexpected method %s %s", r.Method, r.URL.String())
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		path := r.URL.Path
		q := r.URL.Query()
		parts := strings.Split(strings.TrimPrefix(path, "/"), "/")

		switch {
		case path == "/api/v1/org":
			m.counts["org"]++
			mockWriteJSON(w, map[string]any{"id": "org1", "companyName": "Mock Org", "subdomain": "mock"})

		case path == "/api/v1/users":
			m.counts["users-list"]++
			m.requireQueryKeys(r, "limit", "after", "search")
			if q.Get("search") != "status pr" {
				m.t.Errorf("mock okta: users listing missing search=\"status pr\": %s", r.URL.String())
			}
			ids, next := pageOf(m.userOrder, q.Get("after"), mockPageSize)
			out := make([]map[string]any, 0, len(ids))
			for _, id := range ids {
				out = append(out, m.userJSON(m.users[id]))
			}
			m.linkNext(w, "/api/v1/users", next)
			mockWriteJSON(w, out)

		case path == "/api/v1/groups":
			m.counts["groups-list"]++
			m.requireQueryKeys(r, "limit", "after", "expand")
			if q.Get("expand") != "stats" {
				m.t.Errorf("mock okta: groups listing missing expand=stats: %s", r.URL.String())
			}
			ids, next := pageOf(m.groupOrder, q.Get("after"), mockPageSize)
			out := make([]map[string]any, 0, len(ids))
			for _, id := range ids {
				out = append(out, m.groupJSON(m.groups[id], true))
			}
			m.linkNext(w, "/api/v1/groups", next)
			mockWriteJSON(w, out)

		case len(parts) == 5 && parts[2] == "groups" && parts[4] == "users":
			gid := parts[3]
			m.counts["group-users:"+gid]++
			m.requireQueryKeys(r, "limit", "after")
			g, ok := m.groups[gid]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				mockWriteJSON(w, map[string]any{"errorCode": mockErrNotFound, "errorSummary": "Not found: " + gid})
				return
			}
			ids, next := pageOf(g.Members, q.Get("after"), mockPageSize)
			out := make([]map[string]any, 0, len(ids))
			for _, id := range ids {
				out = append(out, m.userJSON(m.users[id]))
			}
			m.linkNext(w, path, next)
			mockWriteJSON(w, out)

		case len(parts) == 5 && parts[2] == "groups" && parts[4] == "roles":
			gid := parts[3]
			m.counts["group-roles:"+gid]++
			m.requireQueryKeys(r)
			g, ok := m.groups[gid]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				mockWriteJSON(w, map[string]any{"errorCode": mockErrNotFound, "errorSummary": "Not found: " + gid})
				return
			}
			out := make([]map[string]any, 0, len(g.Roles))
			for _, role := range g.Roles {
				out = append(out, map[string]any{
					"id":                role.AssignmentID,
					groupTypeProfileKey: role.Type,
					"label":             role.Label,
					mockKeyStatus:       mockStatusActive,
					"assignmentType":    "GROUP",
				})
			}
			mockWriteJSON(w, out)

		case path == "/api/v1/iam/assignees/users":
			m.counts["role-assignees"]++
			mockWriteJSON(w, map[string]any{"value": []any{}})

		default:
			m.t.Errorf("mock okta: unexpected request %s %s", r.Method, r.URL.String())
			w.WriteHeader(http.StatusNotFound)
			mockWriteJSON(w, map[string]any{"errorCode": mockErrNotFound, "errorSummary": "unhandled: " + path})
		}
	}
}

// --- harness -----------------------------------------------------------------

var harnessSyncResourceTypes = []string{resourceTypeUser.Id, resourceTypeGroup.Id, resourceTypeRole.Id}

type syncHarness struct {
	t      *testing.T
	ctx    context.Context
	mock   *mockOkta
	cc     types.ConnectorClient
	tmpDir string
	syncN  int
}

func newSyncHarness(ctx context.Context, t *testing.T, mock *mockOkta) *syncHarness {
	t.Helper()

	server := httptest.NewServer(mock.handler())
	t.Cleanup(server.Close)
	mock.base = server.URL
	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	_, oktaClient, err := okta.NewClient(ctx,
		okta.WithOrgUrl(server.URL),
		okta.WithToken("test-token"),
		okta.WithTestingDisableHttpsCheck(true),
		okta.WithHttpClientPtr(server.Client()),
		okta.WithCache(false),
		okta.WithRateLimitMaxRetries(0),
	)
	require.NoError(t, err)

	c := &Okta{
		client:      oktaClient,
		domain:      serverURL.Host,
		apiToken:    "test-token",
		userFilters: &userFilterConfig{},
	}

	srv, err := connectorbuilder.NewConnector(ctx, c)
	require.NoError(t, err)

	// Serve the connector over local gRPC and talk to it through the real
	// connector client, mirroring how the CLI runs syncs.
	gs := grpc.NewServer()
	v2.RegisterConnectorServiceServer(gs, srv)
	v2.RegisterGrantsServiceServer(gs, srv)
	v2.RegisterEntitlementsServiceServer(gs, srv)
	v2.RegisterResourcesServiceServer(gs, srv)
	v2.RegisterResourceTypesServiceServer(gs, srv)
	v2.RegisterAssetServiceServer(gs, srv)
	v2.RegisterEventServiceServer(gs, srv)
	v2.RegisterResourceGetterServiceServer(gs, srv)
	v2.RegisterTicketsServiceServer(gs, srv)
	v2.RegisterActionServiceServer(gs, srv)
	v2.RegisterGrantManagerServiceServer(gs, srv)
	v2.RegisterResourceManagerServiceServer(gs, srv)
	v2.RegisterResourceDeleterServiceServer(gs, srv)
	v2.RegisterAccountManagerServiceServer(gs, srv)
	v2.RegisterCredentialManagerServiceServer(gs, srv)

	lis, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test-scoped loopback listener
	require.NoError(t, err)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	cc := connectorclient.NewConnectorClient(ctx, conn)

	// In-process lookup delivery: the syncer installs its per-sync lookup on
	// the client, which forwards it to the builder (the CLI wrapper does
	// this same wiring in internal/connector).
	setter, ok := cc.(interface {
		SetSourceCacheSetter(sourcecache.SetLookup)
	})
	require.True(t, ok, "connector client must accept a source-cache setter")
	lookupSink, ok := srv.(sourcecache.SetLookup)
	require.True(t, ok, "connectorbuilder server must implement sourcecache.SetLookup")
	setter.SetSourceCacheSetter(lookupSink)

	return &syncHarness{t: t, ctx: ctx, mock: mock, cc: cc, tmpDir: t.TempDir()}
}

// runSync executes one full sync into a fresh Pebble c1z, optionally
// replaying from prevPath. Returns the new file's path.
func (h *syncHarness) runSync(name string, prevPath string) string {
	h.t.Helper()
	h.syncN++
	path := filepath.Join(h.tmpDir, fmt.Sprintf("%02d-%s.c1z", h.syncN, name))

	store, err := dotc1z.NewStore(h.ctx, path,
		dotc1z.WithEngine(dotc1z.EnginePebble),
		dotc1z.WithTmpDir(h.tmpDir),
	)
	require.NoError(h.t, err)

	opts := []sdkSync.SyncOpt{
		sdkSync.WithConnectorStore(store),
		sdkSync.WithTmpDir(h.tmpDir),
		sdkSync.WithSyncResourceTypes(harnessSyncResourceTypes),
	}
	if prevPath != "" {
		opts = append(opts, sdkSync.WithPreviousSyncC1ZPath(prevPath))
	}

	syncer, err := sdkSync.NewSyncer(h.ctx, h.cc, opts...)
	require.NoError(h.t, err)
	require.NoError(h.t, syncer.Sync(h.ctx))
	require.NoError(h.t, syncer.Close(h.ctx))
	return path
}

// runControlSync runs an uncached control sync and discards its request
// counts, so the next scenario's counters see only its own warm sync.
func (h *syncHarness) runControlSync(name string) string {
	h.t.Helper()
	path := h.runSync(name, "")
	h.mock.snapshotCounts()
	return path
}

// snapshot reads a finished c1z at the v2 reader surface and returns
// id → canonical JSON for resources, entitlements, and grants.
func (h *syncHarness) snapshot(path string) map[string]string {
	h.t.Helper()
	store, err := dotc1z.NewStore(h.ctx, path,
		dotc1z.WithEngine(dotc1z.EnginePebble),
		dotc1z.WithReadOnly(true),
		dotc1z.WithTmpDir(h.tmpDir),
	)
	require.NoError(h.t, err)
	defer func() { _ = store.Close(h.ctx) }()

	latest, err := store.SyncMeta().LatestFullSync(h.ctx)
	require.NoError(h.t, err)
	require.NotNil(h.t, latest)
	require.NoError(h.t, store.SetCurrentSync(h.ctx, latest.ID))

	out := map[string]string{}
	put := func(prefix, id string, msg proto.Message) {
		jb, err := protojson.Marshal(msg)
		require.NoError(h.t, err)
		// protojson output spacing is deliberately unstable; re-marshal
		// through encoding/json for canonical (sorted-key) bytes.
		var v any
		require.NoError(h.t, json.Unmarshal(jb, &v))
		cb, err := json.Marshal(v)
		require.NoError(h.t, err)
		key := prefix + ":" + id
		require.NotContains(h.t, out, key, "duplicate id at reader surface")
		out[key] = string(cb)
	}

	for _, rt := range harnessSyncResourceTypes {
		pageToken := ""
		for {
			resp, err := store.ListResources(h.ctx, v2.ResourcesServiceListResourcesRequest_builder{
				ResourceTypeId: rt,
				PageToken:      pageToken,
			}.Build())
			require.NoError(h.t, err)
			for _, r := range resp.GetList() {
				put("resource", r.GetId().GetResourceType()+"/"+r.GetId().GetResource(), r)
			}
			pageToken = resp.GetNextPageToken()
			if pageToken == "" {
				break
			}
		}
	}

	pageToken := ""
	for {
		resp, err := store.ListEntitlements(h.ctx, v2.EntitlementsServiceListEntitlementsRequest_builder{
			PageToken: pageToken,
		}.Build())
		require.NoError(h.t, err)
		for _, e := range resp.GetList() {
			put("entitlement", e.GetId(), e)
		}
		pageToken = resp.GetNextPageToken()
		if pageToken == "" {
			break
		}
	}

	pageToken = ""
	for {
		resp, err := store.ListGrants(h.ctx, v2.GrantsServiceListGrantsRequest_builder{
			PageToken: pageToken,
		}.Build())
		require.NoError(h.t, err)
		for _, g := range resp.GetList() {
			put("grant", g.GetId(), g)
		}
		pageToken = resp.GetNextPageToken()
		if pageToken == "" {
			break
		}
	}

	return out
}

// requireEquivalent is the release-blocker check: a warm (replayed) sync
// must be byte-identical to an uncached control sync at the reader surface.
func (h *syncHarness) requireEquivalent(warmPath, controlPath string, scenario string) {
	h.t.Helper()
	warm := h.snapshot(warmPath)
	control := h.snapshot(controlPath)
	require.Equal(h.t, control, warm,
		"%s: warm sync diverged from uncached control sync — replay equivalence violated", scenario)
}

// memberListingCalls sums group-users request counts, keyed per group.
func memberListingCalls(counts map[string]int) map[string]int {
	out := map[string]int{}
	for k, v := range counts {
		if gid, ok := strings.CutPrefix(k, "group-users:"); ok {
			out[gid] = v
		}
	}
	return out
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func memberGrantID(groupID, userID string) string {
	return fmt.Sprintf("group:%s:member:user:%s", groupID, userID)
}

func roleGroupGrantID(roleType, groupID string) string {
	return fmt.Sprintf("role:%s:assigned:group:%s", roleType, groupID)
}

// --- the scenarios -----------------------------------------------------------

func TestSourceCacheReplayEndToEnd(t *testing.T) {
	ctx, err := logging.Init(t.Context())
	require.NoError(t, err)

	mock := newMockOkta(t)

	// Org: five users; g1 (3 members, paginates at mockPageSize=2, carries
	// an admin role for the always-fresh roles leg + grant expansion),
	// g2 (1 member), g3 (empty — exercises the users_count==0 skip).
	for i := 1; i <= 5; i++ {
		mock.addUser(&mockOktaUser{
			ID:        fmt.Sprintf("u%d", i),
			FirstName: "Member",
			LastName:  fmt.Sprintf("Number%d", i),
			Email:     fmt.Sprintf("u%d@x.test", i),
		})
	}
	mock.addGroup(&mockOktaGroup{ID: "g1", Name: "Engineering", Members: []string{"u1", "u2", "u3"}})
	mock.addGroup(&mockOktaGroup{ID: "g2", Name: "Sales", Members: []string{"u4"}})
	mock.addGroup(&mockOktaGroup{ID: "g3", Name: "Empty"})
	mock.assignGroupRole("g1", mockOktaGroupRole{AssignmentID: "gra1", Type: roleTypeUserAdmin, Label: roleLabelGroupAdmin})

	h := newSyncHarness(ctx, t, mock)

	// --- Sync 1: cold ---------------------------------------------------------
	sync1 := h.runSync("cold", "")
	c1 := mock.snapshotCounts()
	mc1 := memberListingCalls(c1)
	require.Equal(t, 2, mc1["g1"], "3 members at page size 2 = 2 requests")
	require.Equal(t, 1, mc1["g2"])
	require.Zero(t, mc1["g3"], "users_count==0 skips the member listing even cold")
	require.Equal(t, 1, c1["group-roles:g1"], "roles leg runs once per group")
	require.Equal(t, 1, c1["group-roles:g2"])
	require.Equal(t, 1, c1["group-roles:g3"])

	snap1 := h.snapshot(sync1)
	require.Contains(t, snap1, "resource:user/u1")
	require.Contains(t, snap1, "resource:group/g1")
	require.Contains(t, snap1, "resource:group/g3")
	require.Contains(t, snap1, "grant:"+memberGrantID("g1", "u1"))
	require.Contains(t, snap1, "grant:"+memberGrantID("g1", "u3"))
	require.Contains(t, snap1, "grant:"+memberGrantID("g2", "u4"))
	require.Contains(t, snap1, "grant:"+roleGroupGrantID(roleTypeUserAdmin, "g1"), "group role grant from the fresh roles leg")
	// Grant expansion: g1's members must hold derived USER_ADMIN grants.
	foundDerived := false
	for k := range snap1 {
		if strings.HasPrefix(k, "grant:role:USER_ADMIN:assigned:user:u1") {
			foundDerived = true
		}
	}
	require.True(t, foundDerived, "expansion must derive u1's USER_ADMIN grant via g1")

	// --- Scenario 1: no-op round ----------------------------------------------
	sync2 := h.runSync("noop", sync1)
	c2 := mock.snapshotCounts()
	mc2 := memberListingCalls(c2)
	require.Empty(t, sortedKeys(mc2), "no-op warm sync must spend ZERO member-listing requests, got %v", mc2)
	require.Equal(t, 1, c2["group-roles:g1"], "roles leg stays fresh on warm rounds")
	control2 := h.runControlSync("noop-control")
	h.requireEquivalent(sync2, control2, "no-op round")

	// --- Scenario 2: member ADD -----------------------------------------------
	mock.addMember("g2", "u5")
	sync3 := h.runSync("add", sync2)
	mc3 := memberListingCalls(mock.snapshotCounts())
	require.Equal(t, []string{"g2"}, sortedKeys(mc3), "only the dirty group re-enumerates, got %v", mc3)
	require.Contains(t, h.snapshot(sync3), "grant:"+memberGrantID("g2", "u5"))
	control3 := h.runControlSync("add-control")
	h.requireEquivalent(sync3, control3, "member add")

	// --- Scenario 3: member REMOVE (the model-critical direction) --------------
	mock.removeMember("g1", "u2")
	sync4 := h.runSync("remove", sync3)
	mc4 := memberListingCalls(mock.snapshotCounts())
	require.Equal(t, []string{"g1"}, sortedKeys(mc4), "only the dirty group re-enumerates, got %v", mc4)
	snap4 := h.snapshot(sync4)
	require.NotContains(t, snap4, "grant:"+memberGrantID("g1", "u2"), "revoked membership must disappear from the warm sync")
	require.Contains(t, snap4, "grant:"+memberGrantID("g1", "u1"))
	control4 := h.runControlSync("remove-control")
	h.requireEquivalent(sync4, control4, "member remove")

	// --- Scenario 4: empty group gains its first member ------------------------
	mock.addMember("g3", "u2")
	sync5 := h.runSync("empty-fill", sync4)
	mc5 := memberListingCalls(mock.snapshotCounts())
	require.Equal(t, []string{"g3"}, sortedKeys(mc5), "formerly-empty dirty group must enumerate, got %v", mc5)
	require.Contains(t, h.snapshot(sync5), "grant:"+memberGrantID("g3", "u2"))
	control5 := h.runControlSync("empty-fill-control")
	h.requireEquivalent(sync5, control5, "empty group fill")

	// --- Scenario 5: group create + delete -------------------------------------
	mock.addGroup(&mockOktaGroup{ID: "g4", Name: "Newcomers", Members: []string{"u5"}})
	sync6 := h.runSync("create", sync5)
	mc6 := memberListingCalls(mock.snapshotCounts())
	require.Equal(t, []string{"g4"}, sortedKeys(mc6), "only the new group enumerates, got %v", mc6)
	require.Contains(t, h.snapshot(sync6), "grant:"+memberGrantID("g4", "u5"))
	control6 := h.runControlSync("create-control")
	h.requireEquivalent(sync6, control6, "group create")

	mock.deleteGroup("g4")
	sync7 := h.runSync("delete", sync6)
	mc7 := memberListingCalls(mock.snapshotCounts())
	require.Empty(t, sortedKeys(mc7), "deleting a group must not dirty the others, got %v", mc7)
	snap7 := h.snapshot(sync7)
	require.NotContains(t, snap7, "resource:group/g4")
	require.NotContains(t, snap7, "grant:"+memberGrantID("g4", "u5"))
	control7 := h.runControlSync("delete-control")
	h.requireEquivalent(sync7, control7, "group delete")

	// --- Scenario 6: validator regression (bump without member change) ---------
	mock.touchGroup("g2")
	sync8 := h.runSync("touch", sync7)
	mc8 := memberListingCalls(mock.snapshotCounts())
	require.Equal(t, []string{"g2"}, sortedKeys(mc8), "touched group re-enumerates (fails toward cold), got %v", mc8)
	control8 := h.runControlSync("touch-control")
	h.requireEquivalent(sync8, control8, "validator regression")

	// --- Scenario 7: profile rename must NOT rotate the member validator -------
	mock.renameGroup("g1", "Engineering Platform")
	sync9 := h.runSync("rename", sync8)
	mc9 := memberListingCalls(mock.snapshotCounts())
	require.Empty(t, sortedKeys(mc9), "profile change must not dirty the member scope, got %v", mc9)
	snap9 := h.snapshot(sync9)
	require.Contains(t, snap9["resource:group/g1"], "Engineering Platform", "rename lands via the resources phase")
	control9 := h.runControlSync("rename-control")
	h.requireEquivalent(sync9, control9, "group rename")

	// --- Scenario 8: user deactivation (member stays; probed live) -------------
	mock.deactivateUser("u4")
	sync10 := h.runSync("deactivate", sync9)
	mc10 := memberListingCalls(mock.snapshotCounts())
	require.Empty(t, sortedKeys(mc10), "deactivation bumps no group timestamp; replay must hold, got %v", mc10)
	snap10 := h.snapshot(sync10)
	require.Contains(t, snap10, "grant:"+memberGrantID("g2", "u4"), "deprovisioned member remains in the listing (probed) — grant stays")
	control10 := h.runControlSync("deactivate-control")
	h.requireEquivalent(sync10, control10, "user deactivation")

	// --- Scenario 9: user DELETION (removes membership + bumps; probed live) ---
	mock.deleteUser("u4")
	sync11 := h.runSync("user-delete", sync10)
	mc11 := memberListingCalls(mock.snapshotCounts())
	require.Equal(t, []string{"g2"}, sortedKeys(mc11), "user deletion dirties exactly the groups they belonged to, got %v", mc11)
	snap11 := h.snapshot(sync11)
	require.NotContains(t, snap11, "resource:user/u4")
	require.NotContains(t, snap11, "grant:"+memberGrantID("g2", "u4"))
	control11 := h.runControlSync("user-delete-control")
	h.requireEquivalent(sync11, control11, "user deletion")

	// --- Scenario 10: role assignment changes ride the fresh leg ---------------
	mock.assignGroupRole("g2", mockOktaGroupRole{AssignmentID: "gra2", Type: roleTypeHelpDesk, Label: "Help Desk Administrator"})
	sync12 := h.runSync("role-assign", sync11)
	mc12 := memberListingCalls(mock.snapshotCounts())
	require.Empty(t, sortedKeys(mc12), "role assignment must not dirty the member scope, got %v", mc12)
	require.Contains(t, h.snapshot(sync12), "grant:"+roleGroupGrantID(roleTypeHelpDesk, "g2"), "new role grant arrives on a fully-warm round via the fresh leg")
	control12 := h.runControlSync("role-assign-control")
	h.requireEquivalent(sync12, control12, "group role assignment")

	mock.revokeGroupRole("g2", roleTypeHelpDesk)
	sync13 := h.runSync("role-revoke", sync12)
	require.NotContains(t, h.snapshot(sync13), "grant:"+roleGroupGrantID(roleTypeHelpDesk, "g2"))
	control13 := h.runControlSync("role-revoke-control")
	h.requireEquivalent(sync13, control13, "group role revocation")

	// --- Scenario 11: mass invalidation + recovery ------------------------------
	for _, gid := range []string{"g1", "g2", "g3"} {
		mock.touchGroup(gid)
	}
	sync14 := h.runSync("mass-invalidation", sync13)
	mc14 := memberListingCalls(mock.snapshotCounts())
	// g3 gained u2 in scenario 4, so all three groups are non-empty here.
	require.Equal(t, []string{"g1", "g2", "g3"}, sortedKeys(mc14), "every non-empty group re-enumerates, got %v", mc14)
	control14 := h.runControlSync("mass-invalidation-control")
	h.requireEquivalent(sync14, control14, "mass invalidation")

	sync15 := h.runSync("recovery", sync14)
	mc15 := memberListingCalls(mock.snapshotCounts())
	require.Empty(t, sortedKeys(mc15), "the round after mass invalidation must be fully warm again, got %v", mc15)
	control15 := h.runControlSync("recovery-control")
	h.requireEquivalent(sync15, control15, "post-invalidation recovery")
}
