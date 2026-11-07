package connector_test

// Black-box regression harness. Every test in this package drives the connector
// only through its public surface -- connector.New and the baton-sdk
// ConnectorServer built from it -- against a fake Okta org served over TLS.
// Each test records the connector's responses and every HTTP request the
// connector sent, and compares the pair against a golden file in
// testdata/golden. Regenerate goldens with:
//
//	go test ./pkg/connector/ -run 'TestBlackbox' -update
//
// The goldens are the behavioral contract: a change that alters what the
// connector emits or what it sends to Okta shows up as a golden diff.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	cfg "github.com/conductorone/baton-okta/pkg/config"
	"github.com/conductorone/baton-okta/pkg/connector"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/cli"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/types"
	"github.com/conductorone/baton-sdk/pkg/types/sessions"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

var updateGolden = flag.Bool("update", false, "rewrite blackbox golden files")

const (
	testAPIToken = "test-api-token-0123456789" //nolint:gosec // fake credential for the fake org
	// fakeHost replaces the httptest listener address everywhere it appears in
	// recorded output, so goldens do not depend on the ephemeral port.
	fakeHost = "okta.test"
	// Fixed rate-limit headers stamped on every fake response unless a handler
	// overrides them.
	rlLimit     = "600"
	rlRemaining = "599"
	rlReset     = "1767225600" // 2026-01-01T00:00:00Z
)

// tlsCertFile holds the PEM of httptest's built-in certificate. TestMain points
// SSL_CERT_FILE at it before anything loads the system roots, so the
// connector's own HTTP client (built inside connector.New) trusts the fake org
// without any test-only hook in production code.
func TestMain(m *testing.M) {
	flag.Parse()
	startAppsProxy()
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	cert := srv.Certificate()
	srv.Close()

	dir, err := os.MkdirTemp("", "baton-okta-blackbox")
	if err != nil {
		panic(err)
	}
	certPath := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600); err != nil {
		panic(err)
	}
	_ = os.Setenv("SSL_CERT_FILE", certPath)
	_ = os.Setenv("SSL_CERT_DIR", dir)
	// The baton-sdk HTTP response cache would otherwise sit in front of the fake
	// org and hide repeated requests from the recorder.
	_ = os.Setenv("BATON_DISABLE_HTTP_CACHE", "true")

	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// ---------------------------------------------------------------------------
// Fake Okta org
// ---------------------------------------------------------------------------

// recordedRequest is one HTTP request the connector sent, reduced to the
// fields that define the request shape.
type recordedRequest struct {
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Query   map[string][]string `json:"query,omitempty"`
	Headers map[string]string   `json:"headers,omitempty"`
	Body    any                 `json:"body,omitempty"`
}

// recordedHeaders are the request headers pinned by the goldens. User-Agent is
// deliberately absent: it carries the Go version and platform.
var recordedHeaders = []string{
	"Accept",
	"Authorization",
	"Content-Type",
	"X-Okta-Retry-Count",
	"X-Okta-Retry-For",
}

type route struct {
	method  string
	pattern *regexp.Regexp
	handler func(w http.ResponseWriter, r *http.Request, m []string)
}

// fakeOkta is an httptest TLS server with a regexp route table. Unmatched
// requests get Okta's 404 body so a missing route is visible in the golden.
type fakeOkta struct {
	t      *testing.T
	srv    *httptest.Server
	mu     sync.Mutex
	routes []route
	reqs   []recordedRequest
	// skipRecord hides requests (e.g. token exchange) whose shape is pinned elsewhere.
	skipRecord func(r *http.Request) bool
}

func newFakeOkta(t *testing.T) *fakeOkta {
	t.Helper()
	f := &fakeOkta{t: t}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// Host is the host:port the connector is configured with.
func (f *fakeOkta) Host() string { return strings.TrimPrefix(f.srv.URL, "https://") }

// URL returns an absolute URL on the fake org (used to build Link headers).
func (f *fakeOkta) URL(pathAndQuery string) string { return f.srv.URL + pathAndQuery }

// Handle registers a handler for METHOD + a path regexp anchored at both ends.
// Later registrations win, so a test can override a default route.
func (f *fakeOkta) Handle(method, pathPattern string, h func(w http.ResponseWriter, r *http.Request, m []string)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes = append([]route{{method: method, pattern: regexp.MustCompile("^" + pathPattern + "$"), handler: h}}, f.routes...)
}

// JSON registers a route that always returns status + body.
func (f *fakeOkta) JSON(method, pathPattern string, status int, body string) {
	f.Handle(method, pathPattern, func(w http.ResponseWriter, r *http.Request, _ []string) {
		writeJSON(w, status, body)
	})
}

// Fixture registers a 200 route returning testdata/okta/<name>.
func (f *fakeOkta) Fixture(method, pathPattern, name string) {
	body := fixture(f.t, name)
	f.JSON(method, pathPattern, http.StatusOK, body)
}

// Pages registers a GET route that serves the given bodies as successive pages
// keyed by the "after" query parameter: page i>0 is served for after=cursor<i>,
// and every page except the last carries a rel="next" Link with the next cursor.
// Okta echoes the request's other query parameters into the next link.
func (f *fakeOkta) Pages(pathPattern string, bodies ...string) {
	f.Handle(http.MethodGet, pathPattern, func(w http.ResponseWriter, r *http.Request, _ []string) {
		idx := 0
		if after := r.URL.Query().Get("after"); after != "" {
			n, err := strconv.Atoi(strings.TrimPrefix(after, "cursor"))
			if err != nil || n <= 0 || n >= len(bodies) {
				writeJSON(w, http.StatusBadRequest, `{"errorCode":"E0000001","errorSummary":"Api validation failed: after","errorLink":"E0000001","errorId":"oaeBadCursor","errorCauses":[]}`)
				return
			}
			idx = n
		}
		self := *r.URL
		links := []string{fmt.Sprintf(`<%s>; rel="self"`, f.URL(self.RequestURI()))}
		if idx+1 < len(bodies) {
			next := *r.URL
			q := next.Query()
			q.Set("after", fmt.Sprintf("cursor%d", idx+1))
			next.RawQuery = q.Encode()
			links = append(links, fmt.Sprintf(`<%s>; rel="next"`, f.URL(next.RequestURI())))
		}
		for _, l := range links {
			w.Header().Add("Link", l)
		}
		writeJSON(w, http.StatusOK, bodies[idx])
	})
}

// FixturePages is Pages with bodies loaded from testdata/okta.
func (f *fakeOkta) FixturePages(pathPattern string, names ...string) {
	bodies := make([]string, len(names))
	for i, n := range names {
		bodies[i] = fixture(f.t, n)
	}
	f.Pages(pathPattern, bodies...)
}

func (f *fakeOkta) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))

	if f.skipRecord == nil || !f.skipRecord(r) {
		f.record(r, body)
	}

	w.Header().Set("X-Rate-Limit-Limit", rlLimit)
	w.Header().Set("X-Rate-Limit-Remaining", rlRemaining)
	w.Header().Set("X-Rate-Limit-Reset", rlReset)
	w.Header().Set("X-Okta-Request-Id", "req-"+strconv.Itoa(f.count()))

	f.mu.Lock()
	routes := append([]route(nil), f.routes...)
	f.mu.Unlock()
	for _, rt := range routes {
		if rt.method != r.Method {
			continue
		}
		if m := rt.pattern.FindStringSubmatch(r.URL.Path); m != nil {
			rt.handler(w, r, m)
			return
		}
	}
	writeJSON(w, http.StatusNotFound, fmt.Sprintf(
		`{"errorCode":"E0000007","errorSummary":"Not found: Resource not found: %s (%s)","errorLink":"E0000007","errorId":"oaeUnrouted","errorCauses":[]}`,
		r.URL.Path, r.Method))
}

func (f *fakeOkta) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reqs)
}

func (f *fakeOkta) record(r *http.Request, body []byte) {
	rec := recordedRequest{Method: r.Method, Path: r.URL.Path}
	if q := r.URL.Query(); len(q) > 0 {
		rec.Query = map[string][]string(q)
	}
	for _, h := range recordedHeaders {
		if v := r.Header.Get(h); v != "" {
			if rec.Headers == nil {
				rec.Headers = map[string]string{}
			}
			rec.Headers[h] = v
		}
	}
	if r.Header.Get("DPoP") != "" {
		if rec.Headers == nil {
			rec.Headers = map[string]string{}
		}
		rec.Headers["DPoP"] = "<proof>"
	}
	if len(body) > 0 {
		var v any
		if err := json.Unmarshal(body, &v); err == nil {
			rec.Body = scrubBody(v)
		} else {
			rec.Body = string(body)
		}
	}
	f.mu.Lock()
	f.reqs = append(f.reqs, rec)
	f.mu.Unlock()
}

// Requests returns the requests recorded so far.
func (f *fakeOkta) Requests() []recordedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedRequest(nil), f.reqs...)
}

// scrubBody replaces the volatile parts of request bodies the connector
// generates: wall-clock timestamps and random passwords.
func scrubBody(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if k == "password" {
				if m, ok := val.(map[string]any); ok {
					if _, has := m["value"]; has {
						m["value"] = "<random>"
					}
				}
			}
			if s, ok := val.(string); ok && looksLikeNow(s) {
				t[k] = "<now>"
				continue
			}
			t[k] = scrubBody(val)
		}
		return t
	case []any:
		for i := range t {
			t[i] = scrubBody(t[i])
		}
		return t
	default:
		return v
	}
}

func looksLikeNow(s string) bool {
	ts, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return false
	}
	d := time.Since(ts)
	return d > -time.Hour && d < time.Hour
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body) //nolint:gosec // test fixture bodies, served as JSON
}

// fixture reads testdata/okta/<name>.
func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "okta", name))
	require.NoError(t, err, "fixture %s", name)
	return string(b)
}

// ---------------------------------------------------------------------------
// Connector construction
// ---------------------------------------------------------------------------

type connOpts struct {
	conf *cfg.Okta
	opts *cli.ConnectorOpts
}

type connOpt func(*connOpts)

func withConfig(mod func(c *cfg.Okta)) connOpt { return func(o *connOpts) { mod(o.conf) } }

func withCLIOpts(opts *cli.ConnectorOpts) connOpt { return func(o *connOpts) { o.opts = opts } }

// defaultConfig mirrors the CLI defaults for every field the connector reads.
func defaultConfig(host string) *cfg.Okta {
	return &cfg.Okta{
		Domain:   host,
		ApiToken: testAPIToken,
		Cache:    true,
		CacheTti: 60,
		CacheTtl: 300,
	}
}

// newServer builds the connector exactly as the CLI does (connector.New) and
// wraps it in the baton-sdk ConnectorServer the sync engine talks to.
func newServer(t *testing.T, f *fakeOkta, mods ...connOpt) types.ConnectorServer {
	t.Helper()
	ctx := context.Background()
	o := &connOpts{conf: defaultConfig(f.Host())}
	for _, m := range mods {
		m(o)
	}
	builder, _, err := connector.New(ctx, o.conf, o.opts)
	require.NoError(t, err)
	srv, err := connectorbuilder.NewConnector(ctx, builder, connectorbuilder.WithSessionStore(newMemSessions()))
	require.NoError(t, err)
	return srv
}

// privateKeyConn configures the OAuth 2.0 private-key (DPoP) auth mode and
// installs a token endpoint on the fake org.
func privateKeyConn(t *testing.T, f *fakeOkta) connOpt {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))

	f.Handle(http.MethodPost, "/oauth2/v1/token", func(w http.ResponseWriter, r *http.Request, _ []string) {
		writeJSON(w, http.StatusOK, `{"access_token":"dpop-access-token","token_type":"DPoP","expires_in":3600,"scope":"okta.users.read"}`)
	})
	f.skipRecord = func(r *http.Request) bool { return r.URL.Path == "/oauth2/v1/token" }

	return func(o *connOpts) {
		o.conf.ApiToken = ""
		o.conf.OktaClientId = "0oaclient123"
		o.conf.OktaPrivateKey = pemKey
		o.conf.OktaPrivateKeyId = "kid-1"
		if o.opts == nil {
			o.opts = &cli.ConnectorOpts{}
		}
		o.opts.SelectedAuthMethod = cfg.PrivateKeyGroup
	}
}

// memSessions is a minimal in-memory sessions.SessionStore.
type memSessions struct {
	mu sync.Mutex
	m  map[string][]byte
}

func newMemSessions() *memSessions { return &memSessions{m: map[string][]byte{}} }

func bagKey(ctx context.Context, key string, opt []sessions.SessionStoreOption) string {
	bag := &sessions.SessionStoreBag{}
	for _, o := range opt {
		_ = o(ctx, bag)
	}
	return bag.SyncID + "|" + bag.Prefix + key
}

func (s *memSessions) Get(ctx context.Context, key string, opt ...sessions.SessionStoreOption) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[bagKey(ctx, key, opt)]
	return v, ok, nil
}

func (s *memSessions) GetMany(ctx context.Context, keys []string, opt ...sessions.SessionStoreOption) (map[string][]byte, []string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string][]byte{}
	var missing []string
	for _, k := range keys {
		if v, ok := s.m[bagKey(ctx, k, opt)]; ok {
			out[k] = v
		} else {
			missing = append(missing, k)
		}
	}
	return out, missing, nil
}

func (s *memSessions) Set(ctx context.Context, key string, value []byte, opt ...sessions.SessionStoreOption) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[bagKey(ctx, key, opt)] = value
	return nil
}

func (s *memSessions) SetMany(ctx context.Context, values map[string][]byte, opt ...sessions.SessionStoreOption) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range values {
		s.m[bagKey(ctx, k, opt)] = v
	}
	return nil
}

func (s *memSessions) Delete(ctx context.Context, key string, opt ...sessions.SessionStoreOption) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, bagKey(ctx, key, opt))
	return nil
}

func (s *memSessions) Clear(ctx context.Context, opt ...sessions.SessionStoreOption) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m = map[string][]byte{}
	return nil
}

func (s *memSessions) GetAll(ctx context.Context, pageToken string, opt ...sessions.SessionStoreOption) (map[string][]byte, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prefix := bagKey(ctx, "", opt)
	out := map[string][]byte{}
	for k, v := range s.m {
		if strings.HasPrefix(k, prefix) {
			out[strings.TrimPrefix(k, prefix)] = v
		}
	}
	return out, "", nil
}

// ---------------------------------------------------------------------------
// Golden recording
// ---------------------------------------------------------------------------

type goldenStep struct {
	Name     string          `json:"name"`
	Response json.RawMessage `json:"response,omitempty"`
	Error    *goldenError    `json:"error,omitempty"`
}

type goldenError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type goldenFile struct {
	Steps    []goldenStep      `json:"steps"`
	Requests []recordedRequest `json:"requests"`
}

// golden accumulates connector outputs for one test.
type golden struct {
	t     *testing.T
	f     *fakeOkta
	steps []goldenStep
}

func newGolden(t *testing.T, f *fakeOkta) *golden { return &golden{t: t, f: f} }

// Step records one connector call's outcome.
func (g *golden) Step(name string, resp proto.Message, err error) {
	g.t.Helper()
	st := goldenStep{Name: name}
	if err != nil {
		s, _ := status.FromError(err)
		st.Error = &goldenError{Code: s.Code().String(), Message: g.normalize(err.Error())}
	} else if resp != nil {
		raw, mErr := protojson.MarshalOptions{UseProtoNames: true}.Marshal(resp)
		require.NoError(g.t, mErr)
		st.Response = json.RawMessage(g.normalize(string(dropSessionUsage(raw))))
	}
	g.steps = append(g.steps, st)
}

func (g *golden) normalize(s string) string {
	return strings.ReplaceAll(s, g.f.Host(), fakeHost)
}

// Check compares (or with -update writes) testdata/golden/<TestName>.json.
func (g *golden) Check() {
	g.t.Helper()
	reqs := g.f.Requests()
	for i := range reqs {
		b, _ := json.Marshal(reqs[i])
		_ = json.Unmarshal([]byte(g.normalize(string(b))), &reqs[i])
	}
	out, err := canonicalJSON(goldenFile{Steps: g.steps, Requests: reqs})
	require.NoError(g.t, err)

	name := strings.NewReplacer("/", "__", " ", "_").Replace(g.t.Name())
	path := filepath.Join("testdata", "golden", name+".json")
	if *updateGolden {
		require.NoError(g.t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(g.t, os.WriteFile(path, out, 0o600))
		return
	}
	want, err := os.ReadFile(path)
	require.NoError(g.t, err, "missing golden %s; run with -update", path)
	require.Equal(g.t, string(want), string(out), "golden mismatch for %s", path)
}

// dropSessionUsage removes SessionUsage entries from every "annotations" array.
func dropSessionUsage(raw []byte) []byte {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw
	}
	var walk func(any) any
	walk = func(x any) any {
		switch t := x.(type) {
		case map[string]any:
			for k, val := range t {
				if k == "annotations" {
					if arr, ok := val.([]any); ok {
						kept := []any{}
						for _, a := range arr {
							if m, ok := a.(map[string]any); ok {
								if typ, _ := m["@type"].(string); strings.Contains(typ, "SessionUsage") {
									continue
								}
							}
							kept = append(kept, walk(a))
						}
						if len(kept) == 0 {
							delete(t, k)
						} else {
							t[k] = kept
						}
						continue
					}
				}
				t[k] = walk(val)
			}
			return t
		case []any:
			for i := range t {
				t[i] = walk(t[i])
			}
			return t
		}
		return x
	}
	out, err := json.Marshal(walk(v))
	if err != nil {
		return raw
	}
	return out
}

// canonicalJSON re-encodes through map[string]any so key order is sorted and
// protojson's deliberately unstable whitespace never reaches the golden.
func canonicalJSON(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var generic any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&generic); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(generic); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ---------------------------------------------------------------------------
// Sync helpers
// ---------------------------------------------------------------------------

const testSyncID = "sync-blackbox"

// listAllResources pages ListResources to exhaustion, recording each page.
func listAllResources(t *testing.T, g *golden, srv types.ConnectorServer, rtID string, parent *v2.ResourceId, pageSize uint32) []*v2.Resource {
	t.Helper()
	ctx := context.Background()
	var all []*v2.Resource
	token := ""
	for page := 1; page <= 50; page++ {
		resp, err := srv.ListResources(ctx, &v2.ResourcesServiceListResourcesRequest{
			ResourceTypeId:   rtID,
			ParentResourceId: parent,
			PageSize:         pageSize,
			PageToken:        token,
			ActiveSyncId:     testSyncID,
		})
		g.Step(fmt.Sprintf("ListResources %s page %d", rtID, page), stripSessionUsage(resp), err)
		if err != nil {
			return all
		}
		all = append(all, resp.GetList()...)
		token = resp.GetNextPageToken()
		if token == "" {
			return all
		}
	}
	t.Fatalf("ListResources %s did not terminate", rtID)
	return nil
}

// listAllEntitlements pages ListEntitlements for one resource.
func listAllEntitlements(t *testing.T, g *golden, srv types.ConnectorServer, res *v2.Resource) []*v2.Entitlement {
	t.Helper()
	ctx := context.Background()
	var all []*v2.Entitlement
	token := ""
	for page := 1; page <= 50; page++ {
		resp, err := srv.ListEntitlements(ctx, &v2.EntitlementsServiceListEntitlementsRequest{
			Resource:     res,
			PageToken:    token,
			ActiveSyncId: testSyncID,
		})
		g.Step(fmt.Sprintf("ListEntitlements %s/%s page %d", res.GetId().GetResourceType(), res.GetId().GetResource(), page), stripSessionUsage(resp), err)
		if err != nil {
			return all
		}
		all = append(all, resp.GetList()...)
		token = resp.GetNextPageToken()
		if token == "" {
			return all
		}
	}
	t.Fatalf("ListEntitlements did not terminate")
	return nil
}

// listAllGrants pages ListGrants for one resource.
func listAllGrants(t *testing.T, g *golden, srv types.ConnectorServer, res *v2.Resource, pageSize uint32) []*v2.Grant {
	t.Helper()
	ctx := context.Background()
	var all []*v2.Grant
	token := ""
	for page := 1; page <= 50; page++ {
		resp, err := srv.ListGrants(ctx, &v2.GrantsServiceListGrantsRequest{
			Resource:     res,
			PageSize:     pageSize,
			PageToken:    token,
			ActiveSyncId: testSyncID,
		})
		g.Step(fmt.Sprintf("ListGrants %s/%s page %d", res.GetId().GetResourceType(), res.GetId().GetResource(), page), stripSessionUsage(resp), err)
		if err != nil {
			return all
		}
		all = append(all, resp.GetList()...)
		token = resp.GetNextPageToken()
		if token == "" {
			return all
		}
	}
	t.Fatalf("ListGrants did not terminate")
	return nil
}

// stripSessionUsage is kept as an identity hook so call sites read clearly;
// the SDK's session-usage annotation (byte counts of the session store, not
// connector output) is removed in golden.Step.
func stripSessionUsage[T proto.Message](m T) proto.Message {
	if any(m) == nil || !m.ProtoReflect().IsValid() {
		return nil
	}
	return m
}
