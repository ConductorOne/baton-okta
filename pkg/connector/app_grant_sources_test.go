package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	sdkResource "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"google.golang.org/protobuf/proto"
)

const (
	testGrantAppID      = "0oaEXAMPLEAPP0000010"
	testOktaGroupID     = "00gEXAMPLEOKTAGRP001"
	testAppGroupID      = "00gEXAMPLEAPPGRP0001"
	testDirectUserID    = "00uEXAMPLEDIRECT0001"
	testGroupScopedUser = "00uEXAMPLEGROUPED001"
)

func testAppResource() *v2.Resource {
	return &v2.Resource{
		Id:          &v2.ResourceId{ResourceType: resourceTypeApp.Id, Resource: testGrantAppID},
		DisplayName: "Test App",
	}
}

// testAssignment describes one app group assignment. An empty groupType omits
// the _embedded.group object, standing in for an expand Okta did not honor.
type testAssignment struct {
	id        string
	groupType string
}

// appGroupAssignmentBody mirrors the shape Okta returns for
// GET /api/v1/apps/{appId}/groups?expand=group.
func appGroupAssignmentBody(assignments ...testAssignment) string {
	parts := make([]string, 0, len(assignments))
	for _, a := range assignments {
		if a.groupType == "" {
			parts = append(parts, `{"id":"`+a.id+`","priority":0}`)
			continue
		}
		parts = append(parts, `{"id":"`+a.id+`","priority":0,"_embedded":{"group":`+
			`{"id":"`+a.id+`","type":"`+a.groupType+`",`+
			`"profile":{"name":"example-group","description":"example"}}}}`)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func TestAppGroupAssignmentGroupType(t *testing.T) {
	realEmbedded := map[string]interface{}{}
	if err := json.Unmarshal([]byte(`{"group":{"id":"`+testAppGroupID+`","type":"APP_GROUP",`+
		`"source":{"id":"0oaEXAMPLESOURCE0001"},"profile":{"name":"example-app-group"}}}`), &realEmbedded); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	cases := []struct {
		name       string
		assignment *okta.ApplicationGroupAssignment
		wantType   string
		wantKnown  bool
	}{
		{"no embed", &okta.ApplicationGroupAssignment{Id: testOktaGroupID}, "", false},
		{"embed not an object", &okta.ApplicationGroupAssignment{Embedded: "nope"}, "", false},
		{"embed without group", &okta.ApplicationGroupAssignment{
			Embedded: map[string]interface{}{"other": map[string]interface{}{}},
		}, "", false},
		{"group not an object", &okta.ApplicationGroupAssignment{
			Embedded: map[string]interface{}{"group": "nope"},
		}, "", false},
		{"group without type", &okta.ApplicationGroupAssignment{
			Embedded: map[string]interface{}{"group": map[string]interface{}{"id": testOktaGroupID}},
		}, "", false},
		{"group with empty type", &okta.ApplicationGroupAssignment{
			Embedded: map[string]interface{}{"group": map[string]interface{}{"type": ""}},
		}, "", false},
		{"okta group", &okta.ApplicationGroupAssignment{
			Embedded: map[string]interface{}{"group": map[string]interface{}{"type": "OKTA_GROUP"}},
		}, "OKTA_GROUP", true},
		{"app group from a real response shape", &okta.ApplicationGroupAssignment{
			Id: testAppGroupID, Embedded: realEmbedded,
		}, appGroupType, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotType, gotKnown := appGroupAssignmentGroupType(tc.assignment)
			if gotType != tc.wantType || gotKnown != tc.wantKnown {
				t.Errorf("= (%q, %t), want (%q, %t)", gotType, gotKnown, tc.wantType, tc.wantKnown)
			}
		})
	}
}

func TestAppGrantPhaseIDRoundTrip(t *testing.T) {
	cases := []struct {
		resourceID string
		wantPhase  string
		wantUnsync bool
		roundTrips bool
	}{
		{"", "", false, false},
		{appGrantGroup, appGrantGroup, false, true},
		{appGrantUser, appGrantUser, false, true},
		{appGrantGroup + ":" + appGrantUnsyncedMarker, appGrantGroup, true, true},
		{appGrantUser + ":" + appGrantUnsyncedMarker, appGrantUser, true, true},
		// A suffix we never write must not be mistaken for the marker.
		{appGrantUser + ":something", appGrantUser, false, false},
	}

	for _, tc := range cases {
		t.Run(tc.resourceID, func(t *testing.T) {
			phase, unsynced := parseAppGrantPhaseID(tc.resourceID)
			if phase != tc.wantPhase || unsynced != tc.wantUnsync {
				t.Fatalf("parse(%q) = (%q, %t), want (%q, %t)", tc.resourceID, phase, unsynced, tc.wantPhase, tc.wantUnsync)
			}
			if tc.roundTrips {
				if got := appGrantPhaseID(phase, unsynced); got != tc.resourceID {
					t.Errorf("appGrantPhaseID(%q, %t) = %q, want %q", phase, unsynced, got, tc.resourceID)
				}
			}
		})
	}
}

// The group phase queues the user phase itself, so the marker survives in the
// page token rather than a session store. Drive the real Grants loop -- not a
// copy of its state machine -- so a divergence between the two would fail here.
func TestAppGrantPhaseSequenceTerminates(t *testing.T) {
	for _, groupPages := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("%d-group-pages", groupPages), func(t *testing.T) {
			var steps []oktaRequestStep
			for i := 0; i < groupPages; i++ {
				step := oktaRequestStep{
					method:     http.MethodGet,
					path:       "/api/v1/apps/" + testGrantAppID + "/groups",
					query:      map[string]string{"expand": expandGroup},
					statusCode: http.StatusOK,
					body:       appGroupAssignmentBody(testAssignment{testAppGroupID, appGroupType}),
				}
				if i < groupPages-1 {
					// Okta signals another page with a Link header; the SDK turns
					// it into Response.NextPage and parseResp reads the cursor.
					step.headers = map[string]string{
						"Link": `<https://example.okta.com/api/v1/apps/` + testGrantAppID +
							`/groups?after=cursor` + fmt.Sprint(i) + `>; rel="next"`,
					}
				}
				steps = append(steps, step)
			}
			steps = append(steps, oktaRequestStep{
				method:     http.MethodGet,
				path:       "/api/v1/apps/" + testGrantAppID + "/users",
				statusCode: http.StatusOK,
				body:       appUsersBody(),
			})

			o := &appResourceType{
				resourceType:  resourceTypeApp,
				client:        newScriptedOktaClient(t, steps...),
				skipAppGroups: true,
			}

			var (
				token     string
				calls     int
				allGrants []*v2.Grant
			)
			for calls = 0; calls < 25; calls++ {
				grants, results, err := o.Grants(context.Background(), testAppResource(), sdkResource.SyncOpAttrs{
					PageToken: pagination.Token{Token: token},
				})
				if err != nil {
					t.Fatalf("Grants call %d: %v", calls+1, err)
				}
				allGrants = append(allGrants, grants...)
				token = results.NextPageToken
				if token == "" {
					break
				}
			}
			if token != "" {
				t.Fatalf("Grants did not terminate after %d calls", calls)
			}

			// Every assignment is a dropped APP_GROUP, so no group grant is
			// emitted and all three app users must survive as direct grants --
			// the marker has to reach the user phase for that to happen.
			for _, g := range allGrants {
				if g.GetPrincipal().GetId().GetResourceType() == resourceTypeGroup.Id {
					t.Errorf("emitted a grant for a group that was never synced: %s", g.GetId())
				}
			}
			if len(allGrants) != 3 {
				t.Fatalf("got %d user grants, want 3 (marker lost on the way to the user phase?)", len(allGrants))
			}
		})
	}
}

// annotationMessage is the subset of proto.Message that annotations.Pick needs.
type annotationMessage = proto.Message

func grantAnnotation(t *testing.T, grant *v2.Grant, msg annotationMessage) bool {
	t.Helper()
	annos := annotations.Annotations(grant.GetAnnotations())
	found, err := annos.Pick(msg)
	if err != nil {
		t.Fatalf("Pick(%T): %v", msg, err)
	}
	return found
}

func runGroupPhase(t *testing.T, skipAppGroups bool, incomingMarker bool, body string) ([]*v2.Grant, string) {
	t.Helper()

	// The embedded group is only worth fetching when its type will be read, so
	// assert both directions: requested under skip-app-groups, absent otherwise.
	wantExpand := ""
	if skipAppGroups {
		wantExpand = expandGroup
	}

	client := newScriptedOktaClient(t, oktaRequestStep{
		method:     http.MethodGet,
		path:       "/api/v1/apps/" + testGrantAppID + "/groups",
		query:      map[string]string{"expand": wantExpand},
		statusCode: http.StatusOK,
		body:       body,
	})

	o := &appResourceType{resourceType: resourceTypeApp, client: client, skipAppGroups: skipAppGroups}
	bag := &pagination.Bag{}
	bag.Push(pagination.PageState{ResourceTypeID: resourceTypeApp.Id, ResourceID: appGrantGroup})

	grants, _, bag, err := o.listAppGroupGrants(context.Background(), testAppResource(), &pagination.Token{Size: 50}, bag, "", incomingMarker)
	if err != nil {
		t.Fatalf("listAppGroupGrants: %v", err)
	}
	return grants, bag.ResourceID()
}

func TestListAppGroupGrants(t *testing.T) {
	unsyncedPhase := appGrantUser + ":" + appGrantUnsyncedMarker

	cases := []struct {
		name           string
		skipAppGroups  bool
		incomingMarker bool
		assignments    []testAssignment
		wantGroups     []string
		wantExpandable bool
		wantNextPhase  string
	}{
		{
			// The group syncer drops the resource, so a grant would dangle and
			// expansion has nothing to reattribute the members to.
			name:          "app group skipped marks the app and emits nothing",
			skipAppGroups: true,
			assignments:   []testAssignment{{testAppGroupID, appGroupType}},
			wantGroups:    nil,
			wantNextPhase: unsyncedPhase,
		},
		{
			name:           "app group is ordinary when the flag is off",
			skipAppGroups:  false,
			assignments:    []testAssignment{{testAppGroupID, appGroupType}},
			wantGroups:     []string{testAppGroupID},
			wantExpandable: true,
			wantNextPhase:  appGrantUser,
		},
		{
			name:           "okta group is unaffected by the flag",
			skipAppGroups:  true,
			assignments:    []testAssignment{{testOktaGroupID, "OKTA_GROUP"}},
			wantGroups:     []string{testOktaGroupID},
			wantExpandable: true,
			wantNextPhase:  appGrantUser,
		},
		{
			// Without proof the group synced, suppressing its members' direct
			// grants is unsafe, so the app is marked but the grant still goes
			// out -- without an expansion edge into an entitlement that may
			// never have been synced.
			name:           "unreadable group type fails closed and does not expand",
			skipAppGroups:  true,
			assignments:    []testAssignment{{testOktaGroupID, ""}},
			wantGroups:     []string{testOktaGroupID},
			wantExpandable: false,
			wantNextPhase:  unsyncedPhase,
		},
		{
			// The mixed app is the only place the two skip-app-groups settings
			// diverge: the ordinary group still expands normally, and the
			// dropped APP_GROUP alongside it still marks the app.
			name:           "mixed app keeps the ordinary group and still marks the app",
			skipAppGroups:  true,
			assignments:    []testAssignment{{testOktaGroupID, "OKTA_GROUP"}, {testAppGroupID, appGroupType}},
			wantGroups:     []string{testOktaGroupID},
			wantExpandable: true,
			wantNextPhase:  unsyncedPhase,
		},
		{
			// A marker set on an earlier page has to ride out on the state this
			// page pushes, or a multi-page app silently loses it.
			name:           "marker from an earlier page survives a clean page",
			skipAppGroups:  true,
			incomingMarker: true,
			assignments:    []testAssignment{{testOktaGroupID, "OKTA_GROUP"}},
			wantGroups:     []string{testOktaGroupID},
			wantExpandable: true,
			wantNextPhase:  unsyncedPhase,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			grants, nextPhase := runGroupPhase(t, tc.skipAppGroups, tc.incomingMarker, appGroupAssignmentBody(tc.assignments...))

			var got []string
			for _, g := range grants {
				got = append(got, g.GetPrincipal().GetId().GetResource())
			}
			if !slices.Equal(got, tc.wantGroups) {
				t.Fatalf("group grants = %v, want %v", got, tc.wantGroups)
			}
			if nextPhase != tc.wantNextPhase {
				t.Errorf("next phase = %q, want %q", nextPhase, tc.wantNextPhase)
			}

			for _, g := range grants {
				expandable := &v2.GrantExpandable{}
				found := grantAnnotation(t, g, expandable)
				if found != tc.wantExpandable {
					t.Fatalf("grant for %s has GrantExpandable = %t, want %t",
						g.GetPrincipal().GetId().GetResource(), found, tc.wantExpandable)
				}
				if !found {
					continue
				}
				want := "group:" + g.GetPrincipal().GetId().GetResource() + ":member"
				if ids := expandable.GetEntitlementIds(); len(ids) != 1 || ids[0] != want {
					t.Errorf("GrantExpandable entitlement ids = %v, want [%s]", ids, want)
				}
			}
		})
	}
}

func appUsersBody() string {
	return `[{"id":"` + testDirectUserID + `","scope":"USER","profile":{"email":"direct@example.com"}},` +
		`{"id":"` + testGroupScopedUser + `","scope":"GROUP","profile":{"email":"grouped@example.com"}},` +
		`{"id":"00uEXAMPLENOSCOPE001","profile":{"email":"noscope@example.com"}}]`
}

func TestListAppUsersGrants(t *testing.T) {
	cases := []struct {
		name           string
		unsyncedSource bool
		wantPrincipals []string
		wantImmutable  map[string]bool
	}{
		{
			// Group-derived access arrives through expansion with the group as
			// source; emitting it here too would report it as a direct assignment.
			name:           "group scoped users are suppressed by default",
			unsyncedSource: false,
			wantPrincipals: []string{testDirectUserID, "00uEXAMPLENOSCOPE001"},
			wantImmutable:  map[string]bool{testDirectUserID: false, "00uEXAMPLENOSCOPE001": false},
		},
		{
			// The conferring group was dropped, so nothing will regenerate these
			// grants; keeping them costs attribution but never loses access.
			name:           "group scoped users are kept and marked when a group source was dropped",
			unsyncedSource: true,
			wantPrincipals: []string{testDirectUserID, testGroupScopedUser, "00uEXAMPLENOSCOPE001"},
			wantImmutable: map[string]bool{
				testDirectUserID:       false,
				testGroupScopedUser:    true,
				"00uEXAMPLENOSCOPE001": false,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := newScriptedOktaClient(t, oktaRequestStep{
				method:     http.MethodGet,
				path:       "/api/v1/apps/" + testGrantAppID + "/users",
				statusCode: http.StatusOK,
				body:       appUsersBody(),
			})

			o := &appResourceType{resourceType: resourceTypeApp, client: client}
			bag := &pagination.Bag{}
			bag.Push(pagination.PageState{ResourceTypeID: resourceTypeApp.Id, ResourceID: appGrantUser})

			grants, _, _, err := o.listAppUsersGrants(context.Background(), testAppResource(), &pagination.Token{Size: 50}, bag, "", tc.unsyncedSource)
			if err != nil {
				t.Fatalf("listAppUsersGrants: %v", err)
			}

			var got []string
			for _, g := range grants {
				got = append(got, g.GetPrincipal().GetId().GetResource())
			}
			if len(got) != len(tc.wantPrincipals) {
				t.Fatalf("principals = %v, want %v", got, tc.wantPrincipals)
			}
			for _, want := range tc.wantPrincipals {
				var match *v2.Grant
				for _, g := range grants {
					if g.GetPrincipal().GetId().GetResource() == want {
						match = g
						break
					}
				}
				if match == nil {
					t.Fatalf("no grant for principal %s; got %v", want, got)
				}
				immutable := grantAnnotation(t, match, &v2.GrantImmutable{})
				if immutable != tc.wantImmutable[want] {
					t.Errorf("principal %s GrantImmutable = %t, want %t", want, immutable, tc.wantImmutable[want])
				}
			}
		})
	}
}
