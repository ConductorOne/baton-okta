package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
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

// appGroupAssignmentBody mirrors the shape Okta returns for
// GET /api/v1/apps/{appId}/groups?expand=group.
func appGroupAssignmentBody(groupID, groupType string) string {
	return `[{"id":"` + groupID + `","priority":0,"_embedded":{"group":` +
		`{"id":"` + groupID + `","type":"` + groupType + `",` +
		`"profile":{"name":"example-group","description":"example"}}}}]`
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
		{"nil assignment", nil, "", false},
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
// page token rather than in a session store. Assert the sequence terminates and
// carries the marker through however many pages of assignments there are.
func TestAppGrantPhaseSequenceTerminates(t *testing.T) {
	for _, groupPages := range []int{0, 1, 3} {
		t.Run(fmt.Sprintf("%d-extra-group-pages", groupPages), func(t *testing.T) {
			token := ""
			pagesLeft := groupPages
			var phases []string

			for i := 0; i < 25; i++ {
				bag, _, err := parsePageToken(token, &v2.ResourceId{ResourceType: resourceTypeUser.Id})
				if err != nil {
					t.Fatalf("parsePageToken: %v", err)
				}
				phase, unsynced := parseAppGrantPhaseID(bag.ResourceID())
				phases = append(phases, bag.ResourceID())

				switch phase {
				case "":
					bag.Pop()
					bag.Push(pagination.PageState{ResourceTypeID: resourceTypeApp.Id, ResourceID: appGrantGroup})
				case appGrantGroup:
					next := ""
					if pagesLeft > 0 {
						pagesLeft--
						next = "cursor"
					}
					bag.Pop()
					if next != "" {
						bag.Push(pagination.PageState{
							ResourceTypeID: resourceTypeApp.Id,
							ResourceID:     appGrantPhaseID(appGrantGroup, true),
							Token:          next,
						})
					} else {
						bag.Push(pagination.PageState{
							ResourceTypeID: resourceTypeApp.Id,
							ResourceID:     appGrantPhaseID(appGrantUser, true),
						})
					}
				case appGrantUser:
					if !unsynced {
						t.Fatalf("user phase lost the unsynced marker: %v", phases)
					}
					if err := bag.Next(""); err != nil {
						t.Fatalf("bag.Next: %v", err)
					}
				default:
					t.Fatalf("unexpected phase %q", phase)
				}

				token, err = bag.Marshal()
				if err != nil {
					t.Fatalf("Marshal: %v", err)
				}
				if token == "" {
					return
				}
			}
			t.Fatalf("phase sequence did not terminate: %v", phases)
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

func runGroupPhase(t *testing.T, skipAppGroups bool, body string) ([]*v2.Grant, string) {
	t.Helper()

	client := newScriptedOktaClient(t, oktaRequestStep{
		method:     http.MethodGet,
		path:       "/api/v1/apps/" + testGrantAppID + "/groups",
		query:      map[string]string{"expand": expandGroup},
		statusCode: http.StatusOK,
		body:       body,
	})

	o := &appResourceType{resourceType: resourceTypeApp, client: client, skipAppGroups: skipAppGroups}
	bag := &pagination.Bag{}
	bag.Push(pagination.PageState{ResourceTypeID: resourceTypeApp.Id, ResourceID: appGrantGroup})

	grants, _, bag, err := o.listAppGroupGrants(context.Background(), testAppResource(), &pagination.Token{Size: 50}, bag, "", false)
	if err != nil {
		t.Fatalf("listAppGroupGrants: %v", err)
	}
	return grants, bag.ResourceID()
}

func TestListAppGroupGrants(t *testing.T) {
	cases := []struct {
		name          string
		skipAppGroups bool
		body          string
		wantGrants    int
		wantNextPhase string
	}{
		{
			// The group syncer drops the resource, so a grant would dangle and
			// expansion has nothing to reattribute the members to.
			name:          "app group skipped marks the app and emits nothing",
			skipAppGroups: true,
			body:          appGroupAssignmentBody(testAppGroupID, appGroupType),
			wantGrants:    0,
			wantNextPhase: appGrantUser + ":" + appGrantUnsyncedMarker,
		},
		{
			name:          "app group is ordinary when the flag is off",
			skipAppGroups: false,
			body:          appGroupAssignmentBody(testAppGroupID, appGroupType),
			wantGrants:    1,
			wantNextPhase: appGrantUser,
		},
		{
			name:          "okta group is unaffected by the flag",
			skipAppGroups: true,
			body:          appGroupAssignmentBody(testOktaGroupID, "OKTA_GROUP"),
			wantGrants:    1,
			wantNextPhase: appGrantUser,
		},
		{
			// Without proof the group synced, suppressing its members' direct
			// grants is unsafe, so the app is marked but the grant still goes out.
			name:          "unreadable group type fails closed",
			skipAppGroups: true,
			body:          `[{"id":"` + testOktaGroupID + `","priority":0}]`,
			wantGrants:    1,
			wantNextPhase: appGrantUser + ":" + appGrantUnsyncedMarker,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			grants, nextPhase := runGroupPhase(t, tc.skipAppGroups, tc.body)

			if len(grants) != tc.wantGrants {
				t.Fatalf("emitted %d grants, want %d", len(grants), tc.wantGrants)
			}
			if nextPhase != tc.wantNextPhase {
				t.Errorf("next phase = %q, want %q", nextPhase, tc.wantNextPhase)
			}

			for _, g := range grants {
				expandable := &v2.GrantExpandable{}
				if !grantAnnotation(t, g, expandable) {
					t.Fatalf("group grant is missing GrantExpandable; members would never be attributed")
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
