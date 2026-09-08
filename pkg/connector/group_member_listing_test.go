package connector

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	sdkResource "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/okta/okta-sdk-golang/v2/okta"
)

const testStatsGroupID = "00gEXAMPLESTATSGRP01"

func groupWithStats(t *testing.T, usersCount, appsCount float64) *v2.Resource {
	t.Helper()

	o := &groupResourceType{resourceType: resourceTypeGroup}
	resource, err := o.groupResource(&okta.Group{
		Id:      testStatsGroupID,
		Type:    "OKTA_GROUP",
		Profile: &okta.GroupProfile{Name: "example-group", Description: "example"},
		Embedded: map[string]interface{}{
			"stats": map[string]interface{}{
				"usersCount": usersCount,
				"appsCount":  appsCount,
			},
		},
	})
	if err != nil {
		t.Fatalf("groupResource: %v", err)
	}
	return resource
}

// users_count comes from Okta's group stats embed, an aggregate with no
// documented freshness guarantee. App access conferred by a group is expanded
// from its member grants, so skipping the member listing when that count lags
// real membership drops the access entirely. The call-saving skip has to be
// limited to groups that grant no app access.
func TestGroupMemberListingRespectsAppAssignments(t *testing.T) {
	cases := []struct {
		name       string
		usersCount float64
		appsCount  float64
		wantListed bool
	}{
		{
			name:       "empty and unassigned keeps the short circuit",
			usersCount: 0,
			appsCount:  0,
			wantListed: false,
		},
		{
			// The case that loses access: the count lags real membership and an
			// app grant depends on the group's member grants.
			name:       "stale zero on an app assigned group still lists members",
			usersCount: 0,
			appsCount:  2,
			wantListed: true,
		},
		{
			name:       "non-zero count lists members as before",
			usersCount: 3,
			appsCount:  0,
			wantListed: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var steps []oktaRequestStep
			if tc.wantListed {
				steps = append(steps, oktaRequestStep{
					method:     http.MethodGet,
					path:       "/api/v1/groups/" + testStatsGroupID + "/users",
					statusCode: http.StatusOK,
					body:       `[]`,
				})
			}
			// newScriptedOktaClient fails the test on an unscripted request and
			// on a scripted one that never arrives, so the step list alone
			// asserts whether the member listing happened.
			client := newScriptedOktaClient(t, steps...)

			o := &groupResourceType{
				resourceType: resourceTypeGroup,
				connector:    &Okta{client: client, userFilters: &userFilterConfig{}},
			}

			_, _, err := o.Grants(context.Background(), groupWithStats(t, tc.usersCount, tc.appsCount), sdkResource.SyncOpAttrs{})
			if err != nil {
				t.Fatalf("Grants: %v", err)
			}
		})
	}
}

// SkipGrants suppresses the Grants call outright, so the member-listing guard
// never runs on the targeted-sync path. The same rule has to apply here.
func TestGroupGetSkipsGrantsOnlyWhenNoAppAccess(t *testing.T) {
	cases := []struct {
		name          string
		stats         map[string]interface{}
		wantSkipGrant bool
	}{
		{
			name:          "empty and unassigned still skips grants",
			stats:         map[string]interface{}{"usersCount": float64(0), "appsCount": float64(0)},
			wantSkipGrant: true,
		},
		{
			name:          "app assigned group is never skipped on a zero member count",
			stats:         map[string]interface{}{"usersCount": float64(0), "appsCount": float64(2)},
			wantSkipGrant: false,
		},
		{
			// Cannot tell whether the group grants app access, so do not act on
			// the zero.
			name:          "absent apps_count is not enough to skip",
			stats:         map[string]interface{}{"usersCount": float64(0)},
			wantSkipGrant: false,
		},
		{
			name:          "non-zero member count is never skipped",
			stats:         map[string]interface{}{"usersCount": float64(4), "appsCount": float64(0)},
			wantSkipGrant: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(map[string]interface{}{
				"id":        testStatsGroupID,
				"type":      "OKTA_GROUP",
				"profile":   map[string]interface{}{"name": "example-group", "description": "example"},
				"_embedded": map[string]interface{}{"stats": tc.stats},
			})
			if err != nil {
				t.Fatalf("marshal group: %v", err)
			}

			client := newScriptedOktaClient(t, oktaRequestStep{
				method:     http.MethodGet,
				path:       "/api/v1/groups/" + testStatsGroupID,
				query:      map[string]string{"expand": "stats,app"},
				statusCode: http.StatusOK,
				body:       string(body),
			})

			o := &groupResourceType{
				resourceType: resourceTypeGroup,
				connector:    &Okta{client: client, userFilters: &userFilterConfig{}},
			}

			resource, _, err := o.Get(context.Background(),
				&v2.ResourceId{ResourceType: resourceTypeGroup.Id, Resource: testStatsGroupID}, nil)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}

			annos := annotations.Annotations(resource.GetAnnotations())
			skip := &v2.SkipGrants{}
			got, err := annos.Pick(skip)
			if err != nil {
				t.Fatalf("Pick(SkipGrants): %v", err)
			}
			if got != tc.wantSkipGrant {
				t.Errorf("SkipGrants = %t, want %t", got, tc.wantSkipGrant)
			}
		})
	}
}
