package connector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	sdkGrant "github.com/conductorone/baton-sdk/pkg/types/grant"
	sdkResource "github.com/conductorone/baton-sdk/pkg/types/resource"
	oktaSDK "github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func groupAssignmentFixture(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("testdata/group-application-assignment.json")
	require.NoError(t, err)
	return string(data)
}

func TestListEventsGroupApplicationAssignment(t *testing.T) {
	var filterQuery string
	fixture := groupAssignmentFixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/logs" {
			t.Errorf("unexpected request path: %s", r.URL.Path)
		}
		filterQuery = r.URL.Query().Get("filter")
		writeOktaTestResponse(w, http.StatusOK, "["+fixture+"]")
	}))
	defer server.Close()
	_, client, err := oktaSDK.NewClient(context.Background(),
		oktaSDK.WithOrgUrl(server.URL),
		oktaSDK.WithToken("test-token"),
		oktaSDK.WithHttpClientPtr(server.Client()),
		oktaSDK.WithTestingDisableHttpsCheck(true),
		oktaSDK.WithCache(false),
	)
	require.NoError(t, err)
	c := &Okta{client: client}
	events, _, _, err := c.ListEvents(context.Background(), nil, &pagination.StreamToken{Size: 100})
	require.NoError(t, err)
	require.Contains(t, filterQuery, `eventType eq "group.application_assignment.add"`)
	require.Len(t, events, 1)
	require.Equal(t, "00000000-0000-4000-8000-000000000020", events[0].GetId())
	require.Equal(t, "2026-10-23T17:38:52.97Z", events[0].GetOccurredAt().AsTime().Format("2006-01-02T15:04:05.999999999Z07:00"))
	grant := events[0].GetCreateGrantEvent()
	require.NotNil(t, grant)
	require.Equal(t, "app:app1:access", grant.GetEntitlement().GetId())
	require.Equal(t, "access", grant.GetEntitlement().GetSlug())
	require.Equal(t, "app", grant.GetEntitlement().GetResource().GetId().GetResourceType())
	require.Equal(t, "app1", grant.GetEntitlement().GetResource().GetId().GetResource())
	require.Equal(t, "group", grant.GetPrincipal().GetId().GetResourceType())
	require.Equal(t, "group1", grant.GetPrincipal().GetId().GetResource())
	resource, err := sdkResource.NewResource("Example application", resourceTypeApp, "app1")
	require.NoError(t, err)
	fullSyncGrant := sdkGrant.NewGrant(resource, "access", grant.GetPrincipal())
	eventGrant := sdkGrant.NewGrantID(grant.GetPrincipal(), grant.GetEntitlement())
	require.Equal(t, fullSyncGrant.GetId(), eventGrant)
	expansion := &v2.GrantExpandable{}
	annos := annotations.Annotations(grant.GetAnnotations())
	found, err := annos.Pick(expansion)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, []string{"group:group1:member"}, expansion.GetEntitlementIds())
	require.True(t, expansion.GetShallow())
}

func groupAssignmentFilter(t *testing.T) EventFilter {
	t.Helper()
	for _, filter := range activeFilters {
		if filter.EventTypes.Contains("group.application_assignment.add") {
			return filter
		}
	}
	t.Fatal("group application assignment filter is not registered")
	return EventFilter{}
}

func TestListEventsGroupApplicationAssignmentWithSkippedAppGroups(t *testing.T) {
	client := newScriptedOktaClient(t, oktaRequestStep{
		method: http.MethodGet, path: "/api/v1/logs", statusCode: http.StatusOK,
		body: "[" + groupAssignmentFixture(t) + "]",
	})
	c := &Okta{client: client, skipAppGroups: true}
	events, _, _, err := c.ListEvents(t.Context(), nil, &pagination.StreamToken{Size: 100})
	require.NoError(t, err)
	require.Empty(t, events)
}

func TestApplicationGroupAssignmentFilterRejectsMalformedTargets(t *testing.T) {
	filter := groupAssignmentFilter(t)
	for _, tt := range []struct {
		name    string
		targets []*oktaSDK.LogTarget
	}{
		{name: "missing group", targets: []*oktaSDK.LogTarget{{Type: "AppInstance", Id: "app1"}}},
		{name: "missing application", targets: []*oktaSDK.LogTarget{{Type: "UserGroup", Id: "group1"}}},
		{name: "duplicate groups", targets: []*oktaSDK.LogTarget{{Type: "UserGroup", Id: "group1"}, {Type: "UserGroup", Id: "group2"}, {Type: "AppInstance", Id: "app1"}}},
		{name: "duplicate applications", targets: []*oktaSDK.LogTarget{{Type: "UserGroup", Id: "group1"}, {Type: "AppInstance", Id: "app1"}, {Type: "AppInstance", Id: "app2"}}},
		{name: "empty group id", targets: []*oktaSDK.LogTarget{{Type: "UserGroup"}, {Type: "AppInstance", Id: "app1"}}},
		{name: "empty application id", targets: []*oktaSDK.LogTarget{{Type: "UserGroup", Id: "group1"}, {Type: "AppInstance"}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			event := logEvent("group.application_assignment.add", tt.targets...)
			event.Outcome = &oktaSDK.LogOutcome{Result: "SUCCESS"}
			rv, err := filter.Handle(zap.NewNop(), event)
			require.Error(t, err)
			require.Nil(t, rv)
		})
	}
}

func TestApplicationGroupAssignmentFilterSkipsUnsuccessfulEvents(t *testing.T) {
	filter := groupAssignmentFilter(t)
	for _, outcome := range []*oktaSDK.LogOutcome{nil, {Result: "FAILURE"}, {Result: "SKIPPED"}, {Result: "UNKNOWN"}} {
		event := &oktaSDK.LogEvent{}
		require.NoError(t, json.Unmarshal([]byte(groupAssignmentFixture(t)), event))
		event.Outcome = outcome
		rv, err := filter.Handle(zap.NewNop(), event)
		require.NoError(t, err)
		require.Nil(t, rv)
	}
}
