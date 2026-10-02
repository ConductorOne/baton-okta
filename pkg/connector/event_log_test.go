package connector

import (
	"net/http"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/stretchr/testify/require"
)

// The SDK rejects a builder that implements both EventFeeds and the legacy
// ListEvents, so the connector itself must not grow a ListEvents method again.
func TestOktaIsNotALegacyEventLister(t *testing.T) {
	var o any = &Okta{}
	_, isLegacy := o.(connectorbuilder.EventLister)
	require.False(t, isLegacy)
}

func TestEventFeedsMetadata(t *testing.T) {
	feeds := (&Okta{}).EventFeeds(t.Context())

	byID := make(map[string]*v2.EventFeedMetadata, len(feeds))
	for _, feed := range feeds {
		md := feed.EventFeedMetadata(t.Context())
		require.NoError(t, md.Validate())
		require.NotContains(t, byID, md.GetId(), "duplicate feed id")
		byID[md.GetId()] = md
	}

	// The change feed keeps the legacy ID so cursors from before the split resume.
	require.ElementsMatch(t, []v2.EventType{
		v2.EventType_EVENT_TYPE_RESOURCE_CHANGE,
		v2.EventType_EVENT_TYPE_CREATE_GRANT,
		v2.EventType_EVENT_TYPE_CREATE_REVOKE,
	}, byID[connectorbuilder.LegacyBatonFeedId].GetSupportedEventTypes())
	require.ElementsMatch(t, []v2.EventType{
		v2.EventType_EVENT_TYPE_USAGE,
	}, byID[usageEventFeedID].GetSupportedEventTypes())
}

// An Okta event type queried by both feeds would be emitted twice.
func TestEventFeedsDoNotOverlap(t *testing.T) {
	usage := mapset.NewSet[string]()
	for _, filter := range usageFilters {
		usage = usage.Union(filter.EventTypes)
	}
	changes := mapset.NewSet[string]()
	for _, filter := range changeFilters {
		changes = changes.Union(filter.EventTypes)
	}
	require.Empty(t, usage.Intersect(changes).ToSlice())
}

func TestUsageEventFeedListEvents(t *testing.T) {
	client := newScriptedOktaClient(t, oktaRequestStep{
		method:     http.MethodGet,
		path:       "/api/v1/logs",
		query:      map[string]string{"filter": UsageFilter.Filter()},
		statusCode: http.StatusOK,
		body: `[{
			"uuid": "00000000-0000-4000-8000-000000000003",
			"eventType": "user.authentication.sso",
			"published": "2026-08-25T12:00:00.000Z",
			"actor": {"id":"user1","type":"User","alternateId":"user@example.com","displayName":"User"},
			"target": [{"id":"app1","type":"AppInstance","displayName":"App"}]
		}]`,
	})

	var feed connectorbuilder.EventFeed
	for _, f := range (&Okta{client: client}).EventFeeds(t.Context()) {
		if f.EventFeedMetadata(t.Context()).GetId() == usageEventFeedID {
			feed = f
		}
	}
	require.NotNil(t, feed)

	events, state, _, err := feed.ListEvents(t.Context(), nil, &pagination.StreamToken{Size: 10})
	require.NoError(t, err)
	require.False(t, state.HasMore)
	require.Len(t, events, 1)
	require.Equal(t, "app1", events[0].GetUsageEvent().GetTargetResource().GetId().GetResource())
	require.Equal(t, "user1", events[0].GetUsageEvent().GetActorResource().GetId().GetResource())
}
