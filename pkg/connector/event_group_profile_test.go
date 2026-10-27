package connector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/conductorone/baton-sdk/pkg/pagination"
	oktaSDK "github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/stretchr/testify/require"
)

func TestListEventsGroupChanges(t *testing.T) {
	for _, eventType := range []string{"group.lifecycle.create", "group.profile.update"} {
		t.Run(eventType, func(t *testing.T) {
			event := logEvent(eventType, &oktaSDK.LogTarget{Type: "UserGroup", Id: "group1", DisplayName: "Previous name"})
			event.Outcome = &oktaSDK.LogOutcome{Result: "SUCCESS"}
			body, err := json.Marshal([]*oktaSDK.LogEvent{event})
			require.NoError(t, err)
			var filterQuery string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/logs" {
					t.Errorf("unexpected request path: %s", r.URL.Path)
				}
				filterQuery = r.URL.Query().Get("filter")
				writeOktaTestResponse(w, http.StatusOK, string(body))
			}))
			defer server.Close()
			_, client, err := oktaSDK.NewClient(t.Context(),
				oktaSDK.WithOrgUrl(server.URL),
				oktaSDK.WithToken("test-token"),
				oktaSDK.WithHttpClientPtr(server.Client()),
				oktaSDK.WithTestingDisableHttpsCheck(true),
				oktaSDK.WithCache(false),
			)
			require.NoError(t, err)
			c := &Okta{client: client}
			events, _, _, err := c.ListEvents(t.Context(), nil, &pagination.StreamToken{Size: 100})
			require.NoError(t, err)
			require.Contains(t, filterQuery, `eventType eq "`+eventType+`"`)
			require.Len(t, events, 1)
			require.Equal(t, event.Uuid, events[0].GetId())
			require.Equal(t, *event.Published, events[0].GetOccurredAt().AsTime())
			change := events[0].GetResourceChangeEvent()
			require.NotNil(t, change)
			require.Equal(t, "group", change.GetResourceId().GetResourceType())
			require.Equal(t, "group1", change.GetResourceId().GetResource())
			require.Nil(t, events[0].GetCreateGrantEvent())
		})
	}
}
