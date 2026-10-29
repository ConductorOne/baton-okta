package connector

import (
	"encoding/json"
	"net/http"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/stretchr/testify/require"
)

func TestGroupGetRespectsSkipAppGroups(t *testing.T) {
	for _, tc := range []struct {
		name          string
		groupType     string
		skipAppGroups bool
		wantSkipped   bool
	}{
		{name: "app group excluded", groupType: appGroupType, skipAppGroups: true, wantSkipped: true},
		{name: "app group included", groupType: appGroupType},
		{name: "regular group retained", groupType: oktaGroupType, skipAppGroups: true},
		{name: "built-in group retained", groupType: builtInGroupType, skipAppGroups: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(map[string]interface{}{
				"id":      "group1",
				"type":    tc.groupType,
				"profile": map[string]string{"name": "Renamed group", "description": "Updated description"},
			})
			require.NoError(t, err)
			client := newScriptedOktaClient(t, oktaRequestStep{
				method:     http.MethodGet,
				path:       "/api/v1/groups/group1",
				query:      map[string]string{"expand": "stats,app"},
				statusCode: http.StatusOK,
				body:       string(body),
			})
			o := &groupResourceType{resourceType: resourceTypeGroup, connector: &Okta{client: client, skipAppGroups: tc.skipAppGroups}}
			resource, _, err := o.Get(t.Context(), &v2.ResourceId{ResourceType: "group", Resource: "group1"}, nil)
			require.NoError(t, err)
			if tc.wantSkipped {
				require.Nil(t, resource)
				return
			}
			require.NotNil(t, resource)
			require.Equal(t, "group1", resource.GetId().GetResource())
			require.Equal(t, "Renamed group", resource.GetDisplayName())
			require.Equal(t, "Updated description", resource.GetDescription())
		})
	}
}
