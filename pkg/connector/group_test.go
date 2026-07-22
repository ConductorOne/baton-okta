package connector

import (
	"context"
	"testing"

	"github.com/okta/okta-sdk-golang/v2/okta"
)

func TestGroupTrait_TypeProfileKey(t *testing.T) {
	tests := []struct {
		name           string
		oktaType       string
		want           string
		wantSourceType string
	}{
		{name: "okta-native group", oktaType: oktaGroupType, want: "OKTA_GROUP", wantSourceType: "native"},
		{name: "app push group", oktaType: appGroupType, want: "APP_GROUP", wantSourceType: "app_imported"},
		{name: "built-in group", oktaType: builtInGroupType, want: "BUILT_IN", wantSourceType: "built_in"},
		{name: "unknown future value passes through verbatim", oktaType: "FUTURE_TYPE", want: "FUTURE_TYPE", wantSourceType: ""},
		{name: "empty type passes through as empty", oktaType: "", want: "", wantSourceType: ""},
	}

	o := &groupResourceType{}
	ctx := context.Background()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			group := &okta.Group{
				Id:   "00g1abc2def3GHI4jk5",
				Type: tc.oktaType,
				Profile: &okta.GroupProfile{
					Name:        "test-group",
					Description: "test description",
				},
			}

			trait, err := o.groupTrait(ctx, group)
			if err != nil {
				t.Fatalf("groupTrait returned error: %v", err)
			}
			if trait == nil || trait.Profile == nil {
				t.Fatalf("groupTrait returned nil trait or profile")
			}

			got, ok := trait.Profile.Fields[groupTypeProfileKey]
			if !ok {
				t.Fatalf("profile is missing %q key; fields=%v", groupTypeProfileKey, trait.Profile.Fields)
			}
			if got.GetStringValue() != tc.want {
				t.Errorf("profile[%q] = %q, want %q", groupTypeProfileKey, got.GetStringValue(), tc.want)
			}

			for _, key := range []string{profileFieldName, profileFieldDescription} {
				if _, ok := trait.Profile.Fields[key]; !ok {
					t.Errorf("profile is missing pre-existing %q key", key)
				}
			}

			if got := trait.GetRawGroupSourceType(); got != tc.oktaType {
				t.Errorf("RawGroupSourceType = %q, want %q", got, tc.oktaType)
			}
			if got := trait.GetGroupSourceType(); got != tc.wantSourceType {
				t.Errorf("GroupSourceType = %q, want %q", got, tc.wantSourceType)
			}
		})
	}
}

func TestMapOktaGroupSourceType(t *testing.T) {
	tests := []struct {
		oktaType string
		want     string
	}{
		{oktaType: oktaGroupType, want: "native"},
		{oktaType: appGroupType, want: "app_imported"},
		{oktaType: builtInGroupType, want: "built_in"},
		{oktaType: "FUTURE_TYPE", want: ""},
		{oktaType: "", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.oktaType, func(t *testing.T) {
			if got := mapOktaGroupSourceType(tc.oktaType); got != tc.want {
				t.Errorf("mapOktaGroupSourceType(%q) = %q, want %q", tc.oktaType, got, tc.want)
			}
		})
	}
}
