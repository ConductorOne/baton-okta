package connector

import (
	"strings"
	"testing"
	"unicode/utf8"

	sdkResource "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/okta/okta-sdk-golang/v2/okta"
)

func TestGroupResource_TypeProfileKey(t *testing.T) {
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

			resource, err := o.groupResource(group)
			if err != nil {
				t.Fatalf("groupResource returned error: %v", err)
			}

			profile := resource.GetProfile()
			if profile == nil {
				t.Fatalf("groupResource returned resource with nil profile")
			}

			got, ok := sdkResource.GetProfileStringValue(profile, groupTypeProfileKey)
			if !ok {
				t.Fatalf("profile is missing %q key; fields=%v", groupTypeProfileKey, profile.GetFields())
			}
			if got != tc.want {
				t.Errorf("profile[%q] = %q, want %q", groupTypeProfileKey, got, tc.want)
			}

			for _, key := range []string{profileFieldName, profileFieldDescription} {
				if _, ok := profile.GetFields()[key]; !ok {
					t.Errorf("profile is missing pre-existing %q key", key)
				}
			}

			trait, err := sdkResource.GetGroupTrait(resource)
			if err != nil {
				t.Fatalf("GetGroupTrait returned error: %v", err)
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

func TestGroupResource_Description(t *testing.T) {
	tests := []struct {
		name            string
		oktaDescription string
		want            string
	}{
		{
			name:            "description is synced to the resource",
			oktaDescription: "Grants RDP access to machine wolt-1c",
			want:            "Grants RDP access to machine wolt-1c",
		},
		{
			name:            "multi-line description is preserved verbatim",
			oktaDescription: "For: RDP access\nNot for: VPN\nDo not request unless approved",
			want:            "For: RDP access\nNot for: VPN\nDo not request unless approved",
		},
		{
			name:            "surrounding whitespace is trimmed",
			oktaDescription: "  padded description\n",
			want:            "padded description",
		},
		{
			name:            "whitespace-only description is treated as unset",
			oktaDescription: "   \n\t ",
			want:            "",
		},
		{
			name:            "missing description stays empty",
			oktaDescription: "",
			want:            "",
		},
	}

	o := &groupResourceType{}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			group := &okta.Group{
				Id:   "00g1abc2def3GHI4jk5",
				Type: oktaGroupType,
				Profile: &okta.GroupProfile{
					Name:        "test-group",
					Description: tc.oktaDescription,
				},
			}

			resource, err := o.groupResource(group)
			if err != nil {
				t.Fatalf("groupResource returned error: %v", err)
			}

			if got := resource.GetDescription(); got != tc.want {
				t.Errorf("resource description = %q, want %q", got, tc.want)
			}

			// The profile `description` key is an already-shipped contract and must
			// keep carrying Okta's raw value.
			got, ok := sdkResource.GetProfileStringValue(resource.GetProfile(), profileFieldDescription)
			if !ok {
				t.Fatalf("profile is missing %q key", profileFieldDescription)
			}
			if got != tc.oktaDescription {
				t.Errorf("profile[%q] = %q, want raw Okta value %q", profileFieldDescription, got, tc.oktaDescription)
			}
		})
	}
}

func TestGroupDescription_ProtocolBudget(t *testing.T) {
	// Okta caps group descriptions at 1024 UTF-16 units, so a CJK description is
	// accepted by Okta at 3072 bytes of UTF-8 — over the protocol budget. Left
	// unclamped this aborts the whole sync with InvalidArgument.
	tests := []struct {
		name            string
		oktaDescription string
		wantBytes       int
	}{
		{
			name:            "ascii under the budget is untouched",
			oktaDescription: strings.Repeat("A", 1024),
			wantBytes:       1024,
		},
		{
			name:            "exactly at the budget is untouched",
			oktaDescription: strings.Repeat("A", maxDescriptionBytes),
			wantBytes:       maxDescriptionBytes,
		},
		{
			name:            "two-byte characters at okta's character cap",
			oktaDescription: strings.Repeat("ñ", 1024),
			wantBytes:       maxDescriptionBytes,
		},
		{
			// 3 does not divide the budget, so the longest character-aligned prefix
			// is 682 characters — one short of the 2048th byte.
			name:            "three-byte characters are clamped to the budget",
			oktaDescription: strings.Repeat("漢", 1024),
			wantBytes:       2046,
		},
		{
			name:            "clamp lands mid-character without splitting it",
			oktaDescription: strings.Repeat("A", maxDescriptionBytes-1) + "漢",
			wantBytes:       maxDescriptionBytes - 1,
		},
	}

	o := &groupResourceType{}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			group := &okta.Group{
				Id:   "00g1abc2def3GHI4jk5",
				Type: oktaGroupType,
				Profile: &okta.GroupProfile{
					Name:        "test-group",
					Description: tc.oktaDescription,
				},
			}

			resource, err := o.groupResource(group)
			if err != nil {
				t.Fatalf("groupResource returned error: %v", err)
			}

			got := resource.GetDescription()
			if len(got) != tc.wantBytes {
				t.Errorf("description length = %d bytes, want %d", len(got), tc.wantBytes)
			}
			if len(got) > maxDescriptionBytes {
				t.Errorf("description is %d bytes, over the %d-byte budget", len(got), maxDescriptionBytes)
			}
			if !utf8.ValidString(got) {
				t.Error("truncation produced invalid UTF-8")
			}
			if !strings.HasPrefix(tc.oktaDescription, got) {
				t.Error("truncated description is not a prefix of the Okta value")
			}

			// The entitlement reuses the resource description, so it inherits the clamp.
			if entDesc := o.groupEntitlement(resource).GetDescription(); len(entDesc) > maxDescriptionBytes {
				t.Errorf("entitlement description is %d bytes, over the %d-byte budget", len(entDesc), maxDescriptionBytes)
			}
		})
	}
}

func TestGroupEntitlement_Description(t *testing.T) {
	tests := []struct {
		name            string
		oktaDescription string
		want            string
	}{
		{
			name:            "okta description wins over the generated template",
			oktaDescription: "Grants RDP access to machine wolt-1c",
			want:            "Grants RDP access to machine wolt-1c",
		},
		{
			name:            "group without a description falls back to the template",
			oktaDescription: "",
			want:            "Member of test-group group in Okta",
		},
		{
			name:            "whitespace-only description falls back to the template",
			oktaDescription: "   \n ",
			want:            "Member of test-group group in Okta",
		},
	}

	o := &groupResourceType{}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			group := &okta.Group{
				Id:   "00g1abc2def3GHI4jk5",
				Type: oktaGroupType,
				Profile: &okta.GroupProfile{
					Name:        "test-group",
					Description: tc.oktaDescription,
				},
			}

			resource, err := o.groupResource(group)
			if err != nil {
				t.Fatalf("groupResource returned error: %v", err)
			}

			entitlement := o.groupEntitlement(resource)

			if got := entitlement.GetDescription(); got != tc.want {
				t.Errorf("entitlement description = %q, want %q", got, tc.want)
			}

			// The description must not leak into identity or the label: changing it
			// would re-key every existing grant.
			if got, want := entitlement.GetId(), "group:00g1abc2def3GHI4jk5:member"; got != want {
				t.Errorf("entitlement id = %q, want %q", got, want)
			}
			if got, want := entitlement.GetSlug(), "member"; got != want {
				t.Errorf("entitlement slug = %q, want %q", got, want)
			}
			if got, want := entitlement.GetDisplayName(), "test-group Group Member"; got != want {
				t.Errorf("entitlement display name = %q, want %q", got, want)
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
