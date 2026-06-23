package connector

import (
	"context"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"google.golang.org/protobuf/types/known/structpb"
)

// FDE-178 / RFC §8.5 gap-R6: user resources must carry a V1Identifier
// annotation so v1→v2 migration can map them.
func TestUserResource_HasV1Identifier(t *testing.T) {
	const userID = "00u1abc2def3GHI4jk5"

	profile := okta.UserProfile{
		"firstName":   "Test",
		"lastName":    "User",
		"email":       "test.user@example.com",
		"login":       "test.user@example.com",
		"displayName": "Test User",
	}
	user := &okta.User{
		Id:      userID,
		Status:  userStatusActive,
		Profile: &profile,
	}

	got, err := userResource(context.Background(), user, false)
	if err != nil {
		t.Fatalf("userResource returned error: %v", err)
	}
	if got == nil {
		t.Fatalf("userResource returned nil resource")
	}

	annos := annotations.Annotations(got.GetAnnotations())
	v1id := &v2.V1Identifier{}
	found, err := annos.Pick(v1id)
	if err != nil {
		t.Fatalf("Pick(V1Identifier) returned error: %v", err)
	}
	if !found {
		t.Fatalf("user resource is missing V1Identifier annotation")
	}

	want := fmtResourceIdV1(userID)
	if v1id.GetId() != want {
		t.Errorf("V1Identifier id = %q, want %q", v1id.GetId(), want)
	}
}

func Test_shouldIncludeUserByEmails(t *testing.T) {
	type args struct {
		userEmails         []string
		emailDomainFilters []string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "should include user by email",
			args: args{
				userEmails:         []string{"alice@foo.com"},
				emailDomainFilters: []string{"foo.com"},
			},
			want: true,
		},
		{
			name: "no match",
			args: args{
				userEmails:         []string{"alice@foo.com"},
				emailDomainFilters: []string{"example.com"},
			},
			want: false,
		},
		{
			name: "no match, user email domain is a substring",
			args: args{
				userEmails:         []string{"alice@foo.com"},
				emailDomainFilters: []string{"food.com"},
			},
			want: false,
		},
		{
			name: "multiple filters",
			args: args{
				userEmails:         []string{"alice@foo.com"},
				emailDomainFilters: []string{"example.com", "foo.com"},
			},
			want: true,
		},
		{
			name: "no filters",
			args: args{
				userEmails:         []string{"alice@foo.com"},
				emailDomainFilters: []string{},
			},
			want: false,
		},
		{
			name: "no filters (nil list)",
			args: args{
				userEmails:         []string{"alice@foo.com"},
				emailDomainFilters: nil,
			},
			want: false,
		},
		{
			name: "empty filters (has capacity)",
			args: args{
				userEmails:         []string{"alice@foo.com"},
				emailDomainFilters: make([]string, 0, 100),
			},
			want: false,
		},
		{
			name: "one empty email in list",
			args: args{
				userEmails:         []string{""},
				emailDomainFilters: []string{"foo.com"},
			},
			want: false,
		},
		{
			name: "one empty email, one matching email in list",
			args: args{
				userEmails:         []string{"", "alice@foo.com"},
				emailDomainFilters: []string{"foo.com"},
			},
			want: true,
		},
		{
			name: "no emails in list",
			args: args{
				userEmails:         []string{},
				emailDomainFilters: []string{"foo.com"},
			},
			want: false,
		},
		{
			name: "nil email list",
			args: args{
				userEmails:         nil,
				emailDomainFilters: []string{"foo.com"},
			},
			want: false,
		},
		{
			name: "empty email list (has capacity)",
			args: args{
				userEmails:         make([]string, 0, 100),
				emailDomainFilters: []string{"foo.com"},
			},
			want: false,
		},
		{
			name: "multiple emails, no match",
			args: args{
				userEmails:         []string{"alice@foo.com", "bob@example.com"},
				emailDomainFilters: []string{"test.com"},
			},
			want: false,
		},
		{
			name: "multiple emails, multiple matches",
			args: args{
				userEmails:         []string{"alice@foo.com", "bob@example.com"},
				emailDomainFilters: []string{"foo.com", "example.com"},
			},
			want: true,
		},
		{
			name: "multiple emails, single match",
			args: args{
				userEmails:         []string{"alice@foo.com", "bob@example.com", "carlos@test.com"},
				emailDomainFilters: []string{"test.com"},
			},
			want: true,
		},
		{
			name: "mixed case match",
			args: args{
				userEmails:         []string{"alice@fOo.cOm"},
				emailDomainFilters: []string{"foo.com"},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldIncludeUserByEmails(tt.args.userEmails, tt.args.emailDomainFilters); got != tt.want {
				t.Errorf("shouldIncludeUserByEmails() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetUserProfile(t *testing.T) {
	tests := []struct {
		name       string
		profile    map[string]interface{}
		wantKeys   []string
		wantAbsent []string
		wantErr    bool
	}{
		{
			name: "core fields only",
			profile: map[string]interface{}{
				"first_name": "Ada",
				"last_name":  "Lovelace",
				"email":      "ada@example.com",
				"login":      "ada@example.com",
			},
			wantKeys: []string{"firstName", "lastName", "email", "login"},
		},
		{
			name: "login defaults to email",
			profile: map[string]interface{}{
				"first_name": "Ada",
				"last_name":  "Lovelace",
				"email":      "ada@example.com",
			},
			wantKeys: []string{"firstName", "lastName", "email", "login"},
		},
		{
			name: "additionalAttributes merged",
			profile: map[string]interface{}{
				"first_name": "Ada",
				"last_name":  "Lovelace",
				"email":      "ada@example.com",
				"login":      "ada@example.com",
				"additionalAttributes": map[string]interface{}{
					"city":       "London",
					"department": "Engineering",
				},
			},
			wantKeys: []string{"firstName", "lastName", "email", "login", "city", "department"},
		},
		{
			name: "additionalAttributes absent",
			profile: map[string]interface{}{
				"first_name": "Ada",
				"last_name":  "Lovelace",
				"email":      "ada@example.com",
				"login":      "ada@example.com",
			},
			wantKeys:   []string{"firstName", "lastName", "email", "login"},
			wantAbsent: []string{"city"},
		},
		{
			name: "additionalAttributes wrong type silently ignored",
			profile: map[string]interface{}{
				"first_name":           "Ada",
				"last_name":            "Lovelace",
				"email":                "ada@example.com",
				"login":                "ada@example.com",
				"additionalAttributes": "not-a-map",
			},
			wantKeys:   []string{"firstName", "lastName", "email", "login"},
			wantAbsent: []string{"additionalAttributes"},
		},
		{
			name: "protected field rejected",
			profile: map[string]interface{}{
				"first_name": "Ada",
				"last_name":  "Lovelace",
				"email":      "ada@example.com",
				"login":      "ada@example.com",
				"additionalAttributes": map[string]interface{}{
					"firstName": "Override",
				},
			},
			wantErr: true,
		},
		{
			name: "missing required email",
			profile: map[string]interface{}{
				"first_name": "Ada",
				"last_name":  "Lovelace",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := structpb.NewStruct(tt.profile)
			if err != nil {
				t.Fatalf("structpb.NewStruct: %v", err)
			}
			accountInfo := &v2.AccountInfo{Profile: s}

			got, err := getUserProfile(accountInfo)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			for _, k := range tt.wantKeys {
				if _, ok := (*got)[k]; !ok {
					t.Errorf("profile missing key %q", k)
				}
			}
			for _, k := range tt.wantAbsent {
				if _, ok := (*got)[k]; ok {
					t.Errorf("profile unexpectedly contains key %q", k)
				}
			}
		})
	}
}
