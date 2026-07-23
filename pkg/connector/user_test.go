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

func TestGetAccountCreationQueryParams(t *testing.T) {
	noPassword := v2.LocalCredentialOptions_builder{
		NoPassword: &v2.LocalCredentialOptions_NoPassword{},
	}.Build()

	randomPassword := v2.LocalCredentialOptions_builder{
		RandomPassword: &v2.LocalCredentialOptions_RandomPassword{Length: 12},
	}.Build()

	tests := []struct {
		name          string
		profile       map[string]interface{}
		creds         *v2.LocalCredentialOptions
		providerType  string
		wantActivate  *bool  // nil means we don't care / field should be unset
		wantNextLogin string // empty means field should be unset
		wantProvider  bool
		wantSuppress  bool
		wantErr       bool
	}{
		{
			name:    "all defaults no-password",
			profile: map[string]interface{}{},
			creds:   noPassword,
		},
		{
			name: "create_inactive true bool no-password",
			profile: map[string]interface{}{
				"create_inactive": true,
			},
			creds:        noPassword,
			wantActivate: boolPtr(false),
		},
		{
			name: "create_inactive true string no-password",
			profile: map[string]interface{}{
				"create_inactive": "true",
			},
			creds:        noPassword,
			wantActivate: boolPtr(false),
		},
		{
			name: "create_inactive wins over password_change",
			profile: map[string]interface{}{
				"create_inactive":                   true,
				"password_change_on_login_required": true,
			},
			creds:         randomPassword,
			wantActivate:  boolPtr(false),
			wantNextLogin: "",
		},
		{
			name: "password_change_on_login_required with random-password",
			profile: map[string]interface{}{
				"password_change_on_login_required": true,
			},
			creds:         randomPassword,
			wantActivate:  boolPtr(true),
			wantNextLogin: "changePassword",
		},
		{
			name: "password_change_on_login_required ignored for no-password",
			profile: map[string]interface{}{
				"password_change_on_login_required": true,
			},
			creds: noPassword,
		},
		{
			name: "create_inactive invalid string",
			profile: map[string]interface{}{
				"create_inactive": "yes",
			},
			creds:   noPassword,
			wantErr: true,
		},
		{
			name:    "all defaults random-password",
			profile: map[string]interface{}{},
			creds:   randomPassword,
		},
		{
			name: "send_activation_email absent keeps default behavior",
			profile: map[string]interface{}{
				"send_activation_email": nil,
			},
			creds: noPassword,
		},
		{
			name: "send_activation_email true explicit keeps default behavior",
			profile: map[string]interface{}{
				"send_activation_email": true,
			},
			creds: noPassword,
		},
		{
			name: "send_activation_email false bool stages and suppresses",
			profile: map[string]interface{}{
				"send_activation_email": false,
			},
			creds:        noPassword,
			wantActivate: boolPtr(false),
			wantSuppress: true,
		},
		{
			name: "send_activation_email false string stages and suppresses",
			profile: map[string]interface{}{
				"send_activation_email": "false",
			},
			creds:        noPassword,
			wantActivate: boolPtr(false),
			wantSuppress: true,
		},
		{
			name: "create_inactive wins over send_activation_email false",
			profile: map[string]interface{}{
				"create_inactive":       true,
				"send_activation_email": false,
			},
			creds:        noPassword,
			wantActivate: boolPtr(false),
			wantSuppress: false,
		},
		{
			name: "send_activation_email invalid string",
			profile: map[string]interface{}{
				"send_activation_email": "nope",
			},
			creds:   noPassword,
			wantErr: true,
		},
		{
			name: "send_activation_email false conflicts with password_change",
			profile: map[string]interface{}{
				"send_activation_email":             false,
				"password_change_on_login_required": true,
			},
			creds:   randomPassword,
			wantErr: true,
		},
		{
			name:         "federation provider sets provider query param",
			profile:      map[string]interface{}{},
			creds:        noPassword,
			providerType: providerTypeFederation,
			wantProvider: true,
		},
		{
			name:         "okta provider does not set provider query param",
			profile:      map[string]interface{}{},
			creds:        noPassword,
			providerType: providerTypeOkta,
			wantProvider: false,
		},
		{
			name: "federation provider with send_activation_email false stages and sets provider",
			profile: map[string]interface{}{
				"send_activation_email": false,
			},
			creds:        noPassword,
			providerType: providerTypeFederation,
			wantActivate: boolPtr(false),
			wantProvider: true,
			wantSuppress: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := structpb.NewStruct(tt.profile)
			if err != nil {
				t.Fatalf("structpb.NewStruct: %v", err)
			}
			accountInfo := &v2.AccountInfo{Profile: s}

			got, suppress, err := getAccountCreationQueryParams(accountInfo, tt.creds, tt.providerType)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Check Activate
			if tt.wantActivate == nil {
				if got != nil && got.Activate != nil {
					t.Errorf("Activate = %v, want nil", *got.Activate)
				}
			} else {
				if got == nil || got.Activate == nil {
					t.Fatalf("Activate is nil, want %v", *tt.wantActivate)
				}
				if *got.Activate != *tt.wantActivate {
					t.Errorf("Activate = %v, want %v", *got.Activate, *tt.wantActivate)
				}
			}

			// Check NextLogin
			if got != nil && got.NextLogin != tt.wantNextLogin {
				t.Errorf("NextLogin = %q, want %q", got.NextLogin, tt.wantNextLogin)
			}

			// Check Provider query param
			gotProvider := false
			if got != nil {
				if b, ok := got.Provider.(bool); ok {
					gotProvider = b
				}
			}
			if gotProvider != tt.wantProvider {
				t.Errorf("Provider = %v, want %v", gotProvider, tt.wantProvider)
			}

			if suppress != tt.wantSuppress {
				t.Errorf("suppress = %v, want %v", suppress, tt.wantSuppress)
			}
		})
	}
}

func TestGetProviderType(t *testing.T) {
	tests := []struct {
		name    string
		profile map[string]interface{}
		want    string
		wantErr bool
	}{
		{
			name:    "absent defaults to empty",
			profile: map[string]interface{}{},
			want:    "",
		},
		{
			name: "explicit nil defaults to empty",
			profile: map[string]interface{}{
				"provider_type": nil,
			},
			want: "",
		},
		{
			name: "okta uppercase",
			profile: map[string]interface{}{
				"provider_type": "OKTA",
			},
			want: providerTypeOkta,
		},
		{
			name: "federation lowercase normalized",
			profile: map[string]interface{}{
				"provider_type": "federation",
			},
			want: providerTypeFederation,
		},
		{
			name: "federation with surrounding whitespace",
			profile: map[string]interface{}{
				"provider_type": "  FEDERATION  ",
			},
			want: providerTypeFederation,
		},
		{
			name: "unsupported value rejected",
			profile: map[string]interface{}{
				"provider_type": "SOCIAL",
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

			got, err := getProviderType(accountInfo)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("getProviderType() = %q, want %q", got, tt.want)
			}
		})
	}
}

func boolPtr(b bool) *bool { return &b }
