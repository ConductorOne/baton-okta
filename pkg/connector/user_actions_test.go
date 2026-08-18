package connector

import (
	"context"
	"reflect"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestBuildUpdateProfileMap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		argsMap map[string]interface{}
		want    okta.UserProfile
		wantErr bool
	}{
		{
			name:    "no fields yields empty profile",
			argsMap: map[string]interface{}{},
			want:    okta.UserProfile{},
		},
		{
			name:    "empty string field is forwarded as an explicit clear",
			argsMap: map[string]interface{}{oktaAttrFirstName: ""},
			want:    okta.UserProfile{oktaAttrFirstName: ""},
		},
		{
			name:    "single named field is included",
			argsMap: map[string]interface{}{"firstName": "Jane"},
			want:    okta.UserProfile{"firstName": "Jane"},
		},
		{
			name:    "managerId maps through unchanged",
			argsMap: map[string]interface{}{"managerId": "00u123"},
			want:    okta.UserProfile{"managerId": "00u123"},
		},
		{
			name: "named fields plus additionalAttributes merge",
			argsMap: map[string]interface{}{
				"firstName": "Jane",
				"lastName":  "Doe",
				"additionalAttributes": map[string]interface{}{
					"nickName": "J",
				},
			},
			want: okta.UserProfile{
				"firstName": "Jane",
				"lastName":  "Doe",
				"nickName":  "J",
			},
		},
		{
			name:    "wrong-typed named field errors",
			argsMap: map[string]interface{}{"firstName": float64(1)},
			wantErr: true,
		},
		{
			name: "additionalAttributes colliding with a named field errors",
			argsMap: map[string]interface{}{
				"additionalAttributes": map[string]interface{}{"firstName": "override"},
			},
			wantErr: true,
		},
		{
			name:    "wrong-typed additionalAttributes errors",
			argsMap: map[string]interface{}{"additionalAttributes": "bad"},
			wantErr: true,
		},
		{
			name: "additionalAttributes accepts non-string scalar values",
			argsMap: map[string]interface{}{
				"additionalAttributes": map[string]interface{}{"isVip": true, "score": float64(5)},
			},
			want: okta.UserProfile{"isVip": true, "score": float64(5)},
		},
		{
			name: "additionalAttributes rejects a nested object value",
			argsMap: map[string]interface{}{
				"additionalAttributes": map[string]interface{}{"nickName": map[string]interface{}{"nested": true}},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := buildUpdateProfileMap(tt.argsMap)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("buildUpdateProfileMap() = %v, want %v", got, tt.want)
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("key %q = %v, want %v", k, got[k], v)
				}
			}
		})
	}
}

func TestUpdateUserProfileSchema_Shape(t *testing.T) {
	t.Parallel()

	if updateUserProfileSchema.Name != "update_profile" {
		t.Errorf("Name = %q, want update_profile", updateUserProfileSchema.Name)
	}
	if len(updateUserProfileSchema.ActionType) != 1 || updateUserProfileSchema.ActionType[0] != v2.ActionType_ACTION_TYPE_ACCOUNT_UPDATE_PROFILE {
		t.Errorf("ActionType = %v, want only ACTION_TYPE_ACCOUNT_UPDATE_PROFILE", updateUserProfileSchema.ActionType)
	}

	var sawUserID, sawAdditional bool
	for _, arg := range updateUserProfileSchema.Arguments {
		switch arg.Name {
		case "user_id":
			sawUserID = true
			if !arg.IsRequired {
				t.Error("user_id must be required")
			}
			rf := arg.GetResourceIdField()
			if rf == nil {
				t.Fatal("user_id must be a ResourceIdField")
			}
			if got := rf.GetRules().GetAllowedResourceTypeIds(); len(got) != 1 || got[0] != userResourceTypeID {
				t.Errorf("user_id AllowedResourceTypeIds = %v, want [%q]", got, userResourceTypeID)
			}
		case profileFieldAdditionalAttributes:
			sawAdditional = true
			if arg.GetStringMapField() == nil {
				t.Error("additionalAttributes must be a StringMapField")
			}
		}
	}
	if !sawUserID {
		t.Error("schema missing user_id argument")
	}
	if !sawAdditional {
		t.Error("schema missing additionalAttributes argument")
	}

	for _, field := range updateProfileNamedFields {
		found := false
		for _, arg := range updateUserProfileSchema.Arguments {
			if arg.Name == field {
				found = true
				if arg.GetStringField() == nil {
					t.Errorf("argument %q must be a StringField", field)
				}
				break
			}
		}
		if !found {
			t.Errorf("schema missing named field argument %q", field)
		}
	}

	var sawSuccess bool
	for _, rt := range updateUserProfileSchema.ReturnTypes {
		if rt.Name == actionResultSuccess {
			sawSuccess = true
			if !rt.HasBoolField() {
				t.Error("success return field must be a BoolField")
			}
		}
	}
	if !sawSuccess {
		t.Error("schema missing success return field")
	}
}

func TestUpdateUserProfile_ValidationErrors(t *testing.T) {
	t.Parallel()

	o := &userResourceType{connector: &Okta{}}

	tests := []struct {
		name string
		args *structpb.Struct
	}{
		{
			name: "missing user_id",
			args: mustStruct(t, map[string]interface{}{}),
		},
		{
			name: "empty user_id",
			args: mustStruct(t, map[string]interface{}{
				"user_id": map[string]interface{}{"resource_id": "", "resource_type_id": userResourceTypeID},
			}),
		},
		{
			name: "no profile fields provided",
			args: mustStruct(t, map[string]interface{}{
				"user_id": map[string]interface{}{"resource_id": "00u1", "resource_type_id": userResourceTypeID},
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, _, err := o.updateUserProfile(context.Background(), tt.args)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestUserResourceType_ResourceActions_RegistersUpdateProfile(t *testing.T) {
	t.Parallel()

	fake := newFakeActionRegistry()
	o := &userResourceType{connector: &Okta{}}

	if err := o.ResourceActions(context.Background(), fake); err != nil {
		t.Fatalf("ResourceActions() error = %v", err)
	}

	schema, ok := fake.registered[updateUserProfileSchema.GetName()]
	if !ok {
		t.Fatalf("ResourceActions() did not register %q", updateUserProfileSchema.GetName())
	}
	if schema != updateUserProfileSchema {
		t.Error("registered schema is not the expected schema instance")
	}
}

func TestApplyUserProfileUpdate_EmptyUserID(t *testing.T) {
	t.Parallel()

	// nil client is safe here: the empty-userID guard must return before the
	// client is ever dereferenced.
	_, err := applyUserProfileUpdate(context.Background(), nil, false, "", okta.UserProfile{"firstName": "Jane"})
	if err == nil {
		t.Fatal("expected error for empty user_id, got nil")
	}
}

func mustStruct(t *testing.T, m map[string]interface{}) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(m)
	if err != nil {
		t.Fatalf("failed to build struct: %v", err)
	}
	return s
}

func TestProfileArgAsMap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		args    *structpb.Struct
		want    map[string]interface{}
		wantErr bool
	}{
		{
			name:    "missing key errors",
			args:    mustStruct(t, map[string]interface{}{}),
			wantErr: true,
		},
		{
			name: "JSON string is parsed",
			args: mustStruct(t, map[string]interface{}{
				"user_profile": `{"firstName":"Jane","title":"Engineer"}`,
			}),
			want: map[string]interface{}{"firstName": "Jane", "title": "Engineer"},
		},
		{
			name: "invalid JSON string errors",
			args: mustStruct(t, map[string]interface{}{
				"user_profile": `not json`,
			}),
			wantErr: true,
		},
		{
			name: "nested struct is accepted",
			args: mustStruct(t, map[string]interface{}{
				"user_profile": map[string]interface{}{"firstName": "Jane"},
			}),
			want: map[string]interface{}{"firstName": "Jane"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := profileArgAsMap(tt.args, "user_profile")
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("profileArgAsMap() = %v, want %v", got, tt.want)
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("key %q = %v, want %v", k, got[k], v)
				}
			}
		})
	}
}

func TestBuildOktaProfileFromMap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     map[string]interface{}
		want    okta.UserProfile
		wantErr bool
	}{
		{
			name:    "empty map errors (nothing to update)",
			raw:     map[string]interface{}{},
			wantErr: true,
		},
		{
			name: "accepts a field outside Shape B's curated list",
			raw:  map[string]interface{}{"preferredLanguage": "en-US"},
			want: okta.UserProfile{"preferredLanguage": "en-US"},
		},
		{
			name: "forwards explicit empty-string and null values instead of dropping them",
			raw:  map[string]interface{}{"firstName": "", oktaAttrMiddleName: nil, "lastName": "Doe"},
			want: okta.UserProfile{"firstName": "", oktaAttrMiddleName: nil, "lastName": "Doe"},
		},
		{
			name:    "nested object value errors",
			raw:     map[string]interface{}{"firstName": map[string]interface{}{"nested": true}},
			wantErr: true,
		},
		{
			name: "bool value is accepted",
			raw:  map[string]interface{}{"someFlag": true},
			want: okta.UserProfile{"someFlag": true},
		},
		{
			name: "float64 value is accepted",
			raw:  map[string]interface{}{oktaAttrEmployeeNumber: float64(42)},
			want: okta.UserProfile{oktaAttrEmployeeNumber: float64(42)},
		},
		{
			name: "string array value is accepted",
			raw:  map[string]interface{}{"tags": []interface{}{"a", "b"}},
			want: okta.UserProfile{"tags": []interface{}{"a", "b"}},
		},
		{
			name:    "array with non-string element errors",
			raw:     map[string]interface{}{"tags": []interface{}{"a", 5}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := buildOktaProfileFromMap(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("buildOktaProfileFromMap() = %v, want %v", got, tt.want)
			}
			for k, v := range tt.want {
				if _, isSlice := v.([]interface{}); isSlice {
					if !reflect.DeepEqual(got[k], v) {
						t.Errorf("key %q = %v, want %v", k, got[k], v)
					}
					continue
				}
				if got[k] != v {
					t.Errorf("key %q = %v, want %v", k, got[k], v)
				}
			}
		})
	}
}
