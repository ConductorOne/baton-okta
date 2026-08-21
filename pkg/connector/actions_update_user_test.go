package connector

import (
	"context"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/actions"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

// fakeActionRegistry is a minimal recording implementation of
// actions.ActionRegistry, used to verify that GlobalActions/ResourceActions
// actually wire their schemas into the registry rather than merely defining
// package-level schema vars that nothing registers.
type fakeActionRegistry struct {
	registered map[string]*v2.BatonActionSchema
}

func newFakeActionRegistry() *fakeActionRegistry {
	return &fakeActionRegistry{registered: make(map[string]*v2.BatonActionSchema)}
}

func (f *fakeActionRegistry) Register(_ context.Context, schema *v2.BatonActionSchema, _ actions.ActionHandler) error {
	f.registered[schema.GetName()] = schema
	return nil
}

func (f *fakeActionRegistry) RegisterAction(_ context.Context, name string, schema *v2.BatonActionSchema, _ actions.ActionHandler) error {
	f.registered[name] = schema
	return nil
}

func TestOkta_GlobalActions_RegistersExpectedActions(t *testing.T) {
	t.Parallel()

	fake := newFakeActionRegistry()
	o := &Okta{}

	if err := o.GlobalActions(context.Background(), fake); err != nil {
		t.Fatalf("GlobalActions() error = %v", err)
	}

	for _, want := range []*v2.BatonActionSchema{enableUser, disableUser, updateUserSchema} {
		got, ok := fake.registered[want.GetName()]
		if !ok {
			t.Errorf("GlobalActions() did not register %q", want.GetName())
			continue
		}
		if got != want {
			t.Errorf("registered schema for %q is not the expected schema instance", want.GetName())
		}
	}
}

func TestUpdateUserSchema_Shape(t *testing.T) {
	t.Parallel()

	if updateUserSchema.Name != "update_user" {
		t.Errorf("Name = %q, want update_user", updateUserSchema.Name)
	}
	wantTypes := map[v2.ActionType]bool{
		v2.ActionType_ACTION_TYPE_ACCOUNT:                true,
		v2.ActionType_ACTION_TYPE_ACCOUNT_UPDATE_PROFILE: true,
	}
	if len(updateUserSchema.ActionType) != len(wantTypes) {
		t.Fatalf("ActionType = %v, want exactly %v", updateUserSchema.ActionType, wantTypes)
	}
	for _, at := range updateUserSchema.ActionType {
		if !wantTypes[at] {
			t.Errorf("unexpected ActionType %v", at)
		}
	}

	var sawUserID, sawProfile bool
	for _, arg := range updateUserSchema.Arguments {
		switch arg.Name {
		case "user_id":
			sawUserID = true
			if !arg.IsRequired || arg.GetStringField() == nil {
				t.Error("user_id must be a required StringField")
			}
		case "user_profile":
			sawProfile = true
			if !arg.IsRequired || arg.GetStringField() == nil {
				t.Error("user_profile must be a required StringField")
			}
		}
	}
	if !sawUserID || !sawProfile {
		t.Error("schema missing user_id or user_profile argument")
	}
}

func TestUpdateUserActionHandler_ValidationErrors(t *testing.T) {
	t.Parallel()

	o := &Okta{}

	tests := []struct {
		name     string
		args     *structpb.Struct
		wantCode codes.Code
	}{
		{
			name: "missing user_id",
			args: mustStruct(t, map[string]interface{}{
				"user_profile": `{"firstName":"Jane"}`,
			}),
			wantCode: codes.InvalidArgument,
		},
		{
			name: "missing user_profile",
			args: mustStruct(t, map[string]interface{}{
				"user_id": "00u1",
			}),
			wantCode: codes.InvalidArgument,
		},
		{
			name: "empty user_id string",
			args: mustStruct(t, map[string]interface{}{
				"user_id":      "",
				"user_profile": `{"firstName":"Jane"}`,
			}),
			wantCode: codes.InvalidArgument,
		},
		{
			// An empty JSON object has no fields at all. Note that
			// `{"firstName":""}` is NOT an example of this anymore: since
			// buildOktaProfileFromMap now forwards explicit empty-string
			// values (Okta clears a profile attribute on receiving one),
			// that payload has one usable field.
			name: "user_profile is an empty object",
			args: mustStruct(t, map[string]interface{}{
				"user_id":      "00u1",
				"user_profile": `{}`,
			}),
			wantCode: codes.InvalidArgument,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, _, err := o.updateUserActionHandler(context.Background(), tt.args)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if got := status.Code(err); got != tt.wantCode {
				t.Errorf("status code = %v, want %v", got, tt.wantCode)
			}
		})
	}
}
