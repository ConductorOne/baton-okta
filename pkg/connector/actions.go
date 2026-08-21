package connector

import (
	"context"
	"fmt"
	"sort"
	"strings"

	config "github.com/conductorone/baton-sdk/pb/c1/config/v1"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/actions"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

// Argument names shared by this file's update_user (global) action.
const (
	argUserID      = "user_id"
	argUserProfile = "user_profile"
)

var disableUser = &v2.BatonActionSchema{
	Name: "disable_user",
	Arguments: []*config.Field{
		{
			Name:        argUserID,
			DisplayName: "User ID",
			Field:       &config.Field_StringField{},
			IsRequired:  true,
		},
	},
	ReturnTypes: []*config.Field{
		{
			Name:        actionResultSuccess,
			DisplayName: actionResultSuccessDisplay,
			Field:       &config.Field_BoolField{},
		},
		{
			Name:        "message",
			DisplayName: "Message",
			Field:       &config.Field_StringField{},
		},
	},
	ActionType: []v2.ActionType{
		v2.ActionType_ACTION_TYPE_ACCOUNT,
		v2.ActionType_ACTION_TYPE_ACCOUNT_DISABLE,
	},
}

var enableUser = &v2.BatonActionSchema{
	Name: "enable_user",
	Arguments: []*config.Field{
		{
			Name:        argUserID,
			DisplayName: "User ID",
			Field:       &config.Field_StringField{},
			IsRequired:  true,
		},
	},
	ReturnTypes: []*config.Field{
		{
			Name:        actionResultSuccess,
			DisplayName: actionResultSuccessDisplay,
			Field:       &config.Field_BoolField{},
		},
		{
			Name:        "message",
			DisplayName: "Message",
			Field:       &config.Field_StringField{},
		},
	},
	ActionType: []v2.ActionType{
		v2.ActionType_ACTION_TYPE_ACCOUNT,
		v2.ActionType_ACTION_TYPE_ACCOUNT_ENABLE,
	},
}

var deactivateUserActionSchema = &v2.BatonActionSchema{
	Name:        "deactivate_user",
	DisplayName: "Deactivate User",
	Description: "Destructively deprovisions an Okta user from assigned applications while retaining the Okta user record.",
	Arguments: []*config.Field{
		{
			Name:        argUserID,
			DisplayName: userResourceTypeDisplayName,
			Description: "The Okta user to deactivate.",
			Field: &config.Field_ResourceIdField{
				ResourceIdField: &config.ResourceIdField{
					Rules: &config.ResourceIDRules{
						AllowedResourceTypeIds: []string{userResourceTypeID},
					},
				},
			},
			IsRequired: true,
		},
	},
	ReturnTypes: []*config.Field{
		{
			Name:        actionResultSuccess,
			DisplayName: actionResultSuccessDisplay,
			Field:       &config.Field_BoolField{},
		},
		{
			Name:        "message",
			DisplayName: "Message",
			Field:       &config.Field_StringField{},
		},
	},
	ActionType: []v2.ActionType{
		v2.ActionType_ACTION_TYPE_RESOURCE_DISABLE,
	},
}

var deleteUserActionSchema = &v2.BatonActionSchema{
	Name:        "delete_user",
	DisplayName: "Delete User",
	Description: "Deactivates and then permanently deletes an Okta user. This operation cannot be recovered.",
	Arguments: []*config.Field{
		{
			Name:        argUserID,
			DisplayName: userResourceTypeDisplayName,
			Description: "The Okta user to permanently delete.",
			Field: &config.Field_ResourceIdField{
				ResourceIdField: &config.ResourceIdField{
					Rules: &config.ResourceIDRules{
						AllowedResourceTypeIds: []string{userResourceTypeID},
					},
				},
			},
			IsRequired: true,
		},
	},
	ReturnTypes: []*config.Field{
		{
			Name:        actionResultSuccess,
			DisplayName: actionResultSuccessDisplay,
			Field:       &config.Field_BoolField{},
		},
		{
			Name:        "message",
			DisplayName: "Message",
			Field:       &config.Field_StringField{},
		},
	},
	ActionType: []v2.ActionType{
		v2.ActionType_ACTION_TYPE_RESOURCE_DELETE,
	},
}

var updateUserSchema = &v2.BatonActionSchema{
	Name:        "update_user",
	DisplayName: "Update User",
	Description: "Updates a user's profile attributes from a user_profile JSON object. Used by C1's automated " +
		"profile-push pipeline; for manual invocation with individual typed fields, use update_profile instead.",
	Arguments: []*config.Field{
		{
			Name:        argUserID,
			DisplayName: "User Resource ID",
			Description: "The ID of the user to update.",
			Field:       &config.Field_StringField{StringField: &config.StringField{}},
			IsRequired:  true,
		},
		{
			Name:        argUserProfile,
			DisplayName: "User Profile Data",
			Description: "A JSON object of Okta profile attributes to update.",
			Field:       &config.Field_StringField{StringField: &config.StringField{}},
			IsRequired:  true,
		},
	},
	ReturnTypes: []*config.Field{
		{Name: actionResultSuccess, DisplayName: actionResultSuccessDisplay, Field: &config.Field_BoolField{}},
		{Name: "updated_fields", DisplayName: "Updated Fields", Field: &config.Field_StringField{}},
	},
	ActionType: []v2.ActionType{
		v2.ActionType_ACTION_TYPE_ACCOUNT,
		v2.ActionType_ACTION_TYPE_ACCOUNT_UPDATE_PROFILE,
	},
}

var _ connectorbuilder.GlobalActionProvider = (*Okta)(nil)
var _ connectorbuilder.ResourceActionProvider = (*userResourceType)(nil)

func (o *Okta) GlobalActions(ctx context.Context, registry actions.ActionRegistry) error {
	if err := registry.Register(ctx, enableUser, o.enableUser); err != nil {
		return fmt.Errorf("okta-connectorv2: register enable_user action: %w", err)
	}
	if err := registry.Register(ctx, disableUser, o.disableUser); err != nil {
		return fmt.Errorf("okta-connectorv2: register disable_user action: %w", err)
	}
	if err := registry.Register(ctx, updateUserSchema, o.updateUserActionHandler); err != nil {
		return fmt.Errorf("okta-connectorv2: register update_user action: %w", err)
	}
	return nil
}

// ResourceActions registers every resource-scoped action on the user
// resource type: deactivate_user/delete_user (deprovisioning, this file)
// and update_profile (pkg/connector/user_actions.go).
func (o *userResourceType) ResourceActions(ctx context.Context, registry actions.ActionRegistry) error {
	if err := registry.Register(ctx, deactivateUserActionSchema, o.deactivateUserAction); err != nil {
		return fmt.Errorf("okta-connectorv2: register deactivate_user resource action: %w", err)
	}
	if err := registry.Register(ctx, deleteUserActionSchema, o.deleteUserAction); err != nil {
		return fmt.Errorf("okta-connectorv2: register delete_user resource action: %w", err)
	}
	if err := registry.Register(ctx, updateUserProfileSchema, o.updateUserProfile); err != nil {
		return fmt.Errorf("okta-connectorv2: register update_profile resource action: %w", err)
	}
	return nil
}

// updateUserActionHandler handles the global update_user action — the shape
// C1's automated profile-push pipeline looks up. It accepts any Okta profile
// attribute (no curated allowlist, unlike update_profile) and shares
// partialUpdateUserProfile with the resource-scoped action, intentionally
// skipping the v2.Resource rebuild that applyUserProfileUpdate does — so a
// resource-construction failure can never make update_user report a failed
// action for an Okta write that already landed.
func (o *Okta) updateUserActionHandler(ctx context.Context, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	userID, err := actions.RequireStringArg(args, argUserID)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "okta-connectorv2: update-user: %v", err)
	}

	rawProfile, err := profileArgAsMap(args, argUserProfile)
	if err != nil {
		return nil, nil, err
	}

	profile, err := buildOktaProfileFromMap(rawProfile)
	if err != nil {
		return nil, nil, err
	}

	l.Debug("okta-connectorv2: update-user: updating user",
		zap.String(argUserID, userID),
		zap.Int("fields", len(profile)),
	)

	if _, err := partialUpdateUserProfile(ctx, o.client, userID, profile); err != nil {
		return nil, nil, err
	}

	updatedFields := make([]string, 0, len(profile))
	for k := range profile {
		updatedFields = append(updatedFields, k)
	}
	sort.Strings(updatedFields)

	result, err := structpb.NewStruct(map[string]interface{}{
		actionResultSuccess: true,
		"updated_fields":    strings.Join(updatedFields, ", "),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: update-user: failed to build result: %w", err)
	}
	return result, nil, nil
}

// lifecycleTransitionFunc is one Okta lifecycle call (activate, unsuspend, suspend).
type lifecycleTransitionFunc func(ctx context.Context, client *okta.Client, oktaUserID string) error

// lifecyclePlan is how an action treats the account's current Okta status.
type lifecyclePlan int

const (
	planAlreadySatisfied lifecyclePlan = iota // already in the requested state
	planTransition                            // call a lifecycle endpoint
	planUnsupported                           // no transition this action supports
)

// planUserLifecycle selects the Okta endpoint for the requested enabled state.
func planUserLifecycle(oktaStatus string, enabled bool) (lifecyclePlan, lifecycleTransitionFunc) {
	if enabled {
		switch oktaStatus {
		case userStatusStaged:
			return planTransition, activateUser
		case userStatusSuspended:
			return planTransition, unsuspendUser
		default:
			if isEnabledOktaStatus(oktaStatus) {
				return planAlreadySatisfied, nil
			}
		}
		return planUnsupported, nil
	}

	if isDisabledOktaStatus(oktaStatus) {
		return planAlreadySatisfied, nil
	}
	if isEnabledOktaStatus(oktaStatus) {
		return planTransition, suspendUser
	}
	return planUnsupported, nil
}

// enableUser activates a STAGED account or unsuspends a SUSPENDED one. Requires user_id.
// Already-enabled accounts succeed without calling Okta.
func (o *Okta) enableUser(ctx context.Context, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
	return o.applyUserLifecycle(ctx, args, true)
}

// disableUser suspends the subject Okta account. Requires user_id. Accounts nobody can
// sign in to succeed without calling Okta.
func (o *Okta) disableUser(ctx context.Context, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
	return o.applyUserLifecycle(ctx, args, false)
}

// deactivateUserAction deprovisions the selected Okta user but retains the
// DEPROVISIONED user object for an explicit later deletion.
func (o *userResourceType) deactivateUserAction(ctx context.Context, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
	oktaUserID, err := userIDFromResourceActionArgs(args)
	if err != nil {
		return nil, nil, err
	}

	deactivated, missing, err := ensureUserDeactivated(ctx, o.connector.client, oktaUserID)
	if err != nil {
		return nil, nil, err
	}
	if missing {
		return nil, nil, status.Errorf(codes.NotFound, "okta-connectorv2: user %s not found", oktaUserID)
	}
	if !deactivated {
		return createSuccessResponse(fmt.Sprintf("Account %s was already deactivated", oktaUserID)), nil, nil
	}
	return createSuccessResponse(fmt.Sprintf("Account %s has been successfully deactivated", oktaUserID)), nil, nil
}

// deleteUserAction guarantees permanent deletion, including Okta's required
// deactivation transition.
func (o *userResourceType) deleteUserAction(ctx context.Context, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
	oktaUserID, err := userIDFromResourceActionArgs(args)
	if err != nil {
		return nil, nil, err
	}

	deleted, err := permanentlyDeleteUser(ctx, o.connector.client, oktaUserID)
	if err != nil {
		return nil, nil, err
	}
	if !deleted {
		return createSuccessResponse(fmt.Sprintf("Account %s was already deleted", oktaUserID)), nil, nil
	}
	return createSuccessResponse(fmt.Sprintf("Account %s has been permanently deleted", oktaUserID)), nil, nil
}

func userIDFromResourceActionArgs(args *structpb.Struct) (string, error) {
	resourceID, err := actions.RequireResourceIDArg(args, argUserID)
	if err != nil {
		return "", status.Errorf(codes.InvalidArgument, "okta-connectorv2: %v", err)
	}
	return oktaUserIDFromResourceID(resourceID)
}

// applyUserLifecycle reads status and applies the required Okta transition.
// Okta lifecycle endpoints each accept one source status. enabled=true enables;
// enabled=false disables.
func (o *Okta) applyUserLifecycle(ctx context.Context, args *structpb.Struct, enabled bool) (*structpb.Struct, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	oktaUserID, err := extractFieldAsString(args, argUserID)
	if err != nil {
		return nil, nil, err
	}
	verb := "disable"
	pastTense := "disabled"
	if enabled {
		verb = "enable"
		pastTense = "enabled"
	}
	l.Debug("running account lifecycle action",
		zap.String("action", verb),
		zap.String("oktaUserID", oktaUserID),
	)

	currentStatus, err := o.userStatus(ctx, oktaUserID)
	if err != nil {
		return nil, nil, err
	}

	plan, transition := planUserLifecycle(currentStatus, enabled)
	switch plan {
	case planAlreadySatisfied:
		return createSuccessResponse(fmt.Sprintf("Account %s was already %s (Okta status %s)", oktaUserID, pastTense, currentStatus)), nil, nil
	case planUnsupported:
		return nil, nil, status.Errorf(
			codes.FailedPrecondition,
			"okta-connectorv2: cannot %s user %s from Okta status %s",
			verb, oktaUserID, currentStatus,
		)
	case planTransition:
		// fall through
	}

	if err := transition(ctx, o.client, oktaUserID); err != nil {
		return nil, nil, err
	}

	return createSuccessResponse(fmt.Sprintf("Account %s has been successfully %s", oktaUserID, pastTense)), nil, nil
}

// userStatus returns the Okta lifecycle status used to plan the action.
func (o *Okta) userStatus(ctx context.Context, oktaUserID string) (string, error) {
	return getUserStatus(ctx, o.client, oktaUserID)
}
