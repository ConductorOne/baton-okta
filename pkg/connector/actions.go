package connector

import (
	"context"
	"fmt"

	config "github.com/conductorone/baton-sdk/pb/c1/config/v1"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/actions"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

var disableUser = &v2.BatonActionSchema{
	Name: "disable_user",
	Arguments: []*config.Field{
		{
			Name:        "user_id",
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
			Name:        "user_id",
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

func (o *Okta) GlobalActions(ctx context.Context, registry actions.ActionRegistry) error {
	if err := registry.Register(ctx, enableUser, o.enableUser); err != nil {
		return err
	}
	if err := registry.Register(ctx, disableUser, o.disableUser); err != nil {
		return err
	}
	return nil
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

func isRequestedOktaStatus(oktaStatus string, enabled bool) bool {
	if enabled {
		return isEnabledOktaStatus(oktaStatus)
	}
	return isDisabledOktaStatus(oktaStatus)
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

// applyUserLifecycle reads status, applies the required Okta transition, and confirms it.
// Okta lifecycle endpoints each accept one source status; success names the status
// the account actually reached. enabled=true enables; enabled=false disables.
func (o *Okta) applyUserLifecycle(ctx context.Context, args *structpb.Struct, enabled bool) (*structpb.Struct, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	oktaUserID, err := extractFieldAsString(args, "user_id")
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
		// Concurrent change may reject the call while the account is already satisfied.
		finalStatus, statusErr := o.userStatus(ctx, oktaUserID)
		if statusErr != nil || !isRequestedOktaStatus(finalStatus, enabled) {
			return nil, nil, err
		}
		l.Debug("lifecycle call failed but the account is in the requested state",
			zap.String("action", verb),
			zap.String("oktaUserID", oktaUserID),
			zap.String("okta_status", finalStatus),
			zap.Error(err),
		)
		return createSuccessResponse(fmt.Sprintf("Account %s was already %s (Okta status %s)", oktaUserID, pastTense, finalStatus)), nil, nil
	}

	finalStatus, err := o.userStatus(ctx, oktaUserID)
	if err != nil {
		return nil, nil, err
	}
	if !isRequestedOktaStatus(finalStatus, enabled) {
		return nil, nil, status.Errorf(
			codes.Internal,
			"okta-connectorv2: %s of user %s returned success but the account is in Okta status %s",
			verb, oktaUserID, finalStatus,
		)
	}

	return createSuccessResponse(fmt.Sprintf("Account %s has been successfully %s (Okta status %s)", oktaUserID, pastTense, finalStatus)), nil, nil
}

// userStatus returns the live Okta lifecycle status (uncached).
func (o *Okta) userStatus(ctx context.Context, oktaUserID string) (string, error) {
	user, _, err := getUserUncached(ctx, o.client, oktaUserID)
	if err != nil {
		return "", fmt.Errorf("okta-connectorv2: failed to find user %s: %w", oktaUserID, err)
	}
	if user == nil {
		return "", status.Errorf(codes.NotFound, "okta-connectorv2: user %s not found", oktaUserID)
	}

	return user.Status, nil
}
