package connector

import (
	"context"
	"fmt"
	"strings"

	config "github.com/conductorone/baton-sdk/pb/c1/config/v1"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/actions"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
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
			Name:        "success",
			DisplayName: "Success",
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
			Name:        "success",
			DisplayName: "Success",
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

func (o *Okta) RegisterActionManager(ctx context.Context) (connectorbuilder.CustomActionManager, error) { //nolint:staticcheck // deprecated interface still required by SDK
	actionManager := actions.NewActionManager(ctx)

	err := actionManager.RegisterAction(ctx, enableUser.Name, enableUser, o.enableUser) //nolint:staticcheck // deprecated method still required by SDK
	if err != nil {
		return nil, err
	}

	err = actionManager.RegisterAction(ctx, disableUser.Name, disableUser, o.disableUser) //nolint:staticcheck // deprecated method still required by SDK
	if err != nil {
		return nil, err
	}

	return actionManager, nil
}

// enableUser "unsuspends" the subject Okta account.
//
// It requires the "user_id" field to be provided in the arguments struct,
// corresponding to the Okta user to be unsuspended.
//
// If the account is already active or not suspended, no error is returned and success is indicated.
// If unsuspension is successful or the status is already correct, a success response
// is returned. If any other error occurs during the unsuspension process, it is returned.
func (o *Okta) enableUser(ctx context.Context, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	oktaUserID, err := extractFieldAsString(args, "user_id")
	if err != nil {
		return nil, nil, err
	}
	l.Debug("enabling account", zap.String("oktaUserID", oktaUserID))

	err = unsuspendUser(ctx, o.client, oktaUserID)
	if err != nil {
		// if user is already active, do not surface the error and instead respond with
		// success since the state of the account matches the requested state
		if strings.Contains(err.Error(), "Cannot unsuspend a user that is not suspended") {
			// TODO: Update baton-sdk to handle an annotation in order to notify the
			// user that the user is already active.
			l.Debug("user is already enabled", zap.String("oktaUserID", oktaUserID))
			return createSuccessResponse(fmt.Sprintf("Account %s was already enabled", oktaUserID)), nil, nil
		}

		return nil, nil, err
	}

	return createSuccessResponse(fmt.Sprintf("Account %s has been successfully enabled", oktaUserID)), nil, nil
}

// disableUser suspends the subject Okta account.
//
// It requires the "user_id" field to be provided in the arguments struct,
// corresponding to the Okta user to be suspended.
//
// If the user is already suspended, no error is returned and success is indicated.
// If suspension is successful or the status is already correct, a success response
// is returned. If any other error occurs during the suspension process, it is returned.
func (o *Okta) disableUser(ctx context.Context, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	oktaUserID, err := extractFieldAsString(args, "user_id")
	if err != nil {
		return nil, nil, err
	}
	l.Debug("disabling account", zap.String("oktaUserID", oktaUserID))

	err = suspendUser(ctx, o.client, oktaUserID)
	if err != nil {
		// if user is already suspended, do not surface the error and instead respond
		// with success since the state of the account matches the requested state
		if strings.Contains(err.Error(), "Cannot suspend a user that is not active") {
			// TODO: Update baton-sdk to handle an annotation in order to notify the
			// user that the user is already suspended.
			l.Debug("user is already suspended", zap.String("oktaUserID", oktaUserID))
			return createSuccessResponse(fmt.Sprintf("Account %s was already disabled", oktaUserID)), nil, nil
		}

		return nil, nil, err
	}

	return createSuccessResponse(fmt.Sprintf("Account %s has been successfully disabled", oktaUserID)), nil, nil
}
