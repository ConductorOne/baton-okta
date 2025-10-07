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

var disableAccount = &v2.BatonActionSchema{
	Name: "disableAccount",
	Arguments: []*config.Field{
		{
			Name:        "accountId",
			DisplayName: "Account ID",
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
	},
	ActionType: []v2.ActionType{
		v2.ActionType_ACTION_TYPE_ACCOUNT,
		v2.ActionType_ACTION_TYPE_ACCOUNT_DISABLE,
	},
}

var enableAccount = &v2.BatonActionSchema{
	Name: "enableAccount",
	Arguments: []*config.Field{
		{
			Name:        "accountId",
			DisplayName: "Account ID",
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
	},
	ActionType: []v2.ActionType{
		v2.ActionType_ACTION_TYPE_ACCOUNT,
		v2.ActionType_ACTION_TYPE_ACCOUNT_ENABLE,
	},
}

func (o *Okta) RegisterActionManager(ctx context.Context) (connectorbuilder.CustomActionManager, error) {
	actionManager := actions.NewActionManager(ctx)

	err := actionManager.RegisterAction(ctx, enableAccount.Name, enableAccount, o.enableAccount)
	if err != nil {
		return nil, err
	}

	err = actionManager.RegisterAction(ctx, disableAccount.Name, disableAccount, o.disableAccount)
	if err != nil {
		return nil, err
	}

	return actionManager, nil
}

// enableAccount "unsuspends" the subject Okta account.
func (o *Okta) enableAccount(ctx context.Context, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	if args == nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: no arguments provided")
	}

	if args.Fields == nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: no fields provided")
	}

	accountID := args.Fields["accountId"].GetStringValue()
	if accountID == "" {
		return nil, nil, fmt.Errorf("okta-connectorv2: account ID cannot be empty")
	}
	l.Debug("enabling account", zap.String("accountID", accountID))

	err := unsuspendUser(ctx, o.client, accountID)
	if err != nil {
		// if user is already active, do not surface the error and instead respond with
		// success since the state of the account matches the requested state
		if strings.Contains(err.Error(), "Cannot unsuspend a user that is not suspended") {
			// TODO: Update baton-sdk to handle an annotation in order to notify the
			// user that the user is already suspended.
			l.Debug("user is already enabled.")
		} else {
			return nil, nil, err
		}
	}

	response := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"success": structpb.NewBoolValue(true),
		},
	}

	return response, nil, nil
}

// disableAccount suspends the subject Okta account.
func (o *Okta) disableAccount(ctx context.Context, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	if args == nil || args.Fields == nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: invalid arguments provided")
	}

	accountID := args.Fields["accountId"].GetStringValue()
	if accountID == "" {
		return nil, nil, fmt.Errorf("okta-connectorv2: account ID cannot be empty")
	}
	l.Debug("disabling account", zap.String("accountID", accountID))

	err := suspendUser(ctx, o.client, accountID)
	if err != nil {
		// if user is already suspended, do not surface the error and instead respond
		// with success since the state of the account matches the requested state
		if strings.Contains(err.Error(), "Cannot suspend a user that is not active") {
			// TODO: Update baton-sdk to handle an annotation in order to notify the
			// user that the user is already suspended.
			l.Debug("user is already suspended.")
		} else {
			return nil, nil, err
		}
	}

	response := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"success": structpb.NewBoolValue(true),
		},
	}

	return response, nil, nil
}
