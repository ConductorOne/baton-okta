package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

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

// Okta user-profile attribute names (camelCase) for the update_profile
// action's remaining named fields. firstName/lastName already have
// package-level constants (oktaAttrFirstName / oktaAttrLastName) declared in
// profile_keys.go, so those are reused rather than redeclared here.
const (
	oktaAttrSecondEmail    = "secondEmail"
	oktaAttrMiddleName     = "middleName"
	oktaAttrDisplayName    = "displayName"
	oktaAttrTitle          = "title"
	oktaAttrDepartment     = "department"
	oktaAttrDivision       = "division"
	oktaAttrOrganization   = "organization"
	oktaAttrEmployeeNumber = "employeeNumber"
	oktaAttrCostCenter     = "costCenter"
	oktaAttrUserType       = "userType"
	oktaAttrPrimaryPhone   = "primaryPhone"
	oktaAttrMobilePhone    = "mobilePhone"
	oktaAttrCountryCode    = "countryCode"
	oktaAttrManagerID      = "managerId"
)

// updateProfileNamedFields are the Okta profile attributes exposed as named
// arguments on the update_profile action. Names match Okta's API attribute
// names directly — no snake_case aliasing, unlike the account-creation
// schema's profileField* constants.
var updateProfileNamedFields = []string{
	profileFieldLogin,
	profileFieldEmail,
	oktaAttrSecondEmail,
	oktaAttrFirstName,
	oktaAttrLastName,
	oktaAttrMiddleName,
	oktaAttrDisplayName,
	oktaAttrTitle,
	oktaAttrDepartment,
	oktaAttrDivision,
	oktaAttrOrganization,
	oktaAttrEmployeeNumber,
	oktaAttrCostCenter,
	oktaAttrUserType,
	oktaAttrPrimaryPhone,
	oktaAttrMobilePhone,
	oktaAttrCountryCode,
	oktaAttrManagerID,
}

// buildUpdateProfileMap builds the partial-update profile map for the
// update_profile action from its already-flattened argument map (see
// structpb.Struct.AsMap). A field genuinely absent from argsMap (or
// explicitly nil) is left untouched by Okta's partial update semantics. A
// field explicitly present with an empty string is forwarded to Okta as an
// empty string, not silently dropped — but that sets the attribute to
// present-but-empty, it does not clear it (Okta only clears an attribute on
// receiving an explicit null; see docs/docs-info.md). Named fields skip nil
// above, so update_profile has no way to send a null and can never actually
// clear a named attribute — only set it to empty. additionalAttributes
// entries are merged in last and may not override a named field.
func buildUpdateProfileMap(argsMap map[string]interface{}) (okta.UserProfile, error) {
	profile := okta.UserProfile{}
	named := make(map[string]bool, len(updateProfileNamedFields))

	for _, field := range updateProfileNamedFields {
		named[field] = true

		v, present := argsMap[field]
		if !present || v == nil {
			continue
		}

		s, ok := v.(string)
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument, "okta-connectorv2: update-user-profile: %s must be a string, got %T", field, v)
		}
		profile[field] = s
	}

	additional, err := parseObjectProfileField(argsMap, profileFieldAdditionalAttributes)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "okta-connectorv2: update-user-profile: %v", err)
	}
	for k, v := range additional {
		if named[k] {
			return nil, status.Errorf(codes.InvalidArgument, "okta-connectorv2: update-user-profile: additionalAttributes cannot override named field %q", k)
		}
		val, err := validateOktaProfileValue(k, v)
		if err != nil {
			return nil, err
		}
		profile[k] = val
	}

	return profile, nil
}

var updateUserProfileSchema = &v2.BatonActionSchema{
	Name:        "update_profile",
	DisplayName: "Update User Profile",
	Description: "Update an existing Okta user's profile attributes",
	ActionType:  []v2.ActionType{v2.ActionType_ACTION_TYPE_ACCOUNT_UPDATE_PROFILE},

	Arguments: []*config.Field{
		{
			Name:        argUserID,
			DisplayName: userResourceTypeDisplayName,
			Description: "The user to update",
			IsRequired:  true,
			Field: &config.Field_ResourceIdField{
				ResourceIdField: &config.ResourceIdField{
					Rules: &config.ResourceIDRules{
						AllowedResourceTypeIds: []string{userResourceTypeID},
					},
				},
			},
		},
		{
			Name:        profileFieldLogin,
			DisplayName: profileFieldLogin,
			Description: "The user's username (Okta profile attribute login)",
			Field:       &config.Field_StringField{StringField: &config.StringField{}},
		},
		{
			Name:        profileFieldEmail,
			DisplayName: profileFieldEmail,
			Description: "The user's primary email address (Okta profile attribute email)",
			Field:       &config.Field_StringField{StringField: &config.StringField{}},
		},
		{
			Name:        oktaAttrSecondEmail,
			DisplayName: "secondEmail",
			Description: "The user's secondary email address (Okta profile attribute secondEmail)",
			Field:       &config.Field_StringField{StringField: &config.StringField{}},
		},
		{
			Name:        oktaAttrFirstName,
			DisplayName: oktaAttrFirstName,
			Description: "The user's first name (Okta profile attribute firstName)",
			Field:       &config.Field_StringField{StringField: &config.StringField{}},
		},
		{
			Name:        oktaAttrLastName,
			DisplayName: oktaAttrLastName,
			Description: "The user's last name (Okta profile attribute lastName)",
			Field:       &config.Field_StringField{StringField: &config.StringField{}},
		},
		{
			Name:        oktaAttrMiddleName,
			DisplayName: "middleName",
			Description: "The user's middle name (Okta profile attribute middleName)",
			Field:       &config.Field_StringField{StringField: &config.StringField{}},
		},
		{
			Name:        oktaAttrDisplayName,
			DisplayName: "displayName",
			Description: "The user's display name (Okta profile attribute displayName)",
			Field:       &config.Field_StringField{StringField: &config.StringField{}},
		},
		{Name: oktaAttrTitle, DisplayName: oktaAttrTitle, Description: "The user's job title (Okta profile attribute title)", Field: &config.Field_StringField{StringField: &config.StringField{}}},
		{
			Name:        oktaAttrDepartment,
			DisplayName: oktaAttrDepartment,
			Description: "The user's department (Okta profile attribute department)",
			Field:       &config.Field_StringField{StringField: &config.StringField{}},
		},
		{Name: oktaAttrDivision, DisplayName: "division", Description: "The user's division (Okta profile attribute division)", Field: &config.Field_StringField{StringField: &config.StringField{}}},
		{
			Name:        oktaAttrOrganization,
			DisplayName: "organization",
			Description: "The user's organization (Okta profile attribute organization)",
			Field:       &config.Field_StringField{StringField: &config.StringField{}},
		},
		{
			Name:        oktaAttrEmployeeNumber,
			DisplayName: "employeeNumber",
			Description: "The user's employee number (Okta profile attribute employeeNumber)",
			Field:       &config.Field_StringField{StringField: &config.StringField{}},
		},
		{
			Name:        oktaAttrCostCenter,
			DisplayName: "costCenter",
			Description: "The user's cost center (Okta profile attribute costCenter)",
			Field:       &config.Field_StringField{StringField: &config.StringField{}},
		},
		{
			Name:        oktaAttrUserType,
			DisplayName: "userType",
			Description: "The user's employment type (Okta profile attribute userType)",
			Field:       &config.Field_StringField{StringField: &config.StringField{}},
		},
		{
			Name:        oktaAttrPrimaryPhone,
			DisplayName: "primaryPhone",
			Description: "The user's primary phone number (Okta profile attribute primaryPhone)",
			Field:       &config.Field_StringField{StringField: &config.StringField{}},
		},
		{
			Name:        oktaAttrMobilePhone,
			DisplayName: "mobilePhone",
			Description: "The user's mobile phone number (Okta profile attribute mobilePhone)",
			Field:       &config.Field_StringField{StringField: &config.StringField{}},
		},
		{
			Name:        oktaAttrCountryCode,
			DisplayName: "countryCode",
			Description: "The user's country code, ISO 3166 (Okta profile attribute countryCode)",
			Field:       &config.Field_StringField{StringField: &config.StringField{}},
		},
		{
			Name:        oktaAttrManagerID,
			DisplayName: oktaAttrManagerID,
			Description: "The Okta user ID of the user's manager (Okta profile attribute managerId)",
			Field:       &config.Field_StringField{StringField: &config.StringField{}},
		},
		{
			Name:        profileFieldAdditionalAttributes,
			DisplayName: "Additional Attributes",
			Description: "Additional Okta profile attributes to set (e.g. custom schema attributes). Use the raw Okta attribute name as the key.",
			Field:       &config.Field_StringMapField{StringMapField: &config.StringMapField{}},
		},
	},

	ReturnTypes: []*config.Field{
		{
			Name:        actionResultSuccess,
			DisplayName: actionResultSuccessDisplay,
			Field:       &config.Field_BoolField{},
		},
		{
			Name:        "updated_user",
			DisplayName: "Updated User",
			Field:       &config.Field_ResourceField{},
		},
	},
}

// updateUserProfile handles the update_profile action. It sends a single
// partial-update POST to Okta (client.User.PartialUpdateUser), which merges
// only the profile keys present in the request — untouched fields are left
// alone by Okta itself, so no read-modify-write is needed here.
func (o *userResourceType) updateUserProfile(ctx context.Context, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	userID, err := userIDFromResourceActionArgs(args)
	if err != nil {
		return nil, nil, err
	}

	profile, err := buildUpdateProfileMap(args.AsMap())
	if err != nil {
		return nil, nil, err
	}
	if len(profile) == 0 {
		return nil, nil, status.Errorf(codes.InvalidArgument, "okta-connectorv2: update-user-profile: no profile fields provided to update")
	}

	l.Debug("okta-connectorv2: update-user-profile: updating user",
		zap.String(argUserID, userID),
		zap.Int("fields", len(profile)),
	)

	updatedResource, err := applyUserProfileUpdate(ctx, o.connector.client, o.connector.skipSecondaryEmails, userID, profile)
	if err != nil {
		return nil, nil, err
	}

	return buildUpdateProfileResponse(updatedResource)
}

func buildUpdateProfileResponse(resource *v2.Resource) (*structpb.Struct, annotations.Annotations, error) {
	returnField, err := actions.NewResourceReturnField("updated_user", resource)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: update-user-profile: failed to create resource return field: %w", err)
	}
	return actions.NewReturnValues(true, returnField), nil, nil
}

// partialUpdateUserProfile sends the single atomic partial-update POST and
// returns the raw updated Okta user, without building a v2.Resource. Used
// directly by the global update_user action, which doesn't need the
// resource — this means a resource-construction failure (see
// applyUserProfileUpdate) can never cause update_user to report a failed
// action for a write that actually landed in Okta.
func partialUpdateUserProfile(ctx context.Context, client *okta.Client, userID string, profile okta.UserProfile) (*okta.User, error) {
	if userID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "okta-connectorv2: update-user-profile: user_id cannot be empty")
	}

	updatedUser, resp, err := client.User.PartialUpdateUser(ctx, userID, okta.User{Profile: &profile}, nil)
	if err != nil {
		return nil, handleOktaResponseErrorWithNotFoundMessage(resp, err, "user not found")
	}
	if resp != nil && resp.StatusCode != http.StatusOK {
		return nil, status.Errorf(codes.Internal, "okta-connectorv2: update-user-profile: unexpected status updating user %s: %s", userID, resp.Status)
	}
	if updatedUser == nil || updatedUser.Profile == nil {
		return nil, status.Errorf(codes.Internal, "okta-connectorv2: update-user-profile: empty response updating user %s", userID)
	}
	return updatedUser, nil
}

// applyUserProfileUpdate sends a single partial-update POST for userID's
// profile and rebuilds the updated resource from the response. Used by the
// resource-scoped update_profile action, which returns the resource to the
// caller.
func applyUserProfileUpdate(ctx context.Context, client *okta.Client, skipSecondaryEmails bool, userID string, profile okta.UserProfile) (*v2.Resource, error) {
	updatedUser, err := partialUpdateUserProfile(ctx, client, userID, profile)
	if err != nil {
		return nil, err
	}

	updatedResource, err := userResource(updatedUser, skipSecondaryEmails)
	if err != nil {
		return nil, fmt.Errorf("okta-connectorv2: update-user-profile: failed to build updated user resource: %w", err)
	}
	return updatedResource, nil
}

// profileArgAsMap accepts user_profile as either a JSON string (how C1's
// push-rule pipeline sends it) or a nested struct (manual invocation) — the
// caller determines which, so both are handled.
func profileArgAsMap(args *structpb.Struct, key string) (map[string]interface{}, error) {
	v, ok := args.GetFields()[key]
	if !ok || v == nil {
		return nil, status.Errorf(codes.InvalidArgument, "okta-connectorv2: update-user: %s is required", key)
	}
	switch k := v.GetKind().(type) {
	case *structpb.Value_StringValue:
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(k.StringValue), &m); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "okta-connectorv2: update-user: invalid %s JSON: %v", key, err)
		}
		return m, nil
	case *structpb.Value_StructValue:
		return k.StructValue.AsMap(), nil
	default:
		return nil, status.Errorf(codes.InvalidArgument, "okta-connectorv2: update-user: invalid %s format", key)
	}
}

// buildOktaProfileFromMap converts a parsed user_profile map into an
// okta.UserProfile for the global update_user action. Unlike
// buildUpdateProfileMap (Shape B), every key is accepted as-is — no curated
// allowlist — because this action exists specifically so a push rule (or any
// caller with a full profile payload) can set arbitrary Okta profile
// attributes; a restrictive allowlist would defeat that purpose.
//
// Every key in raw is forwarded through to the resulting profile, including
// explicit nil and empty-string values: Okta clears a profile attribute when
// it receives null for that field, so silently dropping nil/empty values
// would turn an intended clear into a no-op. Accepted value types are JSON
// scalars (string, bool, float64 — the type json.Unmarshal produces for a
// JSON number) plus []interface{} where every element is a string, matching
// the attribute types Okta profile schemas support (including custom
// schema attributes). Nested objects/maps and arrays containing non-string
// elements are rejected, since Okta profiles don't support them.
func buildOktaProfileFromMap(raw map[string]interface{}) (okta.UserProfile, error) {
	profile := okta.UserProfile{}
	for k, v := range raw {
		val, err := validateOktaProfileValue(k, v)
		if err != nil {
			return nil, err
		}
		profile[k] = val
	}
	if len(profile) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "okta-connectorv2: update-user: no profile fields provided to update")
	}
	return profile, nil
}

// validateOktaProfileValue checks that a raw JSON-decoded value is a type
// Okta profile attributes actually support — a JSON scalar (nil, string,
// bool, or float64 for a JSON number) or an array of strings — and returns
// it unchanged if so. Nested objects/maps and arrays containing a
// non-string element are rejected, since Okta profiles don't support them.
// Shared by buildOktaProfileFromMap (update_user's whole payload) and
// buildUpdateProfileMap (update_profile's additionalAttributes) so both
// entry points reject the same unsupported shapes locally instead of
// surfacing an opaque Okta 400.
func validateOktaProfileValue(key string, v interface{}) (interface{}, error) {
	switch val := v.(type) {
	case nil, string, bool, float64:
		return val, nil
	case []interface{}:
		for _, item := range val {
			if _, ok := item.(string); !ok {
				return nil, status.Errorf(codes.InvalidArgument, "okta-connectorv2: profile field %q array elements must be strings, got %T", key, item)
			}
		}
		return val, nil
	default:
		return nil, status.Errorf(codes.InvalidArgument, "okta-connectorv2: profile field %q has unsupported type %T", key, v)
	}
}
