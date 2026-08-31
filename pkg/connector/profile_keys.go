package connector

const (
	profileFieldName        = "name"
	profileFieldDescription = "description"
	profileFieldLabel       = "label"
	profileFieldFirstName   = "first_name"
	profileFieldLastName    = "last_name"
	profileFieldEmail       = "email"
	profileFieldLogin       = "login"
)

const (
	// Okta user-profile attribute names (camelCase). email/login match the
	// schema keys above, so those reuse profileFieldEmail / profileFieldLogin.
	oktaAttrFirstName = "firstName"
	oktaAttrLastName  = "lastName"
)

const (
	actionResultSuccess        = "success"
	actionResultSuccessDisplay = "Success"
	actionResultMessage        = "message"
	actionResultMessageDisplay = "Message"
)

const (
	userResourceTypeID          = "user"
	userResourceTypeDisplayName = "User"
)

// oktaLogTargetTypeUser is the target type Okta uses on LogEvent objects. It happens to
// match the resource type's display name, but it is a wire value, so renaming the display
// name must not silently change the event-feed lookups.
const oktaLogTargetTypeUser = "User"

// Okta reports assignment and unassignment of standard admin roles under the same
// user.account.privilege.grant event type and distinguishes them with an extra
// target carrying one of these types. Wire values, like oktaLogTargetTypeUser.
const (
	oktaLogTargetRoleAssigned   = "ROLE_ASSIGNED"
	oktaLogTargetRoleUnassigned = "ROLE_UNASSIGNED"
)

const (
	profileFieldCreateInactive                = "create_inactive"
	profileFieldAdditionalAttributes          = "additionalAttributes"
	profileFieldPasswordChangeOnLoginRequired = "password_change_on_login_required"
	profileFieldSendActivationEmail           = "send_activation_email"
	profileFieldProviderType                  = "provider_type"
)

const (
	providerTypeOkta       = "OKTA"
	providerTypeFederation = "FEDERATION"
)

// placeholderBoolean is the account creation schema placeholder for fields parsed
// with strconv.ParseBool.
const placeholderBoolean = "True/False"

const (
	groupSourceTypeBuiltIn     = "built_in"
	groupSourceTypeAppImported = "app_imported"
	groupSourceTypeNative      = "native"
)

// protectedOktaProfileFields lists the core profile keys set explicitly during
// account creation. additionalAttributes entries cannot override these.
var protectedOktaProfileFields = map[string]bool{
	oktaAttrFirstName: true,
	oktaAttrLastName:  true,
	profileFieldEmail: true,
	profileFieldLogin: true,
}
