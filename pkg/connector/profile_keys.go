package connector

const (
	profileFieldName        = "name"
	profileFieldDescription = "description"
	profileFieldLabel       = "label"
	profileFieldLogin       = "login"
)

const (
	actionResultSuccess        = "success"
	actionResultSuccessDisplay = "Success"
)

const userResourceTypeID = "user"

const (
	profileFieldCreateInactive               = "create_inactive"
	profileFieldAdditionalAttributes         = "additionalAttributes"
	profileFieldPasswordChangeOnLoginRequired = "password_change_on_login_required"
)

// protectedOktaProfileFields lists the core profile keys set explicitly during
// account creation. additionalAttributes entries cannot override these.
var protectedOktaProfileFields = map[string]bool{
	"firstName": true,
	"lastName":  true,
	"email":     true,
	"login":     true,
}
