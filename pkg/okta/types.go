package okta

import (
	"encoding/json"
	"time"
)

// The types below carry only the fields the connector reads or sends. JSON
// tags and omitempty behavior match the Okta API (and the request bodies the
// connector has always sent), so adding a field later is backwards compatible.

// UserProfile is a user's profile. Okta profiles are schema-extensible, so it
// stays a map.
type UserProfile map[string]any

// User is an Okta user.
// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/User/
type User struct {
	Created   *time.Time   `json:"created,omitempty"`
	Id        string       `json:"id,omitempty"`
	LastLogin *time.Time   `json:"lastLogin,omitempty"`
	Profile   *UserProfile `json:"profile,omitempty"`
	Status    string       `json:"status,omitempty"`
}

// CreateUserRequest is the body of POST /api/v1/users.
type CreateUserRequest struct {
	Credentials *UserCredentials `json:"credentials,omitempty"`
	Profile     *UserProfile     `json:"profile,omitempty"`
	Type        *UserType        `json:"type,omitempty"`
}

// UserType identifies how a user was created.
type UserType struct {
	Created   *time.Time `json:"created,omitempty"`
	CreatedBy string     `json:"createdBy,omitempty"`
}

// UserCredentials are the credentials sent when creating a user.
type UserCredentials struct {
	Password *PasswordCredential     `json:"password,omitempty"`
	Provider *AuthenticationProvider `json:"provider,omitempty"`
}

// PasswordCredential is a plaintext password credential.
type PasswordCredential struct {
	Value string `json:"value,omitempty"`
}

// AuthenticationProvider is the provider that masters a user's credentials.
type AuthenticationProvider struct {
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
}

// Group is an Okta group.
// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Group/
type Group struct {
	Embedded any           `json:"_embedded,omitempty"`
	Id       string        `json:"id,omitempty"`
	Profile  *GroupProfile `json:"profile,omitempty"`
	Type     string        `json:"type,omitempty"`
}

// GroupProfile is a group's name and description. Okta always receives both
// keys, so an empty description clears it.
type GroupProfile struct {
	Description string `json:"description"`
	Name        string `json:"name"`
}

// Role is an admin role assignment.
// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleAssignment/
type Role struct {
	AssignmentType string     `json:"assignmentType,omitempty"`
	Created        *time.Time `json:"created,omitempty"`
	Description    string     `json:"description,omitempty"`
	Id             string     `json:"id,omitempty"`
	Label          string     `json:"label,omitempty"`
	Status         string     `json:"status,omitempty"`
	Type           string     `json:"type,omitempty"`
}

// AssignRoleRequest assigns a standard role by type.
type AssignRoleRequest struct {
	Type string `json:"type,omitempty"`
}

// Application is an Okta app instance.
// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Application/
type Application struct {
	Id         string `json:"id,omitempty"`
	Label      string `json:"label,omitempty"`
	SignOnMode string `json:"signOnMode,omitempty"`
	Status     string `json:"status,omitempty"`
}

// AppUser is a user's assignment to an app.
type AppUser struct {
	Credentials *AppUserCredentials `json:"credentials,omitempty"`
	Id          string              `json:"id,omitempty"`
	Profile     any                 `json:"profile,omitempty"`
	Scope       string              `json:"scope,omitempty"`
	Status      string              `json:"status,omitempty"`
}

// AppUserCredentials are the app-level credentials of an app user.
type AppUserCredentials struct {
	UserName string `json:"userName"`
}

// ApplicationGroupAssignment is a group's assignment to an app.
type ApplicationGroupAssignment struct {
	Embedded any    `json:"_embedded,omitempty"`
	Id       string `json:"id,omitempty"`
	Profile  any    `json:"profile,omitempty"`
}

// OrgSetting is the org's settings; the connector only checks that it loads.
type OrgSetting struct {
	Id string `json:"id,omitempty"`
}

// LogEvent is a System Log event.
// https://developer.okta.com/docs/reference/api/system-log/#logevent-object
type LogEvent struct {
	Actor          *LogActor    `json:"actor,omitempty"`
	DisplayMessage string       `json:"displayMessage,omitempty"`
	EventType      string       `json:"eventType,omitempty"`
	Outcome        *LogOutcome  `json:"outcome,omitempty"`
	Published      *time.Time   `json:"published,omitempty"`
	Target         []*LogTarget `json:"target,omitempty"`
	UUID           string       `json:"uuid,omitempty"`
}

// LogActor is the entity that performed a logged action.
type LogActor struct {
	AlternateId string `json:"alternateId,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	Id          string `json:"id,omitempty"`
	Type        string `json:"type,omitempty"`
}

// LogTarget is an entity a logged action was performed on.
type LogTarget struct {
	AlternateId string `json:"alternateId,omitempty"`
	DetailEntry any    `json:"detailEntry,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	Id          string `json:"id,omitempty"`
	Type        string `json:"type,omitempty"`
}

// LogOutcome is the result of a logged action.
type LogOutcome struct {
	Reason string `json:"reason,omitempty"`
	Result string `json:"result,omitempty"`
}

// APIToken is an Okta API token's metadata (never its value).
// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/ApiToken/
type APIToken struct {
	Created     *time.Time `json:"created,omitempty"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"`
	Id          *string    `json:"id,omitempty"`
	LastUpdated *time.Time `json:"lastUpdated,omitempty"`
	Name        string     `json:"name"`
	UserId      *string    `json:"userId,omitempty"`
}

// Device is an entry from the device list.
// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Device/
type Device struct {
	Id      *string        `json:"id,omitempty"`
	Profile *DeviceProfile `json:"profile,omitempty"`
}

// GetId returns the device ID, or "".
func (d *Device) GetId() string {
	if d == nil || d.Id == nil {
		return ""
	}
	return *d.Id
}

// DeviceProfile is the subset of a device profile the connector reads.
type DeviceProfile struct {
	DisplayName  string  `json:"displayName"`
	Manufacturer *string `json:"manufacturer,omitempty"`
	Model        *string `json:"model,omitempty"`
	OsVersion    *string `json:"osVersion,omitempty"`
	Platform     string  `json:"platform"`
	SerialNumber *string `json:"serialNumber,omitempty"`
	Udid         *string `json:"udid,omitempty"`
}

func strOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (p *DeviceProfile) GetDisplayName() string {
	if p == nil {
		return ""
	}
	return p.DisplayName
}

func (p *DeviceProfile) GetPlatform() string {
	if p == nil {
		return ""
	}
	return p.Platform
}

func (p *DeviceProfile) GetManufacturer() string { return strOrEmpty(p.Manufacturer) }
func (p *DeviceProfile) GetModel() string        { return strOrEmpty(p.Model) }
func (p *DeviceProfile) GetOsVersion() string    { return strOrEmpty(p.OsVersion) }
func (p *DeviceProfile) GetSerialNumber() string { return strOrEmpty(p.SerialNumber) }
func (p *DeviceProfile) GetUdid() string         { return strOrEmpty(p.Udid) }

// ResourceSet is an IAM resource set.
// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleCResourceSet/
type ResourceSet struct {
	Description *string `json:"description,omitempty"`
	Id          *string `json:"id,omitempty"`
	Label       *string `json:"label,omitempty"`
}

func (r *ResourceSet) GetId() string {
	if r == nil {
		return ""
	}
	return strOrEmpty(r.Id)
}

func (r *ResourceSet) GetLabel() string {
	if r == nil {
		return ""
	}
	return strOrEmpty(r.Label)
}

func (r *ResourceSet) GetDescription() string {
	if r == nil {
		return ""
	}
	return strOrEmpty(r.Description)
}

// SetId sets the resource set ID.
func (r *ResourceSet) SetId(id string) { r.Id = &id }

// ResourceSetBinding is a role bound to a resource set.
type ResourceSetBinding struct {
	Id *string `json:"id,omitempty"`
}

// RawMessage is re-exported so callers decoding loosely typed responses do not
// need to import encoding/json just for it.
type RawMessage = json.RawMessage
