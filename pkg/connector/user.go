package connector

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/crypto"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/ratelimit"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"go.uber.org/zap"
)

const (
	unknownProfileValue       = "unknown"
	userStatusSuspended       = "SUSPENDED"
	userStatusDeprovisioned   = "DEPROVISIONED"
	userStatusActive          = "ACTIVE"
	userStatusLockedOut       = "LOCKED_OUT"
	userStatusPasswordExpired = "PASSWORD_EXPIRED"
	userStatusProvisioned     = "PROVISIONED"
	userStatusRecovery        = "RECOVERY"
	userStatusStaged          = "STAGED"
)

// oktaEnabledStatuses drives enable_user / disable_user only. Credential problems
// (RECOVERY, PASSWORD_EXPIRED, LOCKED_OUT) stay here — enable does not clear them.
// Sync maps the same "cannot sign in yet / anymore" set to RESOURCE_STATUS_DISABLED
// (STAGED, SUSPENDED, DEPROVISIONED) so C1 status matches lifecycle actions.
var oktaEnabledStatuses = []string{
	userStatusActive,
	userStatusProvisioned,
	userStatusRecovery,
	userStatusPasswordExpired,
	userStatusLockedOut,
}

// oktaDisabledStatuses: nobody can sign in (never activated, suspended, or deactivated).
var oktaDisabledStatuses = []string{
	userStatusStaged,
	userStatusSuspended,
	userStatusDeprovisioned,
}

func isEnabledOktaStatus(oktaStatus string) bool {
	return slices.Contains(oktaEnabledStatuses, oktaStatus)
}

func isDisabledOktaStatus(oktaStatus string) bool {
	return slices.Contains(oktaDisabledStatuses, oktaStatus)
}

type userResourceType struct {
	resourceType *v2.ResourceType
	connector    *Okta
}

func (o *userResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *userResourceType) List(
	ctx context.Context,
	resourceID *v2.ResourceId,
	attrs resource.SyncOpAttrs,
) ([]*v2.Resource, *resource.SyncOpResults, error) {
	token := &attrs.PageToken

	bag, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeUser.Id})
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	var rv []*v2.Resource
	qp := queryParams(token.Size, page)

	users, respCtx, err := listUsers(ctx, o.connector.client, token, qp)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to list users: %w", err)
	}

	nextPage, annos, err := parseResp(respCtx.OktaResponse)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
	}

	for _, user := range users {
		// for okta v2, we only attempt to filter users by email domains when a list is provided
		shouldInclude := o.connector.shouldIncludeUserAndSetCache(ctx, attrs.Session, user)
		if !shouldInclude {
			continue
		}
		resource, err := userResource(user, o.connector.skipSecondaryEmails)
		if err != nil {
			return nil, nil, err
		}

		rv = append(rv, resource)
	}

	pageToken, err := bag.Marshal()
	if err != nil {
		return nil, nil, err
	}

	return rv, &resource.SyncOpResults{NextPageToken: pageToken, Annotations: annos}, nil
}

// extractEmailsFromUserProfile safely extracts email addresses from a regular user profile.
// It checks for email, secondEmail, and login fields that contain email addresses.
func extractEmailsFromUserProfile(user *okta.User) []string {
	var userEmails []string

	// Check if profile exists
	if user == nil || user.Profile == nil {
		return userEmails
	}

	oktaProfile := *user.Profile

	// Extract primary email
	if email, ok := oktaProfile[profileFieldEmail].(string); ok && email != "" {
		userEmails = append(userEmails, email)
	}

	// Extract secondary email
	if secondEmail, ok := oktaProfile["secondEmail"].(string); ok && secondEmail != "" {
		userEmails = append(userEmails, secondEmail)
	}

	// Check if login field contains an email address
	if login, ok := oktaProfile[profileFieldLogin].(string); ok && login != "" {
		if strings.Contains(login, "@") {
			userEmails = append(userEmails, login)
		}
	}

	return userEmails
}

// extractEmailsFromAppUserProfile safely extracts email addresses from an app user profile.
// It checks for email, secondEmail, and login fields that contain email addresses.
func extractEmailsFromAppUserProfile(appUser *okta.AppUser) []string {
	var userEmails []string

	// Check if profile exists
	if appUser == nil || appUser.Profile == nil {
		return userEmails
	}

	// Type assert the profile to map[string]interface{}
	oktaProfile, ok := appUser.Profile.(map[string]interface{})
	if !ok {
		return userEmails
	}

	// Extract primary email
	if email, ok := oktaProfile[profileFieldEmail].(string); ok && email != "" {
		userEmails = append(userEmails, email)
	}

	// Extract secondary email
	if secondEmail, ok := oktaProfile["secondEmail"].(string); ok && secondEmail != "" {
		userEmails = append(userEmails, secondEmail)
	}

	// Check if login field contains an email address
	if login, ok := oktaProfile[profileFieldLogin].(string); ok && login != "" {
		if strings.Contains(login, "@") {
			userEmails = append(userEmails, login)
		}
	}

	return userEmails
}

func shouldIncludeOktaAppUser(u *okta.AppUser, emailDomainFilters []string) bool {
	userEmails := extractEmailsFromAppUserProfile(u)
	return shouldIncludeUserByEmails(userEmails, emailDomainFilters)
}

func shouldIncludeUserByEmails(userEmails []string, emailDomainFilters []string) bool {
	for _, filter := range emailDomainFilters {
		for _, ue := range userEmails {
			if strings.HasSuffix(strings.ToLower(ue), "@"+filter) {
				return true
			}
		}
	}
	return false
}

func (o *userResourceType) Entitlements(
	_ context.Context,
	resource *v2.Resource,
	_ resource.SyncOpAttrs,
) ([]*v2.Entitlement, *resource.SyncOpResults, error) {
	return nil, nil, nil
}

func (o *userResourceType) Grants(
	ctx context.Context,
	resource *v2.Resource,
	attrs resource.SyncOpAttrs,
) ([]*v2.Grant, *resource.SyncOpResults, error) {
	return nil, nil, nil
}

func userName(user *okta.User) (string, string) {
	profile := *user.Profile

	firstName, ok := profile[oktaAttrFirstName].(string)
	if !ok {
		firstName = unknownProfileValue
	}
	lastName, ok := profile[oktaAttrLastName].(string)
	if !ok {
		lastName = unknownProfileValue
	}

	return firstName, lastName
}

func listUsers(ctx context.Context, client *okta.Client, token *pagination.Token, qp *query.Params) ([]*okta.User, *responseContext, error) {
	if qp.Search == "" {
		qp.Search = "status pr" // ListUsers doesn't get deactivated users by default. this should fetch them all
	}

	uri := usersUrl
	if qp != nil {
		uri += qp.String()
	}

	reqUrl, err := url.Parse(uri)
	if err != nil {
		return nil, nil, err
	}

	// Using okta-response="omitCredentials,omitCredentialsLinks,omitTransitioningToStatus" in the content type header omits
	// the credentials, credentials links, and `transitioningToStatus` field from the response which applies performance optimization.
	// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/User/#tag/User/operation/listUsers!in=header&path=Content-Type&t=request
	oktaUsers := make([]*okta.User, 0)
	rq := client.CloneRequestExecutor()
	req, err := rq.
		WithAccept(ContentType).
		WithContentType(`application/json; okta-response="omitCredentials,omitCredentialsLinks,omitTransitioningToStatus"`).
		NewRequest(http.MethodGet, reqUrl.String(), nil)
	if err != nil {
		return nil, nil, err
	}

	// Need to set content type here because the response was still including the credentials when setting it with WithContentType above
	req.Header.Set("Content-Type", `application/json; okta-response="omitCredentials,omitCredentialsLinks,omitTransitioningToStatus"`)

	resp, err := rq.Do(ctx, req, &oktaUsers)
	if err != nil {
		return nil, nil, err
	}

	respCtx, err := responseToContext(token, resp)
	if err != nil {
		return nil, nil, err
	}
	return oktaUsers, respCtx, nil
}

func userBuilder(connector *Okta) *userResourceType {
	return &userResourceType{
		resourceType: resourceTypeUser,
		connector:    connector,
	}
}

// Create a new connector resource for a okta user.
func userResource(user *okta.User, skipSecondaryEmails bool) (*v2.Resource, error) {
	firstName, lastName := userName(user)

	oktaProfile := *user.Profile
	oktaProfile["c1_okta_raw_user_status"] = user.Status

	options := []resource.UserTraitOption{
		// TODO?: use the user types API to figure out the account type
		// https://developer.okta.com/docs/reference/api/user-types/
		// resource.WithAccountType(v2.UserTrait_ACCOUNT_TYPE_UNSPECIFIED),
	}

	resourceOpts := []resource.ResourceOption{
		resource.WithResourceProfile(oktaProfile),
	}

	displayName, ok := oktaProfile["displayName"].(string)
	if !ok {
		displayName = fmt.Sprintf("%s %s", firstName, lastName)
	}

	if user.Created != nil {
		resourceOpts = append(resourceOpts, resource.WithResourceCreatedAt(*user.Created))
	}
	if user.LastLogin != nil {
		options = append(options, resource.WithLastLogin(*user.LastLogin))
	}

	if email, ok := oktaProfile[profileFieldEmail].(string); ok && email != "" {
		options = append(options, resource.WithEmail(email, true))
	}
	if secondEmail, ok := oktaProfile["secondEmail"].(string); ok && secondEmail != "" && !skipSecondaryEmails {
		options = append(options, resource.WithEmail(secondEmail, false))
	}

	if skipSecondaryEmails {
		oktaProfile["secondEmail"] = nil
	}

	employeeIDs := mapset.NewSet[string]()
	for profileKey, profileValue := range oktaProfile {
		switch strings.ToLower(profileKey) {
		case "employeenumber", "employeeid", "employeeidnumber", "employee_number", "employee_id", "employee_idnumber":
			if id, ok := profileValue.(string); ok {
				employeeIDs.Add(id)
			}
		case profileFieldLogin:
			if login, ok := profileValue.(string); ok {
				// If possible, calculate shortname alias from login
				splitLogin := strings.Split(login, "@")
				if len(splitLogin) == 2 {
					options = append(options, resource.WithUserLogin(login, splitLogin[0]))
				} else {
					options = append(options, resource.WithUserLogin(login))
				}
			}
		}
	}

	if employeeIDs.Cardinality() > 0 {
		options = append(options, resource.WithEmployeeID(employeeIDs.ToSlice()...))
	}

	switch {
	// TODO: change userStatusDeprovisioned to STATUS_DELETED once we show deleted stuff in baton & the UI
	// case userStatusDeprovisioned:
	// options = append(options, resource.WithDetailedStatus(v2.UserTrait_Status_STATUS_DELETED, user.Status))
	// STAGED is pre-activation in Okta (cannot sign in) — same DISABLED bucket as SUSPENDED /
	// DEPROVISIONED via isDisabledOktaStatus, aligned with enable_user/disable_user.
	// PROVISIONED stays ENABLED (isEnabledOktaStatus): activated, pending user action only.
	case isDisabledOktaStatus(user.Status):
		resourceOpts = append(resourceOpts, resource.WithResourceStatus(v2.Status_RESOURCE_STATUS_DISABLED, user.Status))
	case isEnabledOktaStatus(user.Status):
		resourceOpts = append(resourceOpts, resource.WithResourceStatus(v2.Status_RESOURCE_STATUS_ENABLED, user.Status))
	default:
		resourceOpts = append(resourceOpts, resource.WithResourceStatus(v2.Status_RESOURCE_STATUS_UNSPECIFIED, user.Status))
	}

	resourceOpts = append(resourceOpts,
		resource.WithAnnotation(&v2.V1Identifier{Id: fmtResourceIdV1(user.Id)}),
		resource.WithAnnotation(&v2.RawId{Id: user.Id}),
	)

	ret, err := resource.NewUserResource(
		displayName,
		resourceTypeUser,
		user.Id,
		options,
		resourceOpts...,
	)
	return ret, err
}

func (o *userResourceType) CreateAccountCapabilityDetails(ctx context.Context) (*v2.CredentialDetailsAccountProvisioning, annotations.Annotations, error) {
	return &v2.CredentialDetailsAccountProvisioning{
		SupportedCredentialOptions: []v2.CapabilityDetailCredentialOption{
			v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_NO_PASSWORD,
			v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_RANDOM_PASSWORD,
		},
		PreferredCredentialOption: v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_NO_PASSWORD,
	}, nil, nil
}

func ToPtr[T any](v T) *T {
	return &v
}

func (r *userResourceType) CreateAccount(
	ctx context.Context,
	accountInfo *v2.AccountInfo,
	credentialOptions *v2.LocalCredentialOptions,
) (
	connectorbuilder.CreateAccountResponse,
	[]*v2.PlaintextData,
	annotations.Annotations,
	error,
) {
	userProfile, err := getUserProfile(accountInfo)
	if err != nil {
		return nil, nil, nil, err
	}

	creds, err := getCredentialOption(credentialOptions)
	if err != nil {
		return nil, nil, nil, err
	}

	providerType, err := getProviderType(accountInfo)
	if err != nil {
		return nil, nil, nil, err
	}

	creds, err = applyProviderCredentials(creds, providerType, credentialOptions)
	if err != nil {
		return nil, nil, nil, err
	}

	params, suppressActivationEmail, err := getAccountCreationQueryParams(accountInfo, credentialOptions, providerType)
	if err != nil {
		return nil, nil, nil, err
	}

	user, response, err := r.connector.client.User.CreateUser(ctx, okta.CreateUserRequest{
		Profile: userProfile,
		Type: &okta.UserType{
			Created:   ToPtr(time.Now()),
			CreatedBy: "ConductorOne",
		},
		Credentials: creds,
	}, params)

	// The login already belongs to an Okta user, so return that account rather than
	// failing the duplicate forever. Its lifecycle is left untouched: a STAGED collision
	// is indistinguishable from an account someone deliberately staged (create_inactive,
	// or an Okta admin), so activating it here would override that decision.
	// The conflict already proved the account exists — if the follow-up lookup fails or
	// cannot resolve a Resource, still return AlreadyExistsResult (without Resource) and
	// let the next sync correlate it.
	switch {
	case isDuplicateLoginError(err):
		l := ctxzap.Extract(ctx)
		login, ok := (*userProfile)[profileFieldLogin].(string)
		if !ok || login == "" {
			l.Debug("okta-connectorv2: login already exists but is unusable for lookup")
			return &v2.CreateAccountResponse_AlreadyExistsResult{}, nil, nil, nil
		}
		existing, _, getErr := r.connector.client.User.GetUser(ctx, login)
		if getErr != nil {
			l.Debug("okta-connectorv2: login already exists but fetch failed",
				zap.String("login", login),
				zap.Error(getErr),
			)
			return &v2.CreateAccountResponse_AlreadyExistsResult{}, nil, nil, nil
		}
		if existing == nil {
			l.Debug("okta-connectorv2: login already exists but user was not found",
				zap.String("login", login),
			)
			return &v2.CreateAccountResponse_AlreadyExistsResult{}, nil, nil, nil
		}
		l.Debug("okta-connectorv2: login already exists; returning the existing user unchanged",
			zap.String("user_id", existing.Id),
			zap.String("login", login),
			zap.String("status", existing.Status),
		)
		existingResource, err := userResource(existing, r.connector.skipSecondaryEmails)
		if err != nil {
			return nil, nil, nil, err
		}
		return &v2.CreateAccountResponse_AlreadyExistsResult{Resource: existingResource}, nil, nil, nil
	case err != nil:
		return nil, nil, nil, err
	case response != nil && response.StatusCode != http.StatusOK:
		return nil, nil, nil, fmt.Errorf("okta-connectorv2: failed to create user: %s", response.Status)
	}

	// Only a user this call just created reaches this point, and a suppressed create
	// always staged it, so no status check is needed.
	if suppressActivationEmail {
		_, activateResp, err := r.connector.client.User.ActivateUser(ctx, user.Id, query.NewQueryParams(query.WithSendEmail(false)))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("okta-connectorv2: user %s is staged but activation failed: %w", user.Id, err)
		}
		if activateResp != nil && activateResp.StatusCode != http.StatusOK {
			return nil, nil, nil, fmt.Errorf("okta-connectorv2: user %s is staged but activation returned non-200: %s", user.Id, activateResp.Status)
		}
		// ActivateUser returns a token, not the user. The account is fully provisioned
		// by now and this read only refreshes Status, so a failure here keeps the
		// create payload rather than discarding a successful provision.
		activated, _, err := r.connector.client.User.GetUser(ctx, user.Id)
		if err != nil {
			ctxzap.Extract(ctx).Debug("okta-connectorv2: activated user could not be re-read; returning the created user",
				zap.String("user_id", user.Id),
				zap.Error(err),
			)
		} else {
			user = activated
		}
	}

	userResource, err := userResource(user, r.connector.skipSecondaryEmails)
	if err != nil {
		return nil, nil, nil, err
	}

	return &v2.CreateAccountResponse_SuccessResult{Resource: userResource}, nil, nil, nil
}

// applyProviderCredentials attaches the federated authentication provider to the
// credentials sent to Okta. Federated users are mastered by an external IdP, so they
// cannot also carry an Okta password.
func applyProviderCredentials(
	creds *okta.UserCredentials,
	providerType string,
	credentialOptions *v2.LocalCredentialOptions,
) (*okta.UserCredentials, error) {
	if providerType != providerTypeFederation {
		return creds, nil
	}

	if credentialOptions.GetRandomPassword() != nil {
		return nil, fmt.Errorf("okta-connectorv2: %s=%s cannot be combined with a random password credential option", profileFieldProviderType, providerTypeFederation)
	}

	if creds == nil {
		creds = &okta.UserCredentials{}
	}
	creds.Provider = &okta.AuthenticationProvider{
		Type: providerTypeFederation,
		Name: providerTypeFederation,
	}

	return creds, nil
}

func getCredentialOption(credentialOptions *v2.LocalCredentialOptions) (*okta.UserCredentials, error) {
	if credentialOptions.GetNoPassword() != nil {
		return nil, nil
	}

	if credentialOptions.GetRandomPassword() == nil {
		return nil, errors.New("unsupported credential options")
	}

	length := min(8, credentialOptions.GetRandomPassword().GetLength())
	plaintextPassword, err := crypto.GenerateRandomPassword(&v2.LocalCredentialOptions_RandomPassword{
		Length: length,
	})
	if err != nil {
		return nil, err
	}

	return &okta.UserCredentials{
		Password: &okta.PasswordCredential{
			Value: plaintextPassword,
		},
	}, nil
}

func getUserProfile(accountInfo *v2.AccountInfo) (*okta.UserProfile, error) {
	pMap := accountInfo.Profile.AsMap()
	firstName, ok := pMap[profileFieldFirstName]
	if !ok {
		return nil, fmt.Errorf("okta-connectorv2: missing first name in account info")
	}

	lastName, ok := pMap[profileFieldLastName]
	if !ok {
		return nil, fmt.Errorf("okta-connectorv2: missing last name in account info")
	}

	email, ok := pMap[profileFieldEmail]
	if !ok {
		return nil, fmt.Errorf("okta-connectorv2: missing email in account info")
	}

	login, ok := pMap[profileFieldLogin]
	if !ok {
		login = email
	}

	profile := &okta.UserProfile{
		oktaAttrFirstName: firstName,
		oktaAttrLastName:  lastName,
		profileFieldEmail: email,
		profileFieldLogin: login,
	}

	additional, err := parseObjectProfileField(pMap, profileFieldAdditionalAttributes)
	if err != nil {
		return nil, err
	}
	for k, v := range additional {
		if protectedOktaProfileFields[k] {
			return nil, fmt.Errorf("okta-connectorv2: additionalAttributes cannot override protected field %q", k)
		}
		(*profile)[k] = v
	}

	return profile, nil
}

// getAccountCreationQueryParams builds Create User query params and whether a
// follow-up ActivateUser(sendEmail=false) is required.
func getAccountCreationQueryParams(accountInfo *v2.AccountInfo, credentialOptions *v2.LocalCredentialOptions, providerType string) (*query.Params, bool, error) {
	pMap := accountInfo.Profile.AsMap()
	params := &query.Params{}

	// Without provider=true Okta ignores credentials.provider.
	if providerType == providerTypeFederation {
		params.Provider = true
	}

	// create_inactive applies regardless of credential type
	createInactive, err := parseBoolProfileField(pMap, profileFieldCreateInactive, false)
	if err != nil {
		return nil, false, err
	}

	// send_activation_email defaults to true to preserve existing behavior
	sendActivationEmail, err := parseBoolProfileField(pMap, profileFieldSendActivationEmail, true)
	if err != nil {
		return nil, false, err
	}

	// Validated on every credential path so an invalid value is never silently
	// dropped, but only applied where Okta sets a password.
	requirePasswordChanged, err := parseBoolProfileField(pMap, profileFieldPasswordChangeOnLoginRequired, false)
	if err != nil {
		return nil, false, err
	}

	// create_inactive wins over send_activation_email / password_change_on_login_required:
	// the user stays staged and no activation follow-up runs.
	if createInactive {
		params.Activate = ToPtr(false)
		return params, false, nil
	}

	// nextLogin=changePassword is only applied on the random-password path, so the
	// conflict with send_activation_email=false is only real there. On no-password,
	// password_change_on_login_required remains inert (pre-existing behavior).
	if !sendActivationEmail && requirePasswordChanged && credentialOptions.GetRandomPassword() != nil {
		return nil, false, fmt.Errorf("okta-connectorv2: %s=false cannot be combined with %s=true", profileFieldSendActivationEmail, profileFieldPasswordChangeOnLoginRequired)
	}

	if !sendActivationEmail {
		// Stage the user so no activation email is sent; the caller activates with sendEmail=false.
		params.Activate = ToPtr(false)
		return params, true, nil
	}

	if requirePasswordChanged && credentialOptions.GetRandomPassword() != nil {
		params.NextLogin = "changePassword"
		params.Activate = ToPtr(true)
	}

	return params, false, nil
}

// parseObjectProfileField reads an account-creation field declared as a map in the
// creation schema. Only an absent or null key yields no attributes; a key present with
// any other type is rejected rather than dropped, because creating the account without
// the attributes the caller asked for reports success for a different outcome.
func parseObjectProfileField(pMap map[string]any, key string) (map[string]interface{}, error) {
	raw, present := pMap[key]
	if !present || raw == nil {
		return nil, nil
	}

	obj, ok := raw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("okta-connectorv2: %s must be an object, got %T", key, raw)
	}

	return obj, nil
}

// parseBoolProfileField reads a boolean account-creation field that C1 may send as a
// bool or as its string form. Only an absent or null key falls back to defaultValue; a
// key that is present with any other type is rejected, because silently defaulting
// send_activation_email back to true would send the email the operator asked to suppress.
func parseBoolProfileField(pMap map[string]any, key string, defaultValue bool) (bool, error) {
	raw, present := pMap[key]
	if !present || raw == nil {
		return defaultValue, nil
	}

	switch v := raw.(type) {
	case bool:
		return v, nil
	case string:
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			return false, fmt.Errorf("okta-connectorv2: invalid value for %s: %w", key, err)
		}
		return parsed, nil
	default:
		return false, fmt.Errorf("okta-connectorv2: %s must be a boolean or its string form, got %T", key, raw)
	}
}

// getProviderType returns "" (Okta default), OKTA, or FEDERATION from the profile.
func getProviderType(accountInfo *v2.AccountInfo) (string, error) {
	raw, ok := accountInfo.Profile.AsMap()[profileFieldProviderType]
	if !ok || raw == nil {
		return "", nil
	}

	providerType, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("okta-connectorv2: %s must be a string", profileFieldProviderType)
	}

	providerType = strings.ToUpper(strings.TrimSpace(providerType))
	switch providerType {
	case "", providerTypeOkta, providerTypeFederation:
		return providerType, nil
	default:
		return "", fmt.Errorf("okta-connectorv2: unsupported %s value %q (supported: %q, %q)", profileFieldProviderType, providerType, providerTypeOkta, providerTypeFederation)
	}
}

func (o *userResourceType) Get(ctx context.Context, resourceId *v2.ResourceId, parentResourceId *v2.ResourceId) (*v2.Resource, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	l.Debug("getting user", zap.String("user_id", resourceId.Resource))

	var annos annotations.Annotations

	user, respCtx, err := getUser(ctx, o.connector.client, resourceId.Resource)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to find user: %w", err)
	}

	resp := respCtx.OktaResponse
	if resp != nil {
		if desc, err := ratelimit.ExtractRateLimitData(resp.StatusCode, &resp.Header); err == nil {
			annos.WithRateLimiting(desc)
		}
	}

	if user == nil {
		return nil, annos, nil
	}

	// for okta v2, we only attempt to filter users by email domains when a list is provided
	if !o.connector.shouldIncludeUser(user) {
		return nil, annos, nil
	}

	resource, err := userResource(user, o.connector.skipSecondaryEmails)
	if err != nil {
		return nil, annos, err
	}

	return resource, annos, nil
}

// getUser retrieves the Okta user with the specified ID (may use the SDK GET cache).
// The request omits credentials and related fields to reduce payload size.
func getUser(ctx context.Context, client *okta.Client, oktaUserID string) (*okta.User, *responseContext, error) {
	reqUrl, err := url.Parse(usersUrl)
	if err != nil {
		return nil, nil, err
	}

	reqUrl = reqUrl.JoinPath(oktaUserID)

	// Using okta-response="omitCredentials,omitCredentialsLinks,omitTransitioningToStatus" in the content type header omits
	// the credentials, credentials links, and `transitioningToStatus` field from the response which applies performance optimization.
	// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/User/#tag/User/operation/listUsers!in=header&path=Content-Type&t=request
	oktaUsers := &okta.User{}
	rq := client.CloneRequestExecutor()
	req, err := rq.
		WithAccept(ContentType).
		WithContentType(`application/json; okta-response="omitCredentials,omitCredentialsLinks,omitTransitioningToStatus"`).
		NewRequest(http.MethodGet, reqUrl.String(), nil)
	if err != nil {
		return nil, nil, err
	}

	// Need to set content type here because the response was still including the credentials when setting it with WithContentType above
	req.Header.Set("Content-Type", `application/json; okta-response="omitCredentials,omitCredentialsLinks,omitTransitioningToStatus"`)

	resp, err := rq.Do(ctx, req, &oktaUsers)
	if err != nil {
		return nil, nil, handleOktaResponseErrorWithNotFoundMessage(resp, err, "user not found")
	}

	return oktaUsers, &responseContext{OktaResponse: resp}, nil
}

// suspendUser suspends the Okta user identified by oktaUserID.
//
// It validates that oktaUserID and client are provided, invokes the Okta suspend API,
// and returns an error if validation fails, the API call returns an error,
// or the API response status is not HTTP 200 OK.
func suspendUser(ctx context.Context, client *okta.Client, oktaUserID string) error {
	l := ctxzap.Extract(ctx)
	l.Debug("suspending user", zap.String("user_id", oktaUserID))

	// Validate input parameters
	if oktaUserID == "" {
		return fmt.Errorf("okta-connectorv2: user ID cannot be empty")
	}

	resp, err := client.User.SuspendUser(ctx, oktaUserID)
	if err != nil {
		return fmt.Errorf("okta-connectorv2: failed to suspend user: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("okta-connectorv2: failed to suspend user: %s", resp.Status)
	}

	l.Info("user suspended", zap.String("user_id", oktaUserID))
	return nil
}

// unsuspendUser unsuspends the Okta user identified by oktaUserID using the provided client.
//
// It validates inputs and returns an error if the client is nil, the user ID is empty,
// the Okta API call fails, or the API responds with a non-200 status.
func unsuspendUser(ctx context.Context, client *okta.Client, oktaUserID string) error {
	l := ctxzap.Extract(ctx)
	l.Debug("unsuspending user", zap.String("user_id", oktaUserID))

	if oktaUserID == "" {
		return fmt.Errorf("okta-connectorv2: user ID cannot be empty")
	}

	resp, err := client.User.UnsuspendUser(ctx, oktaUserID)
	if err != nil {
		return fmt.Errorf("okta-connectorv2: failed to unsuspend user: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("okta-connectorv2: failed to unsuspend user: %s", resp.Status)
	}

	l.Info("user unsuspended", zap.String("user_id", oktaUserID))
	return nil
}

// activateUser activates oktaUserID with sendEmail=false (STAGED → ACTIVE/PROVISIONED).
// The ActivateUser response has no User status; callers that need the landing status must GET.
func activateUser(ctx context.Context, client *okta.Client, oktaUserID string) error {
	l := ctxzap.Extract(ctx)
	l.Debug("activating user", zap.String("user_id", oktaUserID))

	if oktaUserID == "" {
		return fmt.Errorf("okta-connectorv2: user ID cannot be empty")
	}

	_, resp, err := client.User.ActivateUser(ctx, oktaUserID, query.NewQueryParams(query.WithSendEmail(false)))
	if err != nil {
		return fmt.Errorf("okta-connectorv2: failed to activate user: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("okta-connectorv2: failed to activate user: %s", resp.Status)
	}

	l.Info("user activated", zap.String("user_id", oktaUserID))
	return nil
}
