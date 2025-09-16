package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	oktav5 "github.com/conductorone/okta-sdk-golang/v5/okta"

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

type userResourceType struct {
	resourceType     *v2.ResourceType
	ciamEmailFilters []string
	connector        *Okta
}

func (o *userResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *userResourceType) List(
	ctx context.Context,
	resourceID *v2.ResourceId,
	token *pagination.Token,
) ([]*v2.Resource, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	if o.connector.awsConfig != nil && o.connector.awsConfig.Enabled {
		awsConfig, err := o.connector.getAWSApplicationConfig(ctx)
		if err != nil {
			return nil, "", nil, fmt.Errorf("error getting aws app settings config")
		}
		// TODO(lauren) get users for all groups matching pattern when user group mapping enabled
		if !awsConfig.UseGroupMapping {
			return o.listAWSAccountUsers(ctx, resourceID, token)
		}
	}

	// If we are in ciam mode, and there are no email filters specified, don't sync users.
	if o.connector.ciamConfig.Enabled && len(o.ciamEmailFilters) == 0 {
		return nil, "", nil, nil
	}
	bag, page, err := parsePageTokenV5(token.Token, &v2.ResourceId{ResourceType: resourceTypeUser.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse Page token: %w", err)
	}

	var rv []*v2.Resource

	users, respCtx, err := listUsersV5(ctx, o.connector.clientV5, page)
	if err != nil {
		anno, err := wrapErrorV5(respCtx, err, errors.New("okta-connectorv2: failed to list users"))
		return nil, "", anno, err
	}

	nextPage, annos, err := parseRespV5(respCtx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
	}

	for _, user := range users {
		if o.connector.ciamConfig.Enabled && !shouldIncludeOktaUser(&user, o.ciamEmailFilters) {
			continue
		}
		if user.Id == nil {
			l.Warn("okta-connectorv2: user is nil", zap.Any("user", user))
			continue
		}

		// for okta v2, we only attempt to filter users by email domains when a list is provided
		shouldInclude := o.connector.shouldIncludeUserAndSetCache(ctx, &user)
		if !shouldInclude {
			continue
		}
		resource, err := userResource(ctx, &user, o.connector.skipSecondaryEmails)
		if err != nil {
			return nil, "", nil, err
		}

		rv = append(rv, resource)
	}

	pageToken, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, err
	}

	return rv, pageToken, annos, nil
}

func (o *userResourceType) listAWSAccountUsers(
	ctx context.Context,
	// TODO(golds): should we use this parentResourceID?
	resourceID *v2.ResourceId,
	token *pagination.Token,
) ([]*v2.Resource, string, annotations.Annotations, error) {
	bag, page, err := parsePageTokenV5(token.Token, &v2.ResourceId{ResourceType: resourceTypeUser.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-aws-connector: failed to parse Page token: %w", err)
	}

	var rv []*v2.Resource
	appUsers, respContext, err := listApplicationUsersV5(ctx, o.connector.clientV5, o.connector.awsConfig.OktaAppId, page)
	if err != nil {
		anno, err := wrapErrorV5(respContext, err, errors.New("okta-aws-connector: failed to list application users"))
		return nil, "", anno, err
	}

	nextPage, annos, err := parseRespV5(respContext)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-aws-connector: failed to parse response: %w", err)
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-aws-connector: failed to fetch bag.Next: %w", err)
	}

	for _, appUser := range appUsers {
		user, err := embeddedOktaUserFromAppUser(&appUser)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-aws-connector: failed to get user from app user response: %w", err)
		}
		resource, err := userResource(ctx, user, o.connector.skipSecondaryEmails)
		if err != nil {
			return nil, "", nil, err
		}
		rv = append(rv, resource)
	}

	pageToken, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, err
	}

	return rv, pageToken, annos, nil
}

func embeddedOktaUserFromAppUser(appUser *oktav5.AppUser) (*oktav5.User, error) {
	embeddedMap := appUser.Embedded
	if embeddedMap == nil {
		return nil, fmt.Errorf("app user '%s' embedded data was nil", nullableStr(appUser.Id))
	}
	embeddedUser, ok := embeddedMap["user"]
	if !ok {
		return nil, fmt.Errorf("embedded user data was nil for app user '%s'", nullableStr(appUser.Id))
	}
	userJSON, err := json.Marshal(embeddedUser)
	if err != nil {
		return nil, fmt.Errorf("error marshalling embedded user data for app user '%s': %w", nullableStr(appUser.Id), err)
	}
	oktaUser := &oktav5.User{}
	err = json.Unmarshal(userJSON, &oktaUser)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling embedded user data for app user '%s': %w", nullableStr(appUser.Id), err)
	}
	return oktaUser, nil
}

// extractEmailsFromUserProfile safely extracts email addresses from a regular user profile.
// It checks for email, secondEmail, and login fields that contain email addresses.
func extractEmailsFromUserProfile(user *oktav5.User) []string {
	var userEmails []string

	// Check if profile exists
	if user == nil || user.Profile == nil {
		return userEmails
	}

	oktaProfile := *user.Profile

	// Extract primary email
	if email, ok := oktaProfile.GetEmailOk(); ok && nullableStr(email) != "" {
		userEmails = append(userEmails, *email)
	}

	// Extract secondary email
	if secondEmail, ok := oktaProfile.GetSecondEmailOk(); ok && nullableStr(secondEmail) != "" {
		userEmails = append(userEmails, nullableStr(secondEmail))
	}

	// Check if login field contains an email address
	if login, ok := oktaProfile.GetLoginOk(); ok && nullableStr(login) != "" {
		if strings.Contains(*login, "@") {
			userEmails = append(userEmails, *login)
		}
	}

	return userEmails
}

// extractEmailsFromUserProfileV5 safely extracts email addresses from a regular user profile.
// It checks for email, secondEmail, and login fields that contain email addresses.
func extractEmailsFromUserProfileV5(user getUserProfiler) []string {
	var userEmails []string

	// Check if profile exists
	if user == nil {
		return userEmails
	}

	oktaProfile := user.GetProfile()

	// Extract primary email
	if nullableStr(oktaProfile.Email) != "" {
		userEmails = append(userEmails, nullableStr(oktaProfile.Email))
	}

	// Extract secondary email
	if nullableStr(oktaProfile.SecondEmail.Get()) != "" {
		userEmails = append(userEmails, nullableStr(oktaProfile.SecondEmail.Get()))
	}

	// Check if login field contains an email address
	if nullableStr(oktaProfile.Login) != "" {
		if strings.Contains(nullableStr(oktaProfile.Login), "@") {
			userEmails = append(userEmails, nullableStr(oktaProfile.Login))
		}
	}

	return userEmails
}

// extractEmailsFromAppUserProfile safely extracts email addresses from an app user profile.
// It checks for email, secondEmail, and login fields that contain email addresses.
func extractEmailsFromAppUserProfile(appUser *oktav5.AppUser) []string {
	var userEmails []string

	// Check if profile exists
	if appUser == nil || appUser.Profile == nil {
		return userEmails
	}

	oktaProfile := appUser.Profile

	// Extract primary email
	if email, ok := oktaProfile["email"].(string); ok && email != "" {
		userEmails = append(userEmails, email)
	}

	// Extract secondary email
	if secondEmail, ok := oktaProfile["secondEmail"].(string); ok && secondEmail != "" {
		userEmails = append(userEmails, secondEmail)
	}

	// Check if login field contains an email address
	if login, ok := oktaProfile["login"].(string); ok && login != "" {
		if strings.Contains(login, "@") {
			userEmails = append(userEmails, login)
		}
	}

	return userEmails
}

func shouldIncludeOktaUser(u *oktav5.User, emailDomainFilters []string) bool {
	userEmails := extractEmailsFromUserProfile(u)
	return shouldIncludeUserByEmails(userEmails, emailDomainFilters)
}

func shouldIncludeOktaAppUser(u *oktav5.AppUser, emailDomainFilters []string) bool {
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
	_ *pagination.Token,
) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func (o *userResourceType) Grants(
	ctx context.Context,
	resource *v2.Resource,
	token *pagination.Token,
) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func userName(user *oktav5.User) (string, string) {
	profile := *user.Profile

	firstName := nullableStr(profile.FirstName.Get())
	if firstName == "" {
		firstName = unknownProfileValue
	}
	lastName := nullableStr(profile.LastName.Get())
	if lastName == "" {
		lastName = unknownProfileValue
	}

	return firstName, lastName
}

func listUsersV5(ctx context.Context, client *oktav5.APIClient, after string) ([]oktav5.User, *oktav5.APIResponse, error) {
	// ListUsers doesn't get deactivated users by default. this should fetch them all
	return client.UserAPI.ListUsers(ctx).Limit(defaultLimit).Search("status pr").After(after).Execute()
}

func ciamUserBuilder(connector *Okta) *userResourceType {
	var loweredFilters []string
	for _, ef := range connector.ciamConfig.EmailDomains {
		loweredFilters = append(loweredFilters, strings.ToLower(ef))
	}
	return &userResourceType{
		resourceType:     resourceTypeUser,
		ciamEmailFilters: loweredFilters,
		connector:        connector,
	}
}

func userBuilder(connector *Okta) *userResourceType {
	return &userResourceType{
		resourceType: resourceTypeUser,
		connector:    connector,
	}
}

// Create a new connector resource for a okta user.
func userResource(ctx context.Context, user *oktav5.User, skipSecondaryEmails bool) (*v2.Resource, error) {
	firstName, lastName := userName(user)

	oktaProfile := *user.Profile

	// TODO(golds): check the same fields as v2
	profile := map[string]interface{}{
		"email":                   nullableStr(oktaProfile.Email),
		"firstName":               nullableStr(oktaProfile.FirstName.Get()),
		"lastName":                nullableStr(oktaProfile.LastName.Get()),
		"login":                   nullableStr(oktaProfile.Login),
		"mobilePhone":             nullableStr(oktaProfile.MobilePhone.Get()),
		"secondEmail":             nullableStr(oktaProfile.SecondEmail.Get()),
		"c1_okta_raw_user_status": nullableStr(user.Status),
	}
	if skipSecondaryEmails {
		profile["secondEmail"] = nil
	}

	options := []resource.UserTraitOption{
		resource.WithUserProfile(profile),
		// TODO?: use the user types API to figure out the account type
		// https://developer.okta.com/docs/reference/api/user-types/
		// resource.WithAccountType(v2.UserTrait_ACCOUNT_TYPE_UNSPECIFIED),
	}

	displayName := nullableStr(oktaProfile.DisplayName.Get())
	if displayName == "" {
		displayName = fmt.Sprintf("%s %s", firstName, lastName)
	}

	if user.Created != nil {
		options = append(options, resource.WithCreatedAt(*user.Created))
	}
	if user.LastLogin.Get() != nil {
		options = append(options, resource.WithLastLogin(*user.LastLogin.Get()))
	}

	email := nullableStr(oktaProfile.Email)
	if email != "" {
		options = append(options, resource.WithEmail(email, true))
	}

	secondEmail := nullableStr(oktaProfile.SecondEmail.Get())

	if secondEmail != "" && !skipSecondaryEmails {
		options = append(options, resource.WithEmail(secondEmail, false))
	}

	employeeIDs := mapset.NewSet[string]()

	if employeenumber, ok := oktaProfile.GetEmployeeNumberOk(); ok {
		employeeIDs.Add(*employeenumber)
	}

	if login, ok := oktaProfile.GetLoginOk(); ok {
		splitLogin := strings.Split(*login, "@")
		if len(splitLogin) == 2 {
			options = append(options, resource.WithUserLogin(*login, splitLogin[0]))
		} else {
			options = append(options, resource.WithUserLogin(*login))
		}
	}

	for profileKey, profileValue := range oktaProfile.AdditionalProperties {
		switch strings.ToLower(profileKey) {
		case "employeenumber", "employeeid", "employeeidnumber", "employee_number", "employee_id", "employee_idnumber":
			if id, ok := profileValue.(string); ok {
				employeeIDs.Add(id)
			}
		case "login":
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

	switch *user.Status {
	// TODO: change userStatusDeprovisioned to STATUS_DELETED once we show deleted stuff in baton & the UI
	// case userStatusDeprovisioned:
	// options = append(options, resource.WithDetailedStatus(v2.UserTrait_Status_STATUS_DELETED, user.Status))
	case userStatusSuspended, userStatusDeprovisioned:
		options = append(options, resource.WithDetailedStatus(v2.UserTrait_Status_STATUS_DISABLED, *user.Status))
	case userStatusActive, userStatusProvisioned, userStatusStaged, userStatusPasswordExpired, userStatusRecovery, userStatusLockedOut:
		options = append(options, resource.WithDetailedStatus(v2.UserTrait_Status_STATUS_ENABLED, *user.Status))
	default:
		options = append(options, resource.WithDetailedStatus(v2.UserTrait_Status_STATUS_UNSPECIFIED, *user.Status))
	}

	ret, err := resource.NewUserResource(
		displayName,
		resourceTypeUser,
		nullableStr(user.Id),
		options,
		resource.WithAnnotation(&v2.RawId{Id: *user.Id}),
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

	activate, nextLogin, err := getAccountCreationQueryParamsV5(accountInfo, credentialOptions)
	if err != nil {
		return nil, nil, nil, err
	}

	request := r.connector.clientV5.UserAPI.CreateUser(ctx).
		Body(oktav5.CreateUserRequest{
			Profile: *userProfile,
			Type: &oktav5.CreateUserRequestType{
				AdditionalProperties: map[string]interface{}{
					"created":   ToPtr(time.Now()),
					"createdBy": "ConductorOne",
				},
			},
			Credentials: creds,
		}).
		Activate(activate)

	if nextLogin != "" {
		request = request.NextLogin(nextLogin)
	}

	user, response, err := request.Execute()
	if err != nil {
		anno, err := wrapErrorV5(response, err, errors.New("okta-connectorv2: failed to create user"))
		return nil, nil, anno, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, nil, nil, fmt.Errorf("okta-connectorv2: failed to create user: %s", response.Status)
	}

	userResource, err := userResource(ctx, user, r.connector.skipSecondaryEmails)
	if err != nil {
		return nil, nil, nil, err
	}
	car := &v2.CreateAccountResponse_SuccessResult{
		Resource: userResource,
	}

	return car, nil, nil, nil
}

func getCredentialOption(credentialOptions *v2.LocalCredentialOptions) (*oktav5.UserCredentials, error) {
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

	return &oktav5.UserCredentials{
		Password: &oktav5.PasswordCredential{
			Value: &plaintextPassword,
		},
	}, nil
}

func getUserProfile(accountInfo *v2.AccountInfo) (*oktav5.UserProfile, error) {
	pMap := accountInfo.Profile.AsMap()
	firstName, ok := pMap["first_name"]
	if !ok {
		return nil, fmt.Errorf("okta-connectorv2: missing first name in account info")
	}

	lastName, ok := pMap["last_name"]
	if !ok {
		return nil, fmt.Errorf("okta-connectorv2: missing last name in account info")
	}

	email, ok := pMap["email"]
	if !ok {
		return nil, fmt.Errorf("okta-connectorv2: missing email in account info")
	}

	login, ok := pMap["login"]
	if !ok {
		login = email
	}

	firstNameString, ok := firstName.(string)
	if !ok {
		return nil, fmt.Errorf("okta-connectorv2: first name is not a string")
	}

	lastNameString, ok := lastName.(string)
	if !ok {
		return nil, fmt.Errorf("okta-connectorv2: last name is not a string")
	}

	emailString, ok := email.(string)
	if !ok {
		return nil, fmt.Errorf("okta-connectorv2: email is not a string")
	}

	loginString, ok := login.(string)
	if !ok {
		return nil, fmt.Errorf("okta-connectorv2: login is not a string")
	}

	return &oktav5.UserProfile{
		FirstName: *oktav5.NewNullableString(&firstNameString),
		LastName:  *oktav5.NewNullableString(&lastNameString),
		Email:     &emailString,
		Login:     &loginString,
	}, nil
}

func getAccountCreationQueryParamsV5(
	accountInfo *v2.AccountInfo,
	credentialOptions *v2.CredentialOptions,
) (bool, string, error) {
	if credentialOptions.GetNoPassword() != nil {
		return false, "", nil
	}

	pMap := accountInfo.Profile.AsMap()
	requirePass := pMap["password_change_on_login_required"]
	requirePasswordChanged := false

	switch v := requirePass.(type) {
	case bool:
		requirePasswordChanged = v
	case string:

		parsed, err := strconv.ParseBool(v)
		if err != nil {
			return false, "", err
		}
		requirePasswordChanged = parsed
	case nil:
		// Do nothing
	}

	if requirePasswordChanged {
		nextLogin := "changePassword"

		// This defaults to true anyways, but lets be explicit
		return true, nextLogin, nil
	}

	return false, "", nil
}

func (o *userResourceType) Get(ctx context.Context, resourceId *v2.ResourceId, parentResourceId *v2.ResourceId) (*v2.Resource, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	l.Debug("getting user", zap.String("user_id", resourceId.Resource))

	var annos annotations.Annotations

	if o.connector.awsConfig != nil && o.connector.awsConfig.Enabled {
		awsConfig, err := o.connector.getAWSApplicationConfig(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("error getting aws app settings config")
		}
		// TODO: check if user is in any groups matching pattern when user group mapping enabled
		if !awsConfig.UseGroupMapping {
			return o.findAWSAccountUser(ctx, resourceId.Resource)
		}
	}

	// If we are in ciam mode, and there are no email filters specified, don't sync user.
	if o.connector.ciamConfig.Enabled && len(o.ciamEmailFilters) == 0 {
		return nil, nil, nil
	}

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

	if o.connector.ciamConfig.Enabled && !shouldIncludeOktaUser(user, o.ciamEmailFilters) {
		return nil, annos, nil
	}

	// for okta v2, we only attempt to filter users by email domains when a list is provided
	shouldInclude := o.connector.shouldIncludeUserAndSetCache(ctx, user)
	if !shouldInclude {
		return nil, annos, nil
	}

	resource, err := userResource(ctx, user, o.connector.skipSecondaryEmails)
	if err != nil {
		return nil, annos, err
	}

	return resource, annos, nil
}

func (o *userResourceType) findAWSAccountUser(
	ctx context.Context,
	oktaUserID string,
) (*v2.Resource, annotations.Annotations, error) {
	appUser, resp, err := getApplicationUser(ctx, o.connector.clientV5, o.connector.awsConfig.OktaAppId, oktaUserID)
	if err != nil {
		anno, err := wrapErrorV5(resp, err, errors.New("okta-aws-connector: failed to find application user"))
		return nil, anno, err
	}

	_, annos, err := parseRespV5(resp)
	if err != nil {
		return nil, annos, fmt.Errorf("okta-aws-connector: failed to parse response: %w", err)
	}

	if appUser == nil {
		return nil, annos, nil
	}

	user, err := embeddedOktaUserFromAppUser(appUser)
	if err != nil {
		return nil, annos, fmt.Errorf("okta-aws-connector: failed to get user from find app user response: %w", err)
	}
	resource, err := userResource(ctx, user, o.connector.skipSecondaryEmails)
	if err != nil {
		return nil, annos, err
	}
	return resource, annos, nil
}

func getApplicationUser(ctx context.Context, client *oktav5.APIClient, appID string, oktaUserID string) (*oktav5.AppUser, *oktav5.APIResponse, error) {
	applicationUser, resp, err := client.ApplicationUsersAPI.GetApplicationUser(ctx, appID, oktaUserID).Expand("user").Execute()
	if err != nil {
		return nil, resp, err
	}

	return applicationUser, resp, nil
}

func getUser(ctx context.Context, client *okta.Client, oktaUserID string) (*oktav5.User, *responseContext, error) {
	reqUrl, err := url.Parse(usersUrl)
	if err != nil {
		return nil, nil, err
	}

	reqUrl = reqUrl.JoinPath(oktaUserID)

	// Using okta-response="omitCredentials,omitCredentialsLinks,omitTransitioningToStatus" in the content type header omits
	// the credentials, credentials links, and `transitioningToStatus` field from the response which applies performance optimization.
	// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/User/#tag/User/operation/listUsers!in=header&path=Content-Type&t=request
	oktaUsers := &oktav5.User{}
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
