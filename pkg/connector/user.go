package connector

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
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
	attrs resource.SyncOpAttrs,
) ([]*v2.Resource, *resource.SyncOpResults, error) {
	token := &attrs.PageToken

	// If we are in ciam mode, and there are no email filters specified, don't sync users.
	if o.connector.ciamConfig.Enabled && len(o.ciamEmailFilters) == 0 {
		return nil, nil, nil
	}
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
		if o.connector.ciamConfig.Enabled && !shouldIncludeOktaUser(user, o.ciamEmailFilters) {
			continue
		}
		// for okta v2, we only attempt to filter users by email domains when a list is provided
		shouldInclude := o.connector.shouldIncludeUserAndSetCache(ctx, attrs.Session, user)
		if !shouldInclude {
			continue
		}
		resource, err := userResource(ctx, user, o.connector.skipSecondaryEmails)
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

func shouldIncludeOktaUser(u *okta.User, emailDomainFilters []string) bool {
	userEmails := extractEmailsFromUserProfile(u)
	return shouldIncludeUserByEmails(userEmails, emailDomainFilters)
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

	firstName, ok := profile["firstName"].(string)
	if !ok {
		firstName = unknownProfileValue
	}
	lastName, ok := profile["lastName"].(string)
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
func userResource(ctx context.Context, user *okta.User, skipSecondaryEmails bool) (*v2.Resource, error) {
	firstName, lastName := userName(user)

	oktaProfile := *user.Profile
	oktaProfile["c1_okta_raw_user_status"] = user.Status

	options := []resource.UserTraitOption{
		resource.WithUserProfile(oktaProfile),
		// TODO?: use the user types API to figure out the account type
		// https://developer.okta.com/docs/reference/api/user-types/
		// resource.WithAccountType(v2.UserTrait_ACCOUNT_TYPE_UNSPECIFIED),
	}

	displayName, ok := oktaProfile["displayName"].(string)
	if !ok {
		displayName = fmt.Sprintf("%s %s", firstName, lastName)
	}

	if user.Created != nil {
		options = append(options, resource.WithCreatedAt(*user.Created))
	}
	if user.LastLogin != nil {
		options = append(options, resource.WithLastLogin(*user.LastLogin))
	}

	if email, ok := oktaProfile["email"].(string); ok && email != "" {
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

	switch user.Status {
	// TODO: change userStatusDeprovisioned to STATUS_DELETED once we show deleted stuff in baton & the UI
	// case userStatusDeprovisioned:
	// options = append(options, resource.WithDetailedStatus(v2.UserTrait_Status_STATUS_DELETED, user.Status))
	case userStatusSuspended, userStatusDeprovisioned:
		options = append(options, resource.WithDetailedStatus(v2.UserTrait_Status_STATUS_DISABLED, user.Status))
	case userStatusActive, userStatusProvisioned, userStatusStaged, userStatusPasswordExpired, userStatusRecovery, userStatusLockedOut:
		options = append(options, resource.WithDetailedStatus(v2.UserTrait_Status_STATUS_ENABLED, user.Status))
	default:
		options = append(options, resource.WithDetailedStatus(v2.UserTrait_Status_STATUS_UNSPECIFIED, user.Status))
	}

	ret, err := resource.NewUserResource(
		displayName,
		resourceTypeUser,
		user.Id,
		options,
		resource.WithAnnotation(&v2.RawId{Id: user.Id}),
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

	params, err := getAccountCreationQueryParams(accountInfo, credentialOptions)
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
	if err != nil {
		return nil, nil, nil, err
	}
	if response != nil && response.StatusCode != http.StatusOK {
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

	return &okta.UserProfile{
		"firstName": firstName,
		"lastName":  lastName,
		"email":     email,
		"login":     login,
	}, nil
}

func getAccountCreationQueryParams(accountInfo *v2.AccountInfo, credentialOptions *v2.LocalCredentialOptions) (*query.Params, error) {
	if credentialOptions.GetNoPassword() != nil {
		return nil, nil
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
			return nil, err
		}
		requirePasswordChanged = parsed
	case nil:
		// Do nothing
	}

	params := &query.Params{}
	if requirePasswordChanged {
		params.NextLogin = "changePassword"
		params.Activate = ToPtr(true) // This defaults to true anyways, but lets be explicit
	}
	return params, nil
}

func (o *userResourceType) Get(ctx context.Context, resourceId *v2.ResourceId, parentResourceId *v2.ResourceId) (*v2.Resource, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	l.Debug("getting user", zap.String("user_id", resourceId.Resource))

	var annos annotations.Annotations

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
	// Note: Get() doesn't cache the result since it doesn't have access to session store
	if !o.connector.shouldIncludeUser(user) {
		return nil, annos, nil
	}

	resource, err := userResource(ctx, user, o.connector.skipSecondaryEmails)
	if err != nil {
		return nil, annos, err
	}

	return resource, annos, nil
}

// getUser retrieves the Okta user with the specified ID.
// It returns the Okta user and a responseContext containing the HTTP response; if the user is not found or the request fails, an error is returned.
// The underlying request omits credentials and related fields from the response to reduce payload size.
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
