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
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	unknownProfileValue                 = "unknown"
	userStatusSuspended                 = "SUSPENDED"
	userStatusDeprovisioned             = "DEPROVISIONED"
	userStatusActive                    = "ACTIVE"
	userStatusLockedOut                 = "LOCKED_OUT"
	userStatusPasswordExpired           = "PASSWORD_EXPIRED"
	userStatusProvisioned               = "PROVISIONED"
	userStatusRecovery                  = "RECOVERY"
	userStatusStaged                    = "STAGED"
	userDeprovisionConfirmationAttempts = 4
	userDeprovisionConfirmationInterval = 500 * time.Millisecond
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

var _ connectorbuilder.ResourceDeleterV2Limited = (*userResourceType)(nil)

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
	if user == nil || user.Id == "" || user.Profile == nil {
		return nil, status.Error(codes.DataLoss, "okta-connectorv2: user response is missing its identity or profile")
	}
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
	if err != nil {
		return nil, err
	}
	fields := ret.GetProfile().GetFields()
	// Observation metadata is connector-owned, never supplied by custom profile fields.
	for _, key := range []string{
		"c1_okta_fresh_observation", "c1_okta_observed_at", "c1_okta_transitioning_to_status",
		"c1_okta_status_changed_at", "c1_okta_password_changed_at", "c1_okta_last_updated_at",
	} {
		delete(fields, key)
	}
	if user.TransitioningToStatus != "" {
		fields["c1_okta_transitioning_to_status"] = structpb.NewStringValue(user.TransitioningToStatus)
	}
	for _, fact := range []struct {
		key   string
		value *time.Time
	}{
		{"c1_okta_status_changed_at", user.StatusChanged},
		{"c1_okta_password_changed_at", user.PasswordChanged},
		{"c1_okta_last_updated_at", user.LastUpdated},
	} {
		if fact.value != nil && !fact.value.IsZero() {
			fields[fact.key] = structpb.NewStringValue(fact.value.UTC().Format(time.RFC3339Nano))
		}
	}
	return ret, nil
}

func (o *userResourceType) CreateAccountCapabilityDetails(ctx context.Context) (*v2.CredentialDetailsAccountProvisioning, annotations.Annotations, error) {
	return &v2.CredentialDetailsAccountProvisioning{
		SupportedCredentialOptions: []v2.CapabilityDetailCredentialOption{
			v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_NO_PASSWORD,
			v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_RANDOM_PASSWORD,
			v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_ENCRYPTED_PASSWORD,
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

	providerType, err := getProviderType(accountInfo)
	if err != nil {
		return nil, nil, nil, err
	}
	params, suppressActivationEmail, annos, err := getAccountCreationQueryParams(ctx, accountInfo, credentialOptions, providerType, r.connector.strictAccountCreation)
	if err != nil {
		return nil, nil, nil, err
	}
	providerCredentials, err := applyProviderCredentials(providerType, credentialOptions)
	if err != nil {
		return nil, nil, nil, err
	}
	creds, generatedPassword, err := getCredentialOption(ctx, credentialOptions)
	if err != nil {
		return nil, nil, nil, err
	}
	if providerCredentials != nil {
		creds = providerCredentials
	}

	// Generated credential material is returned only on the random-password path,
	// so the SDK can encrypt it to the caller-selected destination. Supplied,
	// no-password and federation creates never return credential material: the
	// caller already holds a supplied password, and the others have none to return.
	var plaintextData []*v2.PlaintextData
	if generatedPassword != "" {
		plaintextData = []*v2.PlaintextData{{
			Name:        "password",
			Description: "Generated Okta account password",
			Bytes:       []byte(generatedPassword),
		}}
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
	// The conflict proved the account exists but the follow-up lookup may not resolve
	// it (lookup by login is best-effort). An unresolved collision must not claim
	// plain AlreadyExists success without a usable identity, and must not promise
	// eventual correlation via full sync: ActionRequiredResult with a non-secret
	// correlation message makes the manual follow-up explicit. No credential
	// material is returned on any duplicate path (the duplicate's password is not
	// the one this request carried).
	switch {
	case isDuplicateLoginError(err):
		l := ctxzap.Extract(ctx)
		login, ok := (*userProfile)[profileFieldLogin].(string)
		if !ok || login == "" {
			l.Debug("okta-connectorv2: login already exists but is unusable for lookup")
			return &v2.CreateAccountResponse_ActionRequiredResult{
				IsCreateAccountResult: true,
				Message:               "okta-connectorv2: duplicate login cannot be resolved; verify the existing account before adoption",
			}, nil, nil, nil
		}
		existing, _, getErr := getUserFresh(ctx, r.connector.client, login)
		if getErr != nil {
			l.Debug("okta-connectorv2: login already exists but fetch failed",
				zap.String("login", login),
				zap.Error(getErr),
			)
			return &v2.CreateAccountResponse_ActionRequiredResult{
				IsCreateAccountResult: true,
				Message:               fmt.Sprintf("okta-connectorv2: duplicate login %q could not be read; verify the existing account before adoption", login),
			}, nil, nil, nil
		}
		if existing == nil || existing.Id == "" {
			l.Debug("okta-connectorv2: login already exists but user was not found",
				zap.String("login", login),
			)
			return &v2.CreateAccountResponse_ActionRequiredResult{
				IsCreateAccountResult: true,
				Message:               fmt.Sprintf("okta-connectorv2: duplicate login %q returned no usable identity; verify the existing account before adoption", login),
			}, nil, nil, nil
		}
		existingLogin := ""
		if existing.Profile != nil {
			existingLogin, _ = (*existing.Profile)[profileFieldLogin].(string)
		}
		if !strings.EqualFold(existingLogin, login) {
			return &v2.CreateAccountResponse_ActionRequiredResult{
				IsCreateAccountResult: true,
				Message:               fmt.Sprintf("okta-connectorv2: login %q already exists, but lookup did not confirm that login; verify the account before adoption", login),
			}, nil, nil, nil
		}
		// A DEPROVISIONED collision has no connector-side recovery path (enable_user
		// refuses it), so AlreadyExistsResult would report success on a login that can
		// never be provisioned. FailedPrecondition mirrors enable_user's DEPROVISIONED path.
		if existing.Status == userStatusDeprovisioned {
			return nil, nil, nil, status.Error(
				codes.FailedPrecondition,
				"okta-connectorv2: login already exists on a deprovisioned account; reactivate the user in Okta, or delete and recreate the account, to reuse this login",
			)
		}
		l.Debug("okta-connectorv2: login already exists; returning the existing user unchanged",
			zap.String("user_id", existing.Id),
			zap.String("login", login),
			zap.String("status", existing.Status),
		)
		existingResource, err := userResource(existing, r.connector.skipSecondaryEmails)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("okta-connectorv2: failed to resolve existing user %s: %w", existing.Id, err)
		}
		return &v2.CreateAccountResponse_AlreadyExistsResult{Resource: existingResource}, nil, nil, nil
	case err != nil:
		return nil, nil, nil, err
	case response != nil && response.StatusCode != http.StatusOK:
		return nil, nil, nil, fmt.Errorf("okta-connectorv2: failed to create user: %s", response.Status)
	case user == nil || user.Id == "":
		// A 200 with no usable identity is an unknown outcome, never a success.
		return nil, nil, nil, status.Error(
			codes.Internal,
			"okta-connectorv2: create user returned no user id; the account may exist in Okta — do not retry with a new login before verifying",
		)
	}

	// The SDK discards resources and credential material on a transport error.
	// Convert partial creation failures to its typed ActionRequired outcome instead.
	needsAction := func(snapshot *v2.Resource, reason string, cause error, annos annotations.Annotations) (
		connectorbuilder.CreateAccountResponse, []*v2.PlaintextData, annotations.Annotations, error,
	) {
		return &v2.CreateAccountResponse_ActionRequiredResult{
			Resource:              snapshot,
			IsCreateAccountResult: true,
			Message: fmt.Sprintf("okta-connectorv2: account %s was created; %s (%s). Any returned resource is the creation snapshot, not current state",
				user.Id, reason, status.Code(cause)),
		}, plaintextData, annos, nil
	}
	createdResource, err := userResource(user, r.connector.skipSecondaryEmails)
	if err != nil {
		return needsAction(nil, "resource construction needs reconciliation", err, annos)
	}
	if !suppressActivationEmail {
		return &v2.CreateAccountResponse_SuccessResult{Resource: createdResource}, plaintextData, annos, nil
	}
	_, activateResp, err := r.connector.client.User.ActivateUser(ctx, user.Id, query.NewQueryParams(query.WithSendEmail(false)))
	if err != nil || activateResp == nil || activateResp.StatusCode != http.StatusOK {
		if err == nil {
			err = status.Error(codes.Unknown, "activation returned an unexpected response")
		}
		return needsAction(createdResource, "activation could not be confirmed", err, annos)
	}
	observed, respCtx, readErr := getUserFresh(ctx, r.connector.client, user.Id)
	if respCtx != nil && respCtx.OktaResponse != nil {
		response := respCtx.OktaResponse
		if limit, err := ratelimit.ExtractRateLimitData(response.StatusCode, &response.Header); err == nil {
			annos.WithRateLimiting(limit)
		}
	}
	if readErr != nil || observed == nil || observed.Id != user.Id {
		if readErr == nil {
			readErr = status.Error(codes.DataLoss, "activation readback did not identify the created user")
		}
		return needsAction(createdResource, "activation was acknowledged but fresh state is unconfirmed", readErr, annos)
	}
	current, err := userResource(observed, r.connector.skipSecondaryEmails)
	if err != nil {
		return needsAction(createdResource, "activation readback was incomplete", err, annos)
	}
	if observed.Status == userStatusStaged || observed.TransitioningToStatus != "" {
		return &v2.CreateAccountResponse_InProgressResult{Resource: current, IsCreateAccountResult: true}, plaintextData, annos, nil
	}
	return &v2.CreateAccountResponse_SuccessResult{Resource: current}, plaintextData, annos, nil
}

// applyProviderCredentials attaches the federated authentication provider to the
// credentials sent to Okta. Federated users are mastered by an external IdP, so they
// cannot also carry an Okta password: both supplied and generated passwords are
// rejected here, before any provider write.
func applyProviderCredentials(
	providerType string,
	credentialOptions *v2.LocalCredentialOptions,
) (*okta.UserCredentials, error) {
	if providerType != providerTypeFederation {
		return nil, nil
	}

	if credentialOptions.GetRandomPassword() != nil {
		return nil, fmt.Errorf("okta-connectorv2: %s=%s cannot be combined with a random password credential option", profileFieldProviderType, providerTypeFederation)
	}
	if credentialOptions.GetPlaintextPassword() != nil {
		return nil, fmt.Errorf("okta-connectorv2: %s=%s cannot be combined with a supplied password credential option", profileFieldProviderType, providerTypeFederation)
	}

	return &okta.UserCredentials{Provider: &okta.AuthenticationProvider{
		Type: providerTypeFederation,
		Name: providerTypeFederation,
	}}, nil
}

// getCredentialOption translates SDK credential options into Okta credentials.
// It returns the Okta credentials plus the generated password when the random
// option was selected, so CreateAccount can return that material (and only
// that material) to the SDK for encrypted delivery.
func getCredentialOption(ctx context.Context, credentialOptions *v2.LocalCredentialOptions) (*okta.UserCredentials, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	if credentialOptions.GetNoPassword() != nil {
		return nil, "", nil
	}

	// The SDK's crypto.GeneratePassword handles both options: it returns the
	// supplied plaintext unchanged (never regenerating a caller-provided
	// bootstrap password) and honors the requested random length and
	// constraints (the SDK enforces a minimum length of 8 itself).
	plaintextPassword, err := crypto.GeneratePassword(ctx, credentialOptions)
	if err != nil {
		if errors.Is(err, crypto.ErrInvalidCredentialOptions) {
			return nil, "", errors.New("unsupported credential options")
		}
		return nil, "", err
	}

	if credentialOptions.GetPlaintextPassword() != nil {
		if plaintextPassword == "" {
			return nil, "", errors.New("okta-connectorv2: supplied password must not be empty")
		}
		// Supplied mode: the caller already holds the password; no material is returned.
		return &okta.UserCredentials{
			Password: &okta.PasswordCredential{
				Value: plaintextPassword,
			},
		}, "", nil
	}

	// Random mode: honor the requested length (no connector-side cap).
	return &okta.UserCredentials{
		Password: &okta.PasswordCredential{
			Value: plaintextPassword,
		},
	}, plaintextPassword, nil
}

func getUserProfile(accountInfo *v2.AccountInfo) (*okta.UserProfile, error) {
	pMap := accountInfo.GetProfile().AsMap()
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

// getAccountCreationQueryParams preserves legacy caller behavior unless strict
// validation is enabled. Supplied passwords are new functionality and always strict.
func getAccountCreationQueryParams(
	ctx context.Context,
	accountInfo *v2.AccountInfo,
	credentialOptions *v2.LocalCredentialOptions,
	providerType string,
	strictValidation bool,
) (*query.Params, bool, annotations.Annotations, error) {
	pMap := accountInfo.GetProfile().AsMap()
	params := &query.Params{Provider: providerType == providerTypeFederation}
	createInactive, err := parseBoolProfileField(pMap, profileFieldCreateInactive, false)
	if err != nil {
		return nil, false, nil, err
	}
	sendActivationEmail, err := parseBoolProfileField(pMap, profileFieldSendActivationEmail, true)
	if err != nil {
		return nil, false, nil, err
	}
	profileChange, err := parseBoolProfileField(pMap, profileFieldPasswordChangeOnLoginRequired, false)
	if err != nil {
		return nil, false, nil, err
	}
	forceChange := credentialOptions.GetForceChangeAtNextLogin()
	strict := strictValidation || credentialOptions.GetPlaintextPassword() != nil
	hasPassword := credentialOptions.GetRandomPassword() != nil || credentialOptions.GetPlaintextPassword() != nil
	mandatoryChange := profileChange
	if strict {
		mandatoryChange = mandatoryChange || forceChange
		if !hasPassword && mandatoryChange {
			return nil, false, nil, status.Error(codes.InvalidArgument, "okta-connectorv2: strict mandatory password change requires a password")
		}
		if createInactive && hasPassword && mandatoryChange {
			return nil, false, nil, status.Error(codes.InvalidArgument, "okta-connectorv2: create_inactive cannot enforce mandatory password change")
		}
	}
	suppressActivationEmail := false
	switch {
	case createInactive:
		params.Activate = ToPtr(false)
	case !sendActivationEmail:
		// This conflict was already rejected for legacy random-password callers.
		if hasPassword && mandatoryChange {
			return nil, false, nil, status.Error(codes.InvalidArgument, "okta-connectorv2: send_activation_email=false cannot enforce mandatory password change")
		}
		params.Activate = ToPtr(false)
		suppressActivationEmail = true
	case hasPassword && mandatoryChange:
		params.NextLogin = "changePassword"
		params.Activate = ToPtr(true)
	}
	var annos annotations.Annotations
	if (profileChange || forceChange) && params.NextLogin == "" {
		ctxzap.Extract(ctx).Warn("okta-connectorv2: legacy account creation cannot enforce the requested password change; not takeover evidence",
			zap.Bool("strict_validation", strict), zap.Bool("create_inactive", createInactive), zap.Bool("password_credential", hasPassword))
		// CreateAccount returns at most one ErrorInfo annotation. Preserve this
		// invariant: SDK Annotations.Pick returns only the first match by type.
		unenforced := &errdetails.ErrorInfo{
			Reason:   "LEGACY_PASSWORD_CHANGE_NOT_ENFORCED",
			Domain:   "baton-okta",
			Metadata: make(map[string]string),
		}
		if profileChange {
			unenforced.Metadata[profileFieldPasswordChangeOnLoginRequired] = strconv.FormatBool(profileChange)
		}
		if forceChange {
			unenforced.Metadata["force_change_at_next_login"] = strconv.FormatBool(forceChange)
		}
		annos.Append(unenforced)
	}
	return params, suppressActivationEmail, annos, nil
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
	raw, ok := accountInfo.GetProfile().AsMap()[profileFieldProviderType]
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
	l.Debug("getting user", zap.String("user_id", resourceId.GetResource()))

	if resourceId == nil || resourceId.GetResource() == "" {
		return nil, nil, status.Error(codes.InvalidArgument, "okta-connectorv2: user resource ID cannot be empty")
	}

	var annos annotations.Annotations

	// Resource Get has no freshness selector; always take the fresh path so the
	// returned resource is a current point observation (one wire GET, bypassing
	// the SDK GET cache). The ordinary cached path stays on List/sync.
	user, respCtx, err := getUserFresh(ctx, o.connector.client, resourceId.Resource)
	if err != nil {
		// Provider-qualified absence stays NotFound; everything else (timeout,
		// permission, unknown) is a failed read, never successful absence.
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to find user: %w", err)
	}

	resp := respCtx.OktaResponse
	if resp != nil {
		if desc, err := ratelimit.ExtractRateLimitData(resp.StatusCode, &resp.Header); err == nil {
			annos.WithRateLimiting(desc)
		}
	}

	// An empty or unusable provider payload is unknown data, not a verified
	// absence. A user without an ID or profile cannot be represented or
	// filtered; the native ID stays in the error for correlation.
	if user == nil || user.Id == "" || user.Profile == nil {
		return nil, annos, status.Error(codes.Unknown, fmt.Sprintf(
			"okta-connectorv2: provider returned empty or incomplete user payload for %s",
			resourceId.Resource,
		))
	}
	if user.Id != resourceId.GetResource() {
		return nil, annos, status.Errorf(codes.FailedPrecondition, "okta-connectorv2: expected user %s but received %s", resourceId.GetResource(), user.Id)
	}

	// NotFound preserves the SDK targeted-sync skip behavior. ErrorInfo makes a
	// filtered observation distinguishable from authoritative provider absence.
	if !o.connector.shouldIncludeUser(user) {
		filtered, err := status.New(codes.NotFound, "okta-connectorv2: user excluded by configured email-domain filter").WithDetails(&errdetails.ErrorInfo{
			Reason:   "RESOURCE_FILTERED",
			Domain:   "baton-okta",
			Metadata: map[string]string{"resource_type": resourceTypeUser.Id, "resource_id": resourceId.GetResource(), "filter": "email_domain"},
		})
		if err != nil {
			// Without the qualifier, NotFound would falsely imply provider absence.
			return nil, annos, status.Errorf(codes.Internal, "okta-connectorv2: failed to encode configured-filter exclusion: %v", err)
		}
		return nil, annos, filtered.Err()
	}

	resource, err := userResource(user, o.connector.skipSecondaryEmails)
	if err != nil {
		return nil, annos, err
	}

	return resource, annos, nil
}

// getUser retrieves the Okta user with the specified ID (and may use the SDK
// GET cache). The request omits credentials and related fields to reduce the
// payload.
func getUser(ctx context.Context, client *okta.Client, oktaUserID string) (*okta.User, *responseContext, error) {
	return getUserWithCachePolicy(ctx, client, oktaUserID, false)
}

// getUserFresh bypasses the SDK GET cache for lifecycle reconciliation after
// a failed mutation.
func getUserFresh(ctx context.Context, client *okta.Client, oktaUserID string) (*okta.User, *responseContext, error) {
	return getUserWithCachePolicy(ctx, client, oktaUserID, true)
}

func getUserWithCachePolicy(ctx context.Context, client *okta.Client, oktaUserID string, fresh bool) (*okta.User, *responseContext, error) {
	// The user key (ID, or a login the caller resolved) must stay a single
	// escaped path segment: JoinPath would clean slash/dot segments and silently
	// rewrite a slash-containing login into a different endpoint. PathEscape
	// preserves the key verbatim as one segment; no full-user-list fallback.
	reqUrl, err := url.Parse(usersUrl)
	if err != nil {
		return nil, nil, err
	}

	escapedKey := url.PathEscape(oktaUserID)
	if oktaUserID == "." || oktaUserID == ".." {
		escapedKey = strings.ReplaceAll(oktaUserID, ".", "%2E")
	}
	reqUrl.RawPath = reqUrl.EscapedPath() + "/" + escapedKey
	reqUrl.Path += "/" + oktaUserID

	// Using okta-response="omitCredentials,omitCredentialsLinks,omitTransitioningToStatus" in the content type header omits
	// the credentials, credentials links, and `transitioningToStatus` field from the response which applies performance optimization.
	// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/User/#tag/User/operation/listUsers!in=header&path=Content-Type&t=request
	// Fresh reads drop only the omitTransitioningToStatus optimization: a lifecycle
	// point observation needs the nonsecret transition fact, while credentials stay omitted.
	oktaResponseHeader := `application/json; okta-response="omitCredentials,omitCredentialsLinks,omitTransitioningToStatus"`
	if fresh {
		oktaResponseHeader = `application/json; okta-response="omitCredentials,omitCredentialsLinks"`
	}
	oktaUsers := &okta.User{}
	rq := client.CloneRequestExecutor()
	if fresh {
		rq.RefreshNext()
	}
	req, err := rq.
		WithAccept(ContentType).
		WithContentType(oktaResponseHeader).
		NewRequest(http.MethodGet, reqUrl.String(), nil)
	if err != nil {
		return nil, nil, err
	}

	// Need to set content type here because the response was still including the credentials when setting it with WithContentType above
	req.Header.Set("Content-Type", oktaResponseHeader)

	resp, err := rq.Do(ctx, req, &oktaUsers)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to get user: %w", handleOktaResponseError(resp, err))
	}

	return oktaUsers, &responseContext{OktaResponse: resp}, nil
}

func (o *userResourceType) Delete(ctx context.Context, resourceID *v2.ResourceId, _ *v2.ResourceId) (annotations.Annotations, error) {
	oktaUserID, err := oktaUserIDFromResourceID(resourceID)
	if err != nil {
		return nil, err
	}

	deleted, err := permanentlyDeleteUser(ctx, o.connector.client, oktaUserID)
	if err != nil {
		return nil, err
	}

	l := ctxzap.Extract(ctx)
	if deleted {
		l.Info("deprovisioned and deleted Okta user", zap.String("user_id", oktaUserID))
	} else {
		l.Info("Okta user was already deleted", zap.String("user_id", oktaUserID))
	}
	return nil, nil
}

func oktaUserIDFromResourceID(resourceID *v2.ResourceId) (string, error) {
	if resourceID == nil {
		return "", status.Error(codes.InvalidArgument, "okta-connectorv2: user resource ID is required")
	}
	if resourceID.GetResourceType() != resourceTypeUser.Id {
		return "", status.Errorf(
			codes.InvalidArgument,
			"okta-connectorv2: expected resource type %q, got %q",
			resourceTypeUser.Id,
			resourceID.GetResourceType(),
		)
	}
	if resourceID.GetResource() == "" {
		return "", status.Error(codes.InvalidArgument, "okta-connectorv2: user ID cannot be empty")
	}
	return resourceID.GetResource(), nil
}

// ensureUserDeactivated transitions an existing user to DEPROVISIONED. It
// bypasses the SDK GET cache because a stale DEPROVISIONED status could turn
// Okta's first DELETE call into deactivation while the connector reports a
// permanent deletion. The booleans report whether this call changed the status
// and whether the user is already absent; callers decide whether absence
// satisfies their contract.
func ensureUserDeactivated(ctx context.Context, client *okta.Client, oktaUserID string) (bool, bool, error) {
	currentStatus, err := getUserStatusFresh(ctx, client, oktaUserID)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return false, true, nil
		}
		return false, false, err
	}
	if currentStatus == userStatusDeprovisioned {
		return false, false, nil
	}

	if err := deactivateUser(ctx, client, oktaUserID); err != nil {
		// Reconcile concurrent lifecycle changes without relying on vendor error
		// text. Only a confirmed terminal state converts the mutation error to
		// success.
		reconciledStatus, reconcileErr := getUserStatusFresh(ctx, client, oktaUserID)
		if reconcileErr != nil {
			if status.Code(reconcileErr) == codes.NotFound {
				return false, true, nil
			}
			return false, false, err
		}
		if reconciledStatus == userStatusDeprovisioned {
			return false, false, nil
		}
		return false, false, err
	}

	missing, err := waitForUserDeprovisioned(ctx, client, oktaUserID)
	if err != nil {
		return false, false, err
	}
	if missing {
		return false, true, nil
	}
	return true, false, nil
}

func waitForUserDeprovisioned(ctx context.Context, client *okta.Client, oktaUserID string) (bool, error) {
	for attempt := 1; attempt <= userDeprovisionConfirmationAttempts; attempt++ {
		currentStatus, err := getUserStatusFresh(ctx, client, oktaUserID)
		if err != nil {
			if status.Code(err) == codes.NotFound {
				return true, nil
			}
			return false, err
		}
		if currentStatus == userStatusDeprovisioned {
			return false, nil
		}
		if attempt == userDeprovisionConfirmationAttempts {
			return false, status.Errorf(
				codes.Unavailable,
				"okta-connectorv2: user %s is not yet deprovisioned (status %s); retry",
				oktaUserID,
				currentStatus,
			)
		}

		timer := time.NewTimer(userDeprovisionConfirmationInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return false, ctx.Err()
		case <-timer.C:
		}
	}

	return false, status.Error(codes.Internal, "okta-connectorv2: deprovision confirmation loop exited unexpectedly")
}

// permanentlyDeleteUser guarantees that the user is absent. Okta returns 204
// both when DELETE merely deactivates a non-DEPROVISIONED user and when it
// permanently deletes a DEPROVISIONED user, so status codes alone cannot prove
// the postcondition. ensureUserDeactivated confirms the prerequisite; a fresh
// GET after each DELETE proves absence. One second DELETE handles a lifecycle
// race without an unbounded retry loop.
func permanentlyDeleteUser(ctx context.Context, client *okta.Client, oktaUserID string) (bool, error) {
	_, missing, err := ensureUserDeactivated(ctx, client, oktaUserID)
	if err != nil {
		return false, err
	}
	if missing {
		return false, nil
	}

	for attempt := 1; attempt <= 2; attempt++ {
		if err := deleteUser(ctx, client, oktaUserID); err != nil {
			if status.Code(err) == codes.NotFound {
				return true, nil
			}
			return false, err
		}

		currentStatus, err := getUserStatusFresh(ctx, client, oktaUserID)
		if err != nil {
			if status.Code(err) == codes.NotFound {
				return true, nil
			}
			return false, err
		}
		if currentStatus != userStatusDeprovisioned {
			return false, status.Errorf(
				codes.Unavailable,
				"okta-connectorv2: user %s still exists after delete (status %s); retry",
				oktaUserID,
				currentStatus,
			)
		}
	}

	return false, status.Errorf(
		codes.Unavailable,
		"okta-connectorv2: user %s still exists after two delete requests; retry",
		oktaUserID,
	)
}

func getUserStatus(ctx context.Context, client *okta.Client, oktaUserID string) (string, error) {
	return getUserStatusWithCachePolicy(ctx, client, oktaUserID, false)
}

func getUserStatusFresh(ctx context.Context, client *okta.Client, oktaUserID string) (string, error) {
	return getUserStatusWithCachePolicy(ctx, client, oktaUserID, true)
}

func getUserStatusWithCachePolicy(ctx context.Context, client *okta.Client, oktaUserID string, fresh bool) (string, error) {
	if oktaUserID == "" {
		return "", status.Error(codes.InvalidArgument, "okta-connectorv2: user ID cannot be empty")
	}

	var (
		user *okta.User
		err  error
	)
	if fresh {
		user, _, err = getUserFresh(ctx, client, oktaUserID)
	} else {
		user, _, err = getUser(ctx, client, oktaUserID)
	}
	if err != nil {
		return "", fmt.Errorf("okta-connectorv2: failed to find user %s: %w", oktaUserID, err)
	}
	if user == nil {
		return "", status.Errorf(codes.NotFound, "okta-connectorv2: user %s not found", oktaUserID)
	}
	return user.Status, nil
}

func deactivateUser(ctx context.Context, client *okta.Client, oktaUserID string) error {
	if oktaUserID == "" {
		return status.Error(codes.InvalidArgument, "okta-connectorv2: user ID cannot be empty")
	}

	resp, err := client.User.DeactivateUser(ctx, oktaUserID, query.NewQueryParams(query.WithSendEmail(false)))
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return fmt.Errorf("okta-connectorv2: failed to deactivate user: %w", handleOktaResponseError(resp, err))
	}

	ctxzap.Extract(ctx).Info("deactivated Okta user", zap.String("user_id", oktaUserID))
	return nil
}

func deleteUser(ctx context.Context, client *okta.Client, oktaUserID string) error {
	if oktaUserID == "" {
		return status.Error(codes.InvalidArgument, "okta-connectorv2: user ID cannot be empty")
	}

	resp, err := client.User.DeactivateOrDeleteUser(ctx, oktaUserID, nil)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return fmt.Errorf("okta-connectorv2: failed to delete user: %w", handleOktaResponseError(resp, err))
	}
	if resp == nil {
		return status.Error(codes.Internal, "okta-connectorv2: delete user returned no response")
	}

	ctxzap.Extract(ctx).Debug(
		"Okta accepted delete request",
		zap.String("user_id", oktaUserID),
		zap.Int("status_code", resp.StatusCode),
	)
	return nil
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
