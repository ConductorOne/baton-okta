package connector

import (
	"context"
	"fmt"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
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
	resourceType *v2.ResourceType
	domain       string
	apiToken     string
	client       *okta.Client
	ciamMode     bool
	emailFilters []string
}

func (o *userResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *userResourceType) List(
	ctx context.Context,
	resourceID *v2.ResourceId,
	token *pagination.Token,
) ([]*v2.Resource, string, annotations.Annotations, error) {
	bag, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeUser.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	var rv []*v2.Resource
	qp := queryParams(token.Size, page)

	users, respCtx, err := listUsers(ctx, o.client, token, qp)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list users: %w", err)
	}

	nextPage, annos, err := parseResp(respCtx.OktaResponse)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
	}

	for _, user := range users {
		if o.ciamMode && !shouldIncludeUser(user, o.emailFilters) {
			continue
		}
		resource, err := userResource(ctx, user)
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

func shouldIncludeUser(u *okta.User, emailDomainFilters []string) bool {
	if len(emailDomainFilters) == 0 {
		return false
	}

	var userEmails []string
	oktaProfile := *u.Profile
	if email, ok := oktaProfile["email"].(string); ok {
		userEmails = append(userEmails, email)
	}
	if secondEmail, ok := oktaProfile["secondEmail"].(string); ok {
		userEmails = append(userEmails, secondEmail)
	}

	if login, ok := oktaProfile["login"].(string); ok {
		if strings.Contains(login, "@") {
			userEmails = append(userEmails, login)
		}
	}

	for _, filter := range emailDomainFilters {
		for _, ue := range userEmails {
			if strings.HasSuffix(ue, "@"+filter) {
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
	oktaUsers, resp, err := client.User.ListUsers(ctx, qp)
	if err != nil {
		return nil, nil, err
	}
	respCtx, err := responseToContext(token, resp)
	if err != nil {
		return nil, nil, err
	}
	return oktaUsers, respCtx, nil
}

func ciamUserBuilder(domain string, apiToken string, client *okta.Client, emailFilters []string) *userResourceType {
	return &userResourceType{
		resourceType: resourceTypeUser,
		domain:       domain,
		apiToken:     apiToken,
		client:       client,
		ciamMode:     true,
		emailFilters: emailFilters,
	}
}

func userBuilder(domain string, apiToken string, client *okta.Client) *userResourceType {
	return &userResourceType{
		resourceType: resourceTypeUser,
		domain:       domain,
		apiToken:     apiToken,
		client:       client,
	}
}

// Create a new connector resource for a okta user.
func userResource(ctx context.Context, user *okta.User) (*v2.Resource, error) {
	firstName, lastName := userName(user)

	oktaProfile := *user.Profile
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
		resource.WithCreatedAt(*user.Created)
	}
	if user.LastLogin != nil {
		resource.WithLastLogin(*user.LastLogin)
	}

	if email, ok := oktaProfile["email"].(string); ok && email != "" {
		options = append(options, resource.WithEmail(email, true))
	}
	if secondEmail, ok := oktaProfile["secondEmail"].(string); ok && secondEmail != "" {
		options = append(options, resource.WithEmail(secondEmail, false))
	}

	if login, ok := oktaProfile["login"].(string); ok {
		// If possible, calculate shortname alias from login
		splitLogin := strings.Split(login, "@")
		if len(splitLogin) == 2 {
			options = append(options, resource.WithUserLogin(login, splitLogin[0]))
		} else {
			options = append(options, resource.WithUserLogin(login))
		}
	}

	switch user.Status {
	// TODO: change userStatusDeprovisioned to STATUS_DELETED once we show deleted stuff in baton & the UI
	// case userStatusDeprovisioned:
	// options = append(options, resource.WithDetailedStatus(v2.UserTrait_Status_STATUS_DELETED, user.Status))
	case userStatusSuspended, userStatusLockedOut, userStatusDeprovisioned:
		options = append(options, resource.WithDetailedStatus(v2.UserTrait_Status_STATUS_DISABLED, user.Status))
	case userStatusActive, userStatusProvisioned, userStatusStaged, userStatusPasswordExpired, userStatusRecovery:
		options = append(options, resource.WithDetailedStatus(v2.UserTrait_Status_STATUS_ENABLED, user.Status))
	default:
		options = append(options, resource.WithDetailedStatus(v2.UserTrait_Status_STATUS_UNSPECIFIED, user.Status))
	}

	ret, err := resource.NewUserResource(
		displayName,
		resourceTypeUser,
		user.Id,
		options,
	)
	return ret, err
}
