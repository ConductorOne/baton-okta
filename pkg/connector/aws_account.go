package connector

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/bid"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	sdkEntitlement "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	sdkGrant "github.com/conductorone/baton-sdk/pkg/types/grant"
	resource2 "github.com/conductorone/baton-sdk/pkg/types/resource"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"go.uber.org/zap"
)

type OktaAppGroupWrapper struct {
	samlRoles []string
}

type AWSRoles struct {
	AWSEnvironmentEnum []string `json:"AWSEnvironmentEnum,omitempty"`
	SamlIamRole        []string `json:"SamlIamRole,omitempty"`
	IamRole            []string `json:"IamRole,omitempty"`
}

type accountResourceType struct {
	resourceType *v2.ResourceType
	connector    *Okta
}

const apiPathDefaultAppSchema = "/api/v1/meta/schemas/apps/%s/default"

const (
	appUserScope  = "USER"
	appGroupScope = "GROUP"
)

func (o *accountResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func accountBuilder(connector *Okta) *accountResourceType {
	return &accountResourceType{
		resourceType: resourceTypeAccount,
		connector:    connector,
	}
}

func (o *accountResourceType) List(
	ctx context.Context,
	resourceID *v2.ResourceId,
	token *pagination.Token,
) ([]*v2.Resource, string, annotations.Annotations, error) {
	awsConfig, err := o.connector.getAWSApplicationConfig(ctx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("error getting aws app settings config")
	}
	if !awsConfig.UseGroupMapping {
		accountId := awsConfig.IdentityProviderArnAccountID
		// TODO(lauren) what should name be?
		resource, err := resource2.NewResource(accountId, o.resourceType, accountId)
		if err != nil {
			return nil, "", nil, err
		}
		return []*v2.Resource{resource}, "", nil, nil
	} else {
		bag, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeAccount.Id})
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-aws-connector: failed to parse page token: %w", err)
		}

		qp := queryParams(token.Size, page)
		accountSet := mapset.NewSet[string]()

		appGroups, respCtx, err := listGroupsHelper(ctx, o.connector.client, token, qp)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-aws-connector: failed to list application groups: %w", err)
		}

		var rv []*v2.Resource

		nextPage, annos, err := parseResp(respCtx.OktaResponse)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-aws-connector: failed to parse response: %w", err)
		}
		err = bag.Next(nextPage)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-aws-connector: failed to fetch bag.Next: %w", err)
		}

		for _, group := range appGroups {
			accountId, _, matchesRolePattern, err := parseAccountIDAndRoleFromGroupName(ctx, awsConfig.RoleRegex, group.Profile.Name)
			if err != nil {
				return nil, "", nil, fmt.Errorf("okta-aws-connector: failed to parse account id and role from group name: %w", err)
			}
			if !matchesRolePattern {
				continue
			}
			accountSet.Add(accountId)
		}

		for accountId := range accountSet.Iterator().C {
			resource, err := resource2.NewResource(accountId, o.resourceType, accountId)
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
}

func (o *accountResourceType) Entitlements(
	ctx context.Context,
	resource *v2.Resource,
	token *pagination.Token,
) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	awsConfig, err := o.connector.getAWSApplicationConfig(ctx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("error getting aws app settings config")
	}
	var rv []*v2.Entitlement
	if !awsConfig.UseGroupMapping {
		awsRoles, respCtx, err := o.listAWSSamlRoles(ctx)
		if err != nil {
			return nil, "", nil, err
		}
		for _, role := range awsRoles.SamlIamRole {
			rv = append(rv, samlRoleEntitlement(resource, role))
		}
		annos, err := parseGetResp(respCtx.OktaResponse)
		if err != nil {
			return nil, "", nil, err
		}
		return rv, "", annos, nil
	} else {
		bag, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeAccount.Id})
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-aws-connector: failed to parse page token: %w", err)
		}

		qp := queryParams(token.Size, page)

		groups, respCtx, err := listGroupsHelper(ctx, o.connector.client, token, qp)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-aws-connector: failed to list application groups: %w", err)
		}

		nextPage, annos, err := parseResp(respCtx.OktaResponse)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-aws-connector: failed to parse response: %w", err)
		}
		err = bag.Next(nextPage)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-aws-connector: failed to fetch bag.Next: %w", err)
		}

		for _, group := range groups {
			accountId, roleName, matchesRolePattern, err := parseAccountIDAndRoleFromGroupName(ctx, awsConfig.RoleRegex, group.Profile.Name)
			if err != nil {
				return nil, "", nil, fmt.Errorf("okta-aws-connector: failed to parse account id and role from group name: %w", err)
			}
			if !matchesRolePattern || accountId != resource.GetId().Resource {
				continue
			}
			rv = append(rv, samlRoleEntitlement(resource, roleName))
		}

		pageToken, err := bag.Marshal()
		if err != nil {
			return nil, "", nil, err
		}

		return rv, pageToken, annos, nil
	}
}

func samlRoleEntitlement(resource *v2.Resource, role string) *v2.Entitlement {
	return sdkEntitlement.NewAssignmentEntitlement(resource, role,
		sdkEntitlement.WithDisplayName(fmt.Sprintf("%s Role Member", role)),
		sdkEntitlement.WithDescription(fmt.Sprintf("Has the %s role in AWS Okta app", role)),
		sdkEntitlement.WithGrantableTo(resourceTypeUser, resourceTypeGroup),
	)
}

func parseSAMLRoleFromEntitlementID(entitlementID string) (string, error) {
	parts := strings.Split(entitlementID, ":")
	if len(parts) != 3 {
		return "", fmt.Errorf("okta-aws-connector: invalid entitlement ID format: %s, expected format: resource-type:resource-id:samlRole", entitlementID)
	}
	resourceType := parts[0]
	resourceID := parts[1]
	samlRole := parts[2]
	if resourceType == "" || resourceID == "" || samlRole == "" {
		return "", fmt.Errorf("okta-aws-connector: entitlement ID contains empty components: %s", entitlementID)
	}
	return samlRole, nil
}

// Add group principal grant if assigned with a saml role
// Use expand grant if join all roles/use group mapping enabled to get user grants
// Otherwise:
// list application users, if direct assignment, give those role, if group scope, look at all the users groups
// if join all roles also do the above JUST for direct assignments.
func (o *accountResourceType) Grants(
	ctx context.Context,
	resource *v2.Resource,
	token *pagination.Token,
) ([]*v2.Grant, string, annotations.Annotations, error) {
	awsConfig, err := o.connector.getAWSApplicationConfig(ctx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("error getting aws app settings config")
	}
	bag := &pagination.Bag{}
	err = bag.Unmarshal(token.Token)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-aws-connector: failed to parse page token: %w", err)
	}
	if bag.Current() == nil {
		if !awsConfig.UseGroupMapping {
			bag.Push(pagination.PageState{
				ResourceTypeID: resourceTypeUser.Id,
			})
		}
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceTypeGroup.Id,
		})
	}
	page := bag.PageToken()

	var rv []*v2.Grant
	var oktaResp *okta.Response

	switch bag.ResourceTypeID() {
	case resourceTypeUser.Id:
		rv, oktaResp, err = o.userGrants(ctx, resource, token, page)
	case resourceTypeGroup.Id:
		rv, oktaResp, err = o.groupGrants(ctx, resource, token, page)
	default:
		rv, oktaResp, err = o.groupGrants(ctx, resource, token, page)
	}
	if err != nil {
		return nil, "", nil, err
	}

	nextPage, annos, err := parseResp(oktaResp)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-aws-connector: failed to parse response: %w", err)
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-aws-connector: failed to fetch bag.Next: %w", err)
	}

	pageToken, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, err
	}
	return rv, pageToken, annos, nil
}

func (o *accountResourceType) userGrants(ctx context.Context, resource *v2.Resource, token *pagination.Token, page string) ([]*v2.Grant, *okta.Response, error) {
	awsConfig, err := o.connector.getAWSApplicationConfig(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-aws-connector: error getting aws app settings config")
	}

	var rv []*v2.Grant

	qp := queryParams(token.Size, page)
	appUsers, respContext, err := listApplicationUsers(ctx, o.connector.client, o.connector.awsConfig.OktaAppId, token, qp)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-aws-connector: error listing application users %w", err)
	}

	for _, appUser := range appUsers {
		appUserSAMLRolesMap := mapset.NewSet[string]()

		// For users with direct assignments or with Union enabled, we extract samlRoles from their profile
		if appUser.Scope == appUserScope || (appUser.Scope == appGroupScope && awsConfig.SamlRolesUnionEnabled) {
			appUserSAMLRoles, err := getSAMLRolesFromAppUserProfile(ctx, appUser)
			if err != nil {
				return nil, nil, fmt.Errorf("okta-aws-connector: failed to get saml roles for user '%s': %w", appUser.Id, err)
			}
			appUserSAMLRolesMap.Append(appUserSAMLRoles...)
		}

		// For group-scoped users (no direct assignment) and when Union/JoinAllRoles is disabled,
		// samlRoles are gathered by inspecting the user's group memberships
		if appUser.Scope == appGroupScope && !awsConfig.JoinAllRoles && !awsConfig.SamlRolesUnionEnabled {
			appUserSAMLRolesMap, err = o.collectRolesFromUserGroups(ctx, appUser.Id)
			if err != nil {
				return nil, nil, err
			}
		}

		for samlRole := range appUserSAMLRolesMap.Iterator().C {
			rv = append(rv, o.accountGrant(resource, samlRole, appUser.Id))
		}
	}

	return rv, respContext.OktaResponse, nil
}

func (o *accountResourceType) collectRolesFromUserGroups(
	ctx context.Context,
	userID string,
) (mapset.Set[string], error) {
	userGroups, _, err := listUsersGroupsClient(ctx, o.connector.client, userID)
	if err != nil {
		return nil, fmt.Errorf("okta-aws-connector: failed to get groups for user '%s': %w", userID, err)
	}

	roles := mapset.NewSet[string]()

	for _, group := range userGroups {
		appGroup, err := o.getOktaAppGroupFromCacheOrFetch(ctx, group.Id)
		if err != nil {
			return nil, err
		}
		if appGroup != nil {
			roles.Append(appGroup.samlRoles...)
		}
	}

	return roles, nil
}

func (o *accountResourceType) groupGrants(ctx context.Context, resource *v2.Resource, token *pagination.Token, page string) ([]*v2.Grant, *okta.Response, error) {
	awsConfig, err := o.connector.getAWSApplicationConfig(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-aws-connector: error getting aws app settings config")
	}
	qp := queryParams(token.Size, page)
	var rv []*v2.Grant

	if awsConfig.UseGroupMapping {
		groups, respCtx, err := listGroupsHelper(ctx, o.connector.client, token, qp)
		if err != nil {
			return nil, nil, fmt.Errorf("okta-aws-connector: failed to list groups: %w", err)
		}
		for _, group := range groups {
			accountId, roleName, matchesRolePattern, err := parseAccountIDAndRoleFromGroupName(ctx, awsConfig.RoleRegex, group.Profile.Name)
			if err != nil {
				return nil, nil, fmt.Errorf("okta-aws-connector: failed to parse account id and role from group name: %w", err)
			}
			if !matchesRolePattern || accountId != resource.GetId().GetResource() {
				continue
			}
			grant, err := o.accountGrantGroupExpandable(resource, roleName, group.Id)
			if err != nil {
				return nil, nil, fmt.Errorf("okta-aws-connector: failed to create expandable group grant: %w", err)
			}
			rv = append(rv, grant)
		}
		return rv, respCtx.OktaResponse, err
	}

	appGroups, respCtx, err := listApplicationGroupAssignments(ctx, o.connector.client, o.connector.awsConfig.OktaAppId, token, qp)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-aws-connector: failed to list application groups: %w", err)
	}

	for _, appGroup := range appGroups {
		appGroupSAMLRoles, err := appGroupSAMLRolesWrapper(ctx, appGroup)
		if err != nil {
			return nil, nil, fmt.Errorf("okta-aws-connector: failed to get saml roles for app group: %w", err)
		}

		// TODO(lauren) we only need this when !awsConfig.JoinAllRoles
		awsConfig.appGroupCache.Store(appGroup.Id, appGroupSAMLRoles)
		for _, role := range appGroupSAMLRoles.samlRoles {
			if !awsConfig.JoinAllRoles {
				rv = append(rv, o.accountGrantGroup(resource, role, appGroup.Id))
			} else {
				grant, err := o.accountGrantGroupExpandable(resource, role, appGroup.Id)
				if err != nil {
					return nil, nil, fmt.Errorf("okta-aws-connector: failed to create expandable group grant: %w", err)
				}
				rv = append(rv, grant)
			}
		}
	}
	return rv, respCtx.OktaResponse, err
}

func (o *accountResourceType) accountGrant(resource *v2.Resource, samlRole string, oktaUserId string) *v2.Grant {
	grantOpts := make([]sdkGrant.GrantOption, 0)
	if o.connector.awsConfig.AWSSourceIdentityMode {
		grantOpts = append(grantOpts, sdkGrant.WithAnnotation(&v2.ExternalResourceMatchID{Id: oktaUserId}))
	}
	ur := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeUser.Id, Resource: oktaUserId}}
	return sdkGrant.NewGrant(resource, samlRole, ur, grantOpts...)
}

func (o *accountResourceType) accountGrantGroup(resource *v2.Resource, samlRole string, groupId string) *v2.Grant {
	grantOpts := make([]sdkGrant.GrantOption, 0)
	if o.connector.awsConfig.AWSSourceIdentityMode {
		grantOpts = append(grantOpts, sdkGrant.WithAnnotation(&v2.ExternalResourceMatchID{Id: groupId}))
	}
	gr := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeGroup.Id, Resource: groupId}}
	return sdkGrant.NewGrant(resource, samlRole, gr, grantOpts...)
}

func (o *accountResourceType) accountGrantGroupExpandable(resource *v2.Resource, samlRole string, groupId string) (*v2.Grant, error) {
	rID := &v2.ResourceId{ResourceType: resourceTypeGroup.Id, Resource: groupId}
	gr := &v2.Resource{Id: rID}

	grantOpts := make([]sdkGrant.GrantOption, 0)
	expandEntitlementId := fmt.Sprintf("group:%s:member", groupId)
	if o.connector.awsConfig.AWSSourceIdentityMode {
		ent := sdkEntitlement.NewAssignmentEntitlement(gr, "member")
		bidEnt, err := bid.MakeBid(ent)
		if err != nil {
			return nil, err
		}
		expandEntitlementId = bidEnt
		grantOpts = append(grantOpts, sdkGrant.WithAnnotation(&v2.ExternalResourceMatchID{Id: groupId}))
	}

	grantOpts = append(grantOpts, sdkGrant.WithAnnotation(&v2.GrantExpandable{
		EntitlementIds: []string{expandEntitlementId},
		Shallow:        true,
	}))

	return sdkGrant.NewGrant(resource, samlRole, gr, grantOpts...), nil
}

/*
Join all roles: This option enables merging all available roles assigned to a user as follows:

For example, if a user is directly assigned Role1 and Role2 (user to app assignment),
and the user belongs to group GroupAWS with RoleA and RoleB assigned (group to app assignment), then:

Join all roles OFF: Role1 and Role2 are available upon login to AWS
Join all roles ON: Role1, Role2, RoleA, and RoleB are available upon login to AWS
*/

func (o *accountResourceType) listAWSSamlRoles(ctx context.Context) (*AWSRoles, *responseContext, error) {
	apiUrl := fmt.Sprintf("/api/v1/internal/apps/%s/types", o.connector.awsConfig.OktaAppId)

	rq := o.connector.client.CloneRequestExecutor()

	req, err := rq.WithAccept("application/json").WithContentType("application/json").NewRequest(http.MethodGet, apiUrl, nil)
	if err != nil {
		return nil, nil, err
	}

	var awsRoles *AWSRoles
	resp, err := rq.Do(ctx, req, &awsRoles)
	if err != nil {
		return nil, nil, err
	}
	respCtx, err := responseToContext(&pagination.Token{}, resp)
	if err != nil {
		return nil, nil, err
	}

	return awsRoles, respCtx, nil
}

func getSAMLRolesFromAppUserProfile(ctx context.Context, appUser *okta.AppUser) ([]string, error) {
	l := ctxzap.Extract(ctx)
	if appUser.Profile == nil {
		l.Error("app user profile was nil", zap.Any("userId", appUser.Id))
		return nil, nil
	}
	appUserProfile, ok := appUser.Profile.(map[string]interface{})
	if !ok {
		l.Error("error casting app user profile", zap.Any("userId", appUser.Id))
		return nil, nil
	}
	return getSAMLRoles(appUserProfile)
}

func getOrCreateAppUserProfile(ctx context.Context, appUser *okta.AppUser) map[string]any {
	l := ctxzap.Extract(ctx)
	if appUser.Profile == nil {
		l.Error("app user profile was nil", zap.Any("userId", appUser.Id))
		return make(map[string]any)
	}
	appUserProfile, ok := appUser.Profile.(map[string]any)
	if !ok {
		l.Error("error casting app user profile", zap.Any("userId", appUser.Id))
		return make(map[string]any)
	}
	return appUserProfile
}

func getSAMLRolesFromAppGroupProfile(ctx context.Context, appGroup *okta.ApplicationGroupAssignment) ([]string, error) {
	l := ctxzap.Extract(ctx)
	if appGroup.Profile == nil {
		l.Error("app group profile was nil", zap.Any("groupId", appGroup.Id))
		return nil, nil
	}
	appGroupProfile, ok := appGroup.Profile.(map[string]interface{})
	if !ok {
		l.Error("error casting app user profile", zap.Any("groupId", appGroup.Id))
		return nil, nil
	}
	return getSAMLRoles(appGroupProfile)
}

func getSAMLRoles(profile map[string]interface{}) ([]string, error) {
	samlRolesField := profile["samlRoles"]
	if samlRolesField == nil {
		return nil, nil
	}

	samlRoles, ok := samlRolesField.([]interface{})
	if !ok {
		return nil, errors.New("unexpected type in profile[\"samlRoles\"")
	}

	ret := make([]string, len(samlRoles))
	for i, r := range samlRoles {
		role, ok := r.(string)
		if !ok {
			return nil, errors.New("role was not string")
		}
		ret[i] = role
	}
	return ret, nil
}

func (o *accountResourceType) getOktaAppGroupFromCacheOrFetch(ctx context.Context, groupId string) (*OktaAppGroupWrapper, error) {
	l := ctxzap.Extract(ctx)
	awsConfig, err := o.connector.getAWSApplicationConfig(ctx)
	if err != nil {
		return nil, err
	}
	appGroupSAMLRoles, err := awsConfig.getAppGroupFromCache(ctx, groupId)
	if err != nil {
		return nil, err
	}
	if appGroupSAMLRoles != nil {
		l.Debug("okta-aws-connector: found group in cache", zap.String("groupId", groupId))
		return appGroupSAMLRoles, nil
	}
	notAnAppGroup, err := awsConfig.checkIfNotAppGroupFromCache(ctx, groupId)
	if err != nil {
		return nil, err
	}
	if notAnAppGroup {
		return nil, nil
	}

	oktaAppGroup, resp, err := o.connector.client.Application.GetApplicationGroupAssignment(ctx, o.connector.awsConfig.OktaAppId, groupId, nil)
	if err != nil {
		if resp == nil {
			return nil, fmt.Errorf("okta-aws-connector: failed to fetch application group assignment: %w", err)
		}

		defer resp.Body.Close()
		errOkta, err := getError(resp)
		if err != nil {
			return nil, err
		}
		if errOkta.ErrorCode != ResourceNotFoundExceptionErrorCode {
			l.Warn("okta-aws-connector: ", zap.String("ErrorCode", errOkta.ErrorCode), zap.String("ErrorSummary", errOkta.ErrorSummary))
			return nil, fmt.Errorf("okta-aws-connector: %v", errOkta)
		}
		awsConfig.notAppGroupCache.Store(groupId, true)
		return nil, nil
	}

	appGroupSAMLRoles, err = appGroupSAMLRolesWrapper(ctx, oktaAppGroup)
	if err != nil {
		return nil, err
	}
	awsConfig.appGroupCache.Store(groupId, appGroupSAMLRoles)

	return appGroupSAMLRoles, nil
}

const apiPathApplicationGroup = "/api/v1/apps/%s/groups/%s"

type JSONPatchOperation struct {
	// The operation (PATCH action)
	Op string `json:"op,omitempty"`
	// The resource path of the attribute to update
	Path string `json:"path,omitempty"`
	// The update operation value
	Value interface{} `json:"value,omitempty"`
}

func (o *accountResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	if principal.Id.ResourceType != resourceTypeUser.Id && principal.Id.ResourceType != resourceTypeGroup.Id {
		return nil, fmt.Errorf("okta-aws-connector: only users or groups can be granted app membership")
	}
	awsConfig, err := o.connector.getAWSApplicationConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting aws app settings config")
	}

	if awsConfig.UseGroupMapping {
		return nil, fmt.Errorf("okta-aws-connector: group assignments are based on group names matching regex")
	}

	appID := o.connector.awsConfig.OktaAppId
	newSamlRole, err := parseSAMLRoleFromEntitlementID(entitlement.GetId())
	if err != nil {
		return nil, err
	}

	if newSamlRole == "" {
		return nil, fmt.Errorf("okta-aws-connector: entitlement %s had an empty slug", entitlement.Id)
	}

	switch principal.Id.ResourceType {
	case resourceTypeUser.Id:
		userID := principal.Id.Resource
		appUser, response, err := o.connector.client.Application.GetApplicationUser(ctx, appID, userID, nil)
		if err != nil {
			if response == nil {
				return nil, fmt.Errorf("okta-aws-connector: failed to fetch application user: %w", err)
			}
			defer response.Body.Close()
			errOkta, err := getError(response)
			if err != nil {
				return nil, err
			}
			if errOkta.ErrorCode != ResourceNotFoundExceptionErrorCode {
				return nil, fmt.Errorf("okta-aws-connector: error fetching application user: %v", errOkta)
			}
		}

		if appUser != nil {
			if appUser.Scope == appGroupScope && (!o.connector.awsConfig.AllowGroupToDirectAssignmentConversionForProvisioning || !awsConfig.JoinAllRoles) {
				return nil, fmt.Errorf("okta-aws-connector: connect add individual assignment for user with group assignment '%s'", appUser.Id)
			}

			appUserProfile := getOrCreateAppUserProfile(ctx, appUser)
			samlRoles, err := getSAMLRoles(appUserProfile)
			if err != nil {
				return nil, fmt.Errorf("okta-aws-connector: failed to get saml roles for user '%s': %w", appUser.Id, err)
			}

			if slices.Contains(samlRoles, newSamlRole) {
				return annotations.New(&v2.GrantAlreadyExists{}), nil
			}

			if samlRoles == nil {
				samlRoles = make([]string, 0)
			}

			samlRoles = append(samlRoles, newSamlRole)
			appUserProfile["samlRoles"] = samlRoles

			payload := okta.AppUser{
				Profile: appUserProfile,
				Scope:   appUserScope,
			}
			_, _, err = o.connector.client.Application.UpdateApplicationUser(ctx, appID, appUser.Id, payload)
			if err != nil {
				return nil, fmt.Errorf("okta-aws-connector: failed to update application user: %w", err)
			}

			return nil, nil
		}

		profile := map[string]any{
			"samlRoles": []string{newSamlRole},
		}

		payload := okta.AppUser{
			Id:      userID,
			Scope:   appUserScope,
			Profile: profile,
		}
		_, _, err = o.connector.client.Application.AssignUserToApplication(ctx, appID, payload)
		if err != nil {
			return nil, fmt.Errorf("okta-aws-connector: error assigning app to user %w", err)
		}
	case resourceTypeGroup.Id:
		groupID := principal.Id.Resource
		appGroup, response, err := o.connector.client.Application.GetApplicationGroupAssignment(ctx, appID, groupID, nil)
		if err != nil {
			if response == nil {
				return nil, fmt.Errorf("okta-aws-connector: failed to fetch application group assignment: %w", err)
			}
			defer response.Body.Close()
			errOkta, err := getError(response)
			if err != nil {
				return nil, err
			}

			if errOkta.ErrorCode != ResourceNotFoundExceptionErrorCode {
				return nil, fmt.Errorf("okta-aws-connector: error fetching application group assignment %v", errOkta)
			}
		}

		if appGroup != nil {
			samlRoles, err := getSAMLRolesFromAppGroupProfile(ctx, appGroup)
			if err != nil {
				return nil, fmt.Errorf("okta-aws-connector: failed to get saml roles for app group profile '%s': %w", groupID, err)
			}
			if slices.Contains(samlRoles, newSamlRole) {
				return annotations.New(&v2.GrantAlreadyExists{}), nil
			}
			if samlRoles == nil {
				samlRoles = make([]string, 0)
			}
			samlRoles = append(samlRoles, newSamlRole)
			_, err = updateApplicationGroup(ctx, o.connector.client, appID, groupID, samlRoles)
			if err != nil {
				return nil, fmt.Errorf("okta-aws-connector: error updating application group '%s': %w", groupID, err)
			}
			return nil, nil
		}

		profile := map[string]any{
			"samlRoles": []string{newSamlRole},
		}
		payload := okta.ApplicationGroupAssignment{
			Profile: profile,
		}
		_, _, err = o.connector.client.Application.CreateApplicationGroupAssignment(ctx, appID, groupID, payload)
		if err != nil {
			return nil, fmt.Errorf("okta-aws-connector: error creating application group assignment %w", err)
		}
	default:
		return nil, fmt.Errorf("okta-aws-connector: invalid grant resource type: %s", principal.Id.ResourceType)
	}

	return nil, nil
}

func (o *accountResourceType) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	if grant.Principal.Id.ResourceType != resourceTypeUser.Id && grant.Principal.Id.ResourceType != resourceTypeGroup.Id {
		return nil, fmt.Errorf("okta-aws-connector: only users or groups can be have aws account role revoked")
	}
	awsConfig, err := o.connector.getAWSApplicationConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("okta-aws-connector: error getting aws app settings config")
	}

	if awsConfig.UseGroupMapping {
		return nil, fmt.Errorf("okta-aws-connector: grants are based on group name matching configured regular expression")
	}

	appID := o.connector.awsConfig.OktaAppId
	samlRoleToRemove, err := parseSAMLRoleFromEntitlementID(grant.GetEntitlement().GetId())
	if err != nil {
		return nil, err
	}

	if samlRoleToRemove == "" {
		return nil, fmt.Errorf("okta-aws-connector: entitlement %s had an empty slug", grant.Entitlement.Id)
	}

	switch grant.Principal.Id.ResourceType {
	case resourceTypeUser.Id:
		userID := grant.Principal.Id.Resource
		appUser, response, err := o.connector.client.Application.GetApplicationUser(ctx, appID, userID, nil)
		if err != nil {
			if response == nil {
				return nil, fmt.Errorf("okta-aws-connector: failed to fetch application user: %w", err)
			}
			defer response.Body.Close()
			errOkta, err := getError(response)
			if err != nil {
				return nil, err
			}
			if errOkta.ErrorCode != ResourceNotFoundExceptionErrorCode {
				// TODO(lauren) should we error if app user not found?
				return nil, fmt.Errorf("okta-aws-connector: error fetching application user: %v", errOkta)
			}
			return nil, nil
		}

		if appUser.Scope == appGroupScope && !o.connector.awsConfig.AllowGroupToDirectAssignmentConversionForProvisioning || !awsConfig.JoinAllRoles {
			return nil, fmt.Errorf("okta-aws-connector: connect remove role granted via group assignment '%s'", appUser.Id)
		}

		samlRoles, err := getSAMLRolesFromAppUserProfile(ctx, appUser)
		if err != nil {
			return nil, fmt.Errorf("okta-aws-connector: failed to get saml roles for user '%s': %w", appUser.Id, err)
		}
		if !slices.Contains(samlRoles, samlRoleToRemove) {
			return annotations.New(&v2.GrantAlreadyRevoked{}), nil
		}

		appUserProfile, ok := appUser.Profile.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("okta-aws-connector: error converting app user profile '%s'", appUser.Id)
		}

		newSamlRoles := removeSamlRole(samlRoles, samlRoleToRemove)

		appUserProfile["samlRoles"] = newSamlRoles

		payload := okta.AppUser{
			Profile: appUserProfile,
			Scope:   appUserScope,
		}
		_, _, err = o.connector.client.Application.UpdateApplicationUser(ctx, appID, appUser.Id, payload)
		if err != nil {
			return nil, fmt.Errorf("okta-aws-connector: error updating application user: %w", err)
		}
	case resourceTypeGroup.Id:
		groupID := grant.Principal.Id.Resource
		appGroup, response, err := o.connector.client.Application.GetApplicationGroupAssignment(ctx, appID, groupID, nil)
		if err != nil {
			if response == nil {
				return nil, fmt.Errorf("okta-aws-connector: failed to fetch application group assignment: %w", err)
			}
			defer response.Body.Close()
			errOkta, err := getError(response)
			if err != nil {
				return nil, err
			}
			// TODO(lauren) should we error if app group not found?
			if errOkta.ErrorCode != ResourceNotFoundExceptionErrorCode {
				return nil, fmt.Errorf("okta-aws-connector: error fetching application group assignment %v", errOkta)
			}
			return nil, nil
		}

		samlRoles, err := getSAMLRolesFromAppGroupProfile(ctx, appGroup)
		if err != nil {
			return nil, fmt.Errorf("okta-aws-connector: failed to get saml roles for app group '%s': %w", groupID, err)
		}
		if !slices.Contains(samlRoles, samlRoleToRemove) {
			return annotations.New(&v2.GrantAlreadyRevoked{}), nil
		}
		newSamlRoles := removeSamlRole(samlRoles, samlRoleToRemove)
		_, err = updateApplicationGroup(ctx, o.connector.client, appID, groupID, newSamlRoles)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("okta-aws-connector: invalid revoke resource type: %s", grant.Principal.Id.ResourceType)
	}
	return nil, nil
}

func updateApplicationGroup(
	ctx context.Context,
	client *okta.Client,
	appID string,
	groupID string,
	samlRoles []string,
) (*okta.ApplicationGroupAssignment, error) {
	url := fmt.Sprintf(apiPathApplicationGroup, appID, groupID)

	payload := []JSONPatchOperation{
		{
			Op:    "replace",
			Path:  "/profile/samlRoles",
			Value: samlRoles,
		},
	}
	rq := client.CloneRequestExecutor()
	req, err := rq.
		WithAccept(ContentType).
		WithContentType(ContentType).
		NewRequest(http.MethodPatch, url, payload)
	if err != nil {
		return nil, err
	}

	var appGroup *okta.ApplicationGroupAssignment
	resp, err := rq.Do(ctx, req, &appGroup)
	if err != nil {
		oktaErr, err := getError(resp)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("okta-aws-connector: error updating application group: %v", oktaErr)
	}

	return appGroup, nil
}

func removeSamlRole(samlRoles []string, samlRoleToRemove string) []string {
	newSamlRoles := make([]string, 0)
	for _, samlRole := range samlRoles {
		if samlRole == samlRoleToRemove {
			continue
		}
		newSamlRoles = append(newSamlRoles, samlRole)
	}
	return newSamlRoles
}
