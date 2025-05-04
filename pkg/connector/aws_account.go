package connector

import (
	"context"
	"errors"
	"fmt"
	"net/http"

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
