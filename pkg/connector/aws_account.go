package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	sdkEntitlement "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	sdkGrant "github.com/conductorone/baton-sdk/pkg/types/grant"
	resource2 "github.com/conductorone/baton-sdk/pkg/types/resource"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"go.uber.org/zap"
)

type OktaAppGroupWrapper struct {
	oktaGroup *okta.Group
	samlRoles []string
	accountID string
}

type AWSRoles struct {
	AWSEnvironmentEnum []string `json:"AWSEnvironmentEnum,omitempty"`
	SamlIamRole        []string `json:"SamlIamRole,omitempty"`
	IamRole            []string `json:"IamRole,omitempty"`
}

type GroupMappingGrant struct {
	OktaUserID string
	Role       string
}

type accountResourceType struct {
	resourceType *v2.ResourceType
	connector    *Okta
}

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
		// TODO(lauren) move to new connector
		re, err := regexp.Compile(strings.ToLower(awsConfig.IdentityProviderArnRegex))
		if err != nil {
			log.Fatal(err)
		}
		match := re.FindStringSubmatch(strings.ToLower(awsConfig.IdentityProviderArn))

		// First element is full string
		if len(match) != 2 {
			if err != nil {
				return nil, "", nil, fmt.Errorf("error getting aws account id")
			}
		}
		accountId := match[1]

		// TODO(lauren) what should name be?
		resource, err := resource2.NewResource(accountId, o.resourceType, accountId)
		if err != nil {
			return nil, "", nil, err
		}
		return []*v2.Resource{resource}, "", nil, nil
	} else {
		// TODO(lauren) what resource type should this be
		bag, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeUser.Id})
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
		}

		qp := queryParamsExpand(token.Size, page, "group")
		accountSet := mapset.NewSet[string]()

		appGroups, respCtx, err := listApplicationGroupsHelper(ctx, o.connector.client, o.connector.awsConfig.OktaAppId, token, qp)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list application groups: %w", err)
		}

		var rv []*v2.Resource

		nextPage, annos, err := parseResp(respCtx.OktaResponse)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
		}
		err = bag.Next(nextPage)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
		}

		for _, group := range appGroups {
			accountId, _, matchesRolePattern, err := parseAccountIDAndRoleFromGroupName(ctx, awsConfig.RoleRegex, group.Profile.Name)
			if err != nil {
				return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse account id and role from group name: %w", err)
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
		awsRoles, _, err := o.listAWSSamlRoles(ctx)
		if err != nil {
			return nil, "", nil, err
		}
		for _, role := range awsRoles.SamlIamRole {
			rv = append(rv, samlRoleEntitlement(resource, role))
		}
		return rv, "", nil, nil
	} else {
		// TODO(lauren) what resource type should this be
		bag, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeUser.Id})
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
		}

		qp := queryParamsExpand(token.Size, page, "group")

		appGroups, respCtx, err := listApplicationGroupsHelper(ctx, o.connector.client, o.connector.awsConfig.OktaAppId, token, qp)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list application groups: %w", err)
		}

		nextPage, annos, err := parseResp(respCtx.OktaResponse)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
		}
		err = bag.Next(nextPage)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
		}

		for _, group := range appGroups {
			accountId, roleName, matchesRolePattern, err := parseAccountIDAndRoleFromGroupName(ctx, awsConfig.RoleRegex, group.Profile.Name)
			if err != nil {
				return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse account id and role from group name: %w", err)
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
// if join all roles also do the above JUST for direct assignments
func (o *accountResourceType) Grants(
	ctx context.Context,
	resource *v2.Resource,
	token *pagination.Token,
) ([]*v2.Grant, string, annotations.Annotations, error) {
	awsConfig, err := o.connector.getAWSApplicationConfig(ctx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("error getting aws app settings config")
	}
	var rv []*v2.Grant

	// TODO(lauren) what resource type should this be
	bag, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resource.Id.ResourceType})
	//bag, page, err := parsePageToken(token.Token, resource.Id)
	//bag, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeUser.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	switch bag.ResourceTypeID() {
	case resourceTypeUser.Id:
		qp := queryParams(token.Size, page)
		appUsers, respContext, err := listApplicationUsers(ctx, o.connector.client, o.connector.awsConfig.OktaAppId, token, qp)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: list application users %w", err)
		}

		for _, appUser := range appUsers {
			appUserSAMLRolesMap := mapset.NewSet[string]()

			if appUser.Scope == "USER" {
				if appUser.Profile == nil {
					// TODO(lauren) continue or error?
					continue
				}
				appUserProfile, ok := appUser.Profile.(map[string]interface{})
				if !ok {
					// TODO(lauren) continue or error?
					continue
				}
				appUserSAMLRoles, err := getSAMLRoles(appUserProfile)
				if err != nil {
					return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to get saml roles for user '%s': %w", appUser.Id, err)
				}
				appUserSAMLRolesMap.Append(appUserSAMLRoles...)
			}

			// If the user scope is "GROUP", this means the user does not have a direct assignment
			// We want to get the union of the group's samlRoles that the user is assigned to
			// We also want a union of the group's samlRoles if useGroupMapping is enabled
			if appUser.Scope == "GROUP" && !awsConfig.JoinAllRoles {
				userGroups, _, err := listUsersGroupsClient(ctx, o.connector.client, appUser.Id)
				if err != nil {
					return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to groups for user '%s': %w", appUser.Id, err)
				}

				for _, userGroup := range userGroups {
					// TODO(lauren) additional request, need to update ratelimit annotation?
					oktaAppGroup, err := o.getOktaAppGroupFromCacheOrFetch(ctx, userGroup.Id)
					if err != nil {
						return nil, "", nil, err
					}
					if oktaAppGroup == nil {
						continue
					}
					appUserSAMLRolesMap.Append(oktaAppGroup.samlRoles...)
				}
			}

			// TODO(lauren) use ToSlice instead?
			for samlRole := range appUserSAMLRolesMap.Iterator().C {
				rv = append(rv, accountGrant(resource, samlRole, appUser.Id))
			}
		}
		nextPage, annos, err := parseResp(respContext.OktaResponse)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
		}

		err = bag.Next(nextPage)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
		}

		pageToken, err := bag.Marshal()
		if err != nil {
			return nil, "", nil, err
		}
		return rv, pageToken, annos, nil
	default:
		qp := queryParamsExpand(token.Size, page, "group")
		appGroups, respCtx, err := listApplicationGroupAssignments(ctx, o.connector.client, o.connector.awsConfig.OktaAppId, token, qp)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list application groups: %w", err)
		}

		nextPage, annos, err := parseResp(respCtx.OktaResponse)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
		}

		for _, group := range appGroups {
			oktaAppGroup, err := o.oktaAppGroup(ctx, group)
			if err != nil {
				return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list application groups: %w", err)
			}
			if oktaAppGroup.accountID != resource.GetId().GetResource() {
				continue
			}

			// TODO(lauren) we only need this cached when !awsConfig.UseGroupMapping & !awsConfig.JoinAllRoles
			awsConfig.appGroupCache.Store(group.Id, oktaAppGroup)
			for _, role := range oktaAppGroup.samlRoles {
				if !awsConfig.UseGroupMapping && !awsConfig.JoinAllRoles {
					rv = append(rv, accountGrantGroup(resource, role, oktaAppGroup.oktaGroup.Id))
				} else {
					rv = append(rv, accountGrantGroupExpandable(resource, role, oktaAppGroup.oktaGroup.Id))
				}
			}
		}

		err = bag.Next(nextPage)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
		}

		if !awsConfig.UseGroupMapping {
			bag.Push(pagination.PageState{
				ResourceTypeID: resourceTypeUser.Id,
			})
		}

		pageToken, err := bag.Marshal()
		if err != nil {
			return nil, "", nil, err
		}

		return rv, pageToken, annos, nil
	}
}

func accountGrant(resource *v2.Resource, samlRole string, oktaUserId string) *v2.Grant {
	ur := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeUser.Id, Resource: oktaUserId}}
	return sdkGrant.NewGrant(resource, samlRole, ur)
}

func accountGrantGroup(resource *v2.Resource, samlRole string, groupId string) *v2.Grant {
	gr := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeGroup.Id, Resource: groupId}}
	return sdkGrant.NewGrant(resource, samlRole, gr)
}

func accountGrantGroupExpandable(resource *v2.Resource, samlRole string, groupId string) *v2.Grant {
	gr := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeGroup.Id, Resource: groupId}}
	return sdkGrant.NewGrant(resource, samlRole, gr, sdkGrant.WithAnnotation(&v2.GrantExpandable{
		EntitlementIds: []string{fmt.Sprintf("group:%s:member", groupId)},
		Shallow:        true,
	}))
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

	return awsRoles, respCtx, nil
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

func (o *accountResourceType) oktaAppGroup(ctx context.Context, appGroup *okta.ApplicationGroupAssignment) (*OktaAppGroupWrapper, error) {
	embedded := appGroup.Embedded
	if embedded == nil {
		return nil, fmt.Errorf("app group '%s' embedded data was nil", appGroup.Id)
	}
	embeddedMap, ok := embedded.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("app group embedded data was not a map for group with id '%s'", appGroup.Id)
	}
	embeddedGroup, ok := embeddedMap["group"]
	if !ok {
		return nil, fmt.Errorf("embedded group data was nil for app group '%s'", appGroup.Id)
	}
	groupJSON, err := json.Marshal(embeddedGroup)
	if err != nil {
		return nil, fmt.Errorf("error marshalling embedded group data for app group '%s': %w", appGroup.Id, err)
	}
	oktaGroup := &okta.Group{}
	err = json.Unmarshal(groupJSON, &oktaGroup)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling embedded group data for app group '%s': %w", appGroup.Id, err)
	}

	appGroupProfile, ok := appGroup.Profile.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("error converting app group profile '%s'", appGroup.Id)
	}

	awsAppSettings, err := o.connector.getAWSApplicationConfig(ctx)
	if err != nil {
		return nil, err
	}
	samlRoles := make([]string, 0)
	accountId := awsAppSettings.IdentityProviderArnAccountID
	var roleName string
	matchesRolePattern := false

	if awsAppSettings.UseGroupMapping {
		accountId, roleName, matchesRolePattern, err = parseAccountIDAndRoleFromGroupName(ctx, awsAppSettings.RoleRegex, oktaGroup.Profile.Name)
		if err != nil {
			return nil, err
		}
		if matchesRolePattern {
			samlRoles = append(samlRoles, roleName)
		}
	} else {
		samlRoles, err = getSAMLRoles(appGroupProfile)
		if err != nil {
			return nil, err
		}
	}

	return &OktaAppGroupWrapper{
		oktaGroup: oktaGroup,
		samlRoles: samlRoles,
		accountID: accountId,
	}, nil
}

func (o *accountResourceType) getOktaAppGroupFromCacheOrFetch(ctx context.Context, groupId string) (*OktaAppGroupWrapper, error) {
	l := ctxzap.Extract(ctx)
	awsConfig, err := o.connector.getAWSApplicationConfig(ctx)
	if err != nil {
		return nil, err
	}
	appGroup, err := awsConfig.getAppGroupFromCache(ctx, groupId)
	if err != nil {
		return nil, err
	}
	if appGroup != nil {
		l.Debug("okta-aws-connector: found group in cache", zap.String("groupId", groupId))
		return appGroup, nil
	}
	notAnAppGroup, err := awsConfig.checkIfNotAppGroupFromCache(ctx, groupId)
	if err != nil {
		return nil, err
	}
	if notAnAppGroup {
		return nil, nil
	}
	oktaAppGroup, resp, err := o.connector.client.Application.GetApplicationGroupAssignment(
		ctx, o.connector.awsConfig.OktaAppId,
		groupId,
		query.NewQueryParams(query.WithExpand("group")))

	if err != nil {
		defer resp.Body.Close()
		errOkta, err := getError(resp)
		if err != nil {
			return nil, err
		}
		if errOkta.ErrorCode != ResourceNotFoundExceptionErrorCode {
			l.Warn("okta-aws-connector: ", zap.String("ErrorCode", errOkta.ErrorCode), zap.String("ErrorSummary", errOkta.ErrorSummary))
			return nil, fmt.Errorf("okta-connector: %v", errOkta)
		}
		awsConfig.notAppGroupCache.Store(groupId, true)
		return nil, nil
	}

	appGroup, err = o.oktaAppGroup(ctx, oktaAppGroup)
	if err != nil {
		return nil, err
	}
	awsConfig.appGroupCache.Store(ctx, appGroup)

	return appGroup, nil
}
