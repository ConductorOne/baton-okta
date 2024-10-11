package connector

import (
	"context"
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
)

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
		resources := make([]*v2.Resource, 0)
		// TODO(lauren) check map is not empty/nil
		// If it is, list groups and cache
		awsConfig.accountRoleCache.Range(func(key, value interface{}) bool {
			accountId, ok := key.(string)
			if ok {
				resource, err := resource2.NewResource(accountId, o.resourceType, accountId)
				if err != nil {
					// TODO(lauren) should we continue
					return false
				}
				resources = append(resources, resource)
			}
			return true // continue iteration
		})
		return resources, "", nil, nil
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
		for role := range awsConfig.appSamlRoles.Iterator().C {
			rv = append(rv, samlRoleEntitlement(resource, role))
		}
	} else {
		accountRoleCachedSet, ok := awsConfig.accountRoleCache.Load(resource.Id.GetResource())
		if !ok {
			// Should this error or just return empty?
			return rv, "", nil, nil
		}
		accountRoleSet, ok := accountRoleCachedSet.(mapset.Set[string])
		for role := range accountRoleSet.Iterator().C {
			if !awsConfig.appSamlRoles.ContainsOne(role) {
				// TODO(lauren) error or just ignore invalid role?
				continue
			}
			rv = append(rv, samlRoleEntitlement(resource, role))
		}
	}

	return rv, "", nil, nil
}

func samlRoleEntitlement(resource *v2.Resource, role string) *v2.Entitlement {
	return sdkEntitlement.NewAssignmentEntitlement(resource, role,
		sdkEntitlement.WithDisplayName(fmt.Sprintf("%s Role Member", role)),
		sdkEntitlement.WithDescription(fmt.Sprintf("Has the %s role in AWS Okta app", role)),
		/*sdkEntitlement.WithAnnotation(&v2.V1Identifier{
			Id: V1MembershipEntitlementID(role.Type),
		}),*/
		sdkEntitlement.WithGrantableTo(resourceTypeUser),
	)
}

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
	bag, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeUser.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	useMapping := awsConfig.UseGroupMapping

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
		if appUser.Scope == "GROUP" || awsConfig.JoinAllRoles || useMapping {
			appUserGroupCache, ok := awsConfig.appUserToGroup.Load(appUser.Id)
			var appUserGroupsSet mapset.Set[string]
			if !ok {
				// TODO(lauren) This endpoint doesn't paginate but
				// I think we should check the resp code rate limit?
				userGroups, _, err := listUsersGroupsClient(ctx, o.connector.client, appUser.Id)
				if err != nil {
					return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to groups for user '%s': %w", appUser.Id, err)
				}

				groupIDSFilter := mapset.NewSet[string]()
				awsConfig.groupToSamlRoleCache.Range(func(key, value interface{}) bool {
					groupID, ok := key.(string)
					if ok {
						// TODO(lauren) return false or just continue?
						groupIDSFilter.Add(groupID)
					}
					return true
				})

				filteredUserGroups := mapset.NewSet[string]()
				for _, userGroup := range userGroups {
					if groupIDSFilter.ContainsOne(userGroup.Id) {
						filteredUserGroups.Add(userGroup.Id)
					}
				}

				awsConfig.appUserToGroup.Store(appUser.Id, filteredUserGroups)
				appUserGroupsSet = filteredUserGroups
			} else {
				appUserGroupsSet = appUserGroupCache.(mapset.Set[string])
			}

			for group := range appUserGroupsSet.Iterator().C {
				groupRoleCacheVal, ok := awsConfig.groupToSamlRoleCache.Load(group)
				if !ok {
					return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to get roles for group '%s'", group)
				}
				groupRoleSet, ok := groupRoleCacheVal.(mapset.Set[string])
				if !ok {
					return nil, "", nil, fmt.Errorf("error converting group '%s' role set", group)
				}
				// TODO(lauren) is this safe?
				appUserSAMLRolesMap = appUserSAMLRolesMap.Union(groupRoleSet)
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
}

func accountGrant(resource *v2.Resource, samlRole string, oktaUserId string) *v2.Grant {
	ur := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeUser.Id, Resource: oktaUserId}}

	return sdkGrant.NewGrant(resource, samlRole, ur, sdkGrant.WithAnnotation(&v2.V1Identifier{
		Id: fmtGrantIdV1(V1MembershipEntitlementID(resource.Id.Resource), oktaUserId),
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

func getSAMLRolesMap(profile map[string]interface{}) (mapset.Set[string], error) {
	ret := mapset.NewSet[string]()
	samlRolesField := profile["samlRoles"]
	if samlRolesField == nil {
		return ret, nil
	}

	samlRoles, ok := samlRolesField.([]interface{})
	if !ok {
		return nil, errors.New("unexpected type in profile[\"samlRoles\"")
	}

	for _, r := range samlRoles {
		role, ok := r.(string)
		if !ok {
			return nil, errors.New("role was not string")
		}
		ret.Add(role)
	}
	return ret, nil
}
