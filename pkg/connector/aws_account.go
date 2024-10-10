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
	sdkGrant "github.com/conductorone/baton-sdk/pkg/types/grant"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"

	sdkEntitlement "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	resource2 "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/okta/okta-sdk-golang/v2/okta"
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
	domain       string
	apiToken     string
	client       *okta.Client
	awsConfig    *awsConfig
}

func (o *accountResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func accountBuilder(domain string, apiToken string, client *okta.Client, awsConfig *awsConfig) *accountResourceType {
	return &accountResourceType{
		resourceType: resourceTypeAccount,
		domain:       domain,
		apiToken:     apiToken,
		client:       client,
		awsConfig:    awsConfig,
	}
}

func (o *accountResourceType) List(
	ctx context.Context,
	resourceID *v2.ResourceId,
	token *pagination.Token,
) ([]*v2.Resource, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	l.Info("******* (o *accountResourceType) List",
		zap.Any("resourceID", resourceID),
		zap.Any("token", token),
		zap.Any("o.awsConfig.UseGroupMapping", o.awsConfig.UseGroupMapping))

	b := &pagination.Bag{}
	err := b.Unmarshal(token.Token)
	if err != nil {
		return nil, "", nil, err
	}

	if b.Current() == nil {
		b.Push(pagination.PageState{
			ResourceTypeID: resourceTypeGroup.Id,
		})
		page := b.PageToken()
		mar, err := b.Marshal()
		if err != nil {
			return nil, "", nil, err
		}

		l.Info("******* (o *accountResourceType) List pagination token nil:",
			zap.Any("page", page), zap.Any("mar", mar))

		return nil, mar, nil, nil
	} else {
		l.Info("******* (o *accountResourceType) List pagination token nil:",
			zap.Any("token", token))
	}

	if !o.awsConfig.UseGroupMapping {
		// TODO(lauren) move to new connector
		l.Info("************ (o *accountResourceType) List",
			zap.Any("identityProviderArnRegex", o.awsConfig.IdentityProviderArnRegex))

		re, err := regexp.Compile(strings.ToLower(o.awsConfig.IdentityProviderArnRegex))
		if err != nil {
			log.Fatal(err)
		}
		match := re.FindStringSubmatch(strings.ToLower(o.awsConfig.IdentityProviderArn))

		l.Info("******* MATCH", zap.Any("match", match))
		// TODO(lauren) check if empty
		// First element is full string
		accountId := match[1]

		// TODO(lauren) what szhould name be?
		resource, err := resource2.NewResource(accountId, o.resourceType, accountId)
		if err != nil {
			return nil, "", nil, err
		}
		return []*v2.Resource{resource}, "", nil, nil

	} else {
		resources := make([]*v2.Resource, 0)
		// TODO(lauren) check map is not nil
		// TODO(lauren) how to paginate?

		o.awsConfig.accountRoleCache.Range(func(key, value interface{}) bool {
			l.Info("************ (o *accountResourceType) List MAPPING",
				zap.Any("makeaccountId", key))
			accountId, ok := key.(string) // Type assertion to convert interface{} to string
			if ok {
				resource, err := resource2.NewResource(accountId, o.resourceType, accountId)
				//resource, err := resource2.NewResource(accountId, o.resourceType, accountId, resource2.WithParentResourceID(resourceID))
				// TODO(lauren) log
				if err != nil {
					// TODO(lauren) should we continu
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
	var rv []*v2.Entitlement
	if !o.awsConfig.UseGroupMapping {
		awsSamlRoles, _, err := o.listAWSSamlRoles(ctx)
		if err != nil {
			return nil, "", nil, err
		}
		for _, role := range awsSamlRoles.SamlIamRole {
			rv = append(rv, samlRoleEntitlement(resource, role))
		}
	} else {
		accountRoleCachedSet, ok := o.awsConfig.accountRoleCache.Load(resource.Id.GetResource())
		if !ok {
			// Should this error or just return empty?
			return rv, "", nil, nil
		}
		accountRoleSet, ok := accountRoleCachedSet.(mapset.Set[string])
		for role := range accountRoleSet.Iterator().C {
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

	processedGroupGrants := o.awsConfig.processedGroupGrants.Load()
	l := ctxzap.Extract(ctx)
	l.Info("******************** (o *accountResourceType) Grants",
		zap.Any("rersource", resource),
		zap.Any("token", token),
		zap.Any("proccessedGrants", processedGroupGrants), zap.Any("token", token))

	b := &pagination.Bag{}
	err := b.Unmarshal(token.Token)
	if err != nil {
		return nil, "", nil, err
	}

	if !processedGroupGrants {
		l.Info("********* DID NOT PROCESS GRANTS")
		return nil, "", nil, nil

		/*if b.Current() == nil {
			b.Push(pagination.PageState{
				ResourceTypeID: resourceTypeAccount.Id,
			})
		}*/
		/*b.Push(pagination.PageState{
			ResourceTypeID: resourceTypeAccount.Id,
		})*/
		/*b.Pop()
		b.Push(pagination.PageState{
			ResourceTypeID: resourceTypeGroup.Id,
		})

		page := b.PageToken()
		mar, err := b.Marshal()
		if err != nil {
			return nil, "", nil, err
		}

		l.Info("********* DID NOT PROCESS GRANTS", zap.Any("page", page), zap.Any("mar", mar))

		return nil, mar, nil, nil*/
	} else {
		l.Info("********* PROCESS$ED GRANTS")
	}

	/*if b.Current() == nil {
		b.Push(pagination.PageState{
			ResourceTypeID: resourceTypeGroup.Id,
		})

		page := b.PageToken()
		mar, err := b.Marshal()
		if err != nil {
			return nil, "", nil, err
		}

		l.Info("********* GRANTS PAGE NU:L:", zap.Any("page", page), zap.Any("mar", mar))
		return nil, mar, nil, nil
	} else {
		fmt.Println("******* accountResourceType ******** NOT NULL")
	}*/

	var rv []*v2.Grant

	// TODO(lauren) ugh is this the right resource tpye??
	bag, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeUser.Id})
	if err != nil {
		l.Info("******************** errror parsing token")
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	l.Info("******************** (o *accountResourceType) Grants", zap.Any("token", token),
		zap.Any("page", page))

	useMapping := o.awsConfig.UseGroupMapping
	//useMapping = false
	if useMapping {
		accountId := resource.Id.GetResource()
		cachedAccountGrants, ok := o.awsConfig.accountGrantCache.Load(accountId)
		if !ok {
			l.Info("error getting account cached grants", zap.Any("accountId", accountId))
			return nil, "", nil, fmt.Errorf("error getting accounts grant cache '%s'", accountId)
		}
		l.Info("********* cachedAccountGrants", zap.Any("accountGrants", cachedAccountGrants))
		accountGrants, ok := cachedAccountGrants.(*[]*GroupMappingGrant)

		if !ok {
			l.Info("error casting account grants", zap.Any("accountId", accountId))
			return nil, "", nil, fmt.Errorf("error casting account grants '%s'", accountId)
		}
		l.Info("********* o.awsConfig.UseGroupMapping", zap.Any("accountGrants", accountGrants))
		for _, groupGrant := range *accountGrants {
			rv = append(rv, accountGrant(resource, groupGrant.Role, groupGrant.OktaUserID))
		}
		// TODO(lauren)
	} else {

		qp := queryParams(token.Size, page)
		appUsers, respContext, err := listApplicationUsers(ctx, o.client, o.awsConfig.OktaAppId, token, qp)
		// TODO(lauren) log error
		for _, appUser := range appUsers {

			appUserSAMLRolesMap := mapset.NewSet[string]()
			//var appUserSAMLRolesMap mapset.Set[string]

			if appUser.Scope == "USER" {
				// TODO(lauren0 check nil
				// TODO(lauren) check ok?
				appUserProfile := appUser.Profile.(map[string]interface{})
				appUserSAMLRoles, err := getSAMLRoles(appUserProfile)
				if err != nil {
					return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to get saml roles for user '%s': %w", appUser.Id, err)
				}
				appUserSAMLRolesMap.Append(appUserSAMLRoles...)
				l.Info("USER SCOPE", zap.Any("appUserSAMLRolesMap", appUserSAMLRolesMap))
			}

			if appUser.Scope == "GROUP" || o.awsConfig.JoinAllRoles {
				appUserGroupCache, ok := o.awsConfig.appUserToGroup.Load(appUser.Id)
				if !ok {
					// TODO(lauren) load ap
					l.Info("***** BREAKING")
					break
					// TODO(lauren) dont error in case not in groups
					//return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to get groups for user '%s'", appUser.Id)
				}
				appUserGroupsSet := appUserGroupCache.(mapset.Set[string])
				for group := range appUserGroupsSet.Iterator().C {
					// TODO(lauren) this hould be empty roles
					groupRoleCacheVal, ok := o.awsConfig.groupToSamlRoleCache.Load(group)
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
				// TODO(lauren) have app user to group map

			}

			// TODO(lauren) use ToSlice instead?
			for samlRole := range appUserSAMLRolesMap.Iterator().C {
				rv = append(rv, accountGrant(resource, samlRole, appUser.Id))
			}

			// If the user scope is "GROUP", this means the user does not have a direct assignment
			// We want to get the union of the group's samlRoles that the user is assigned to
			// If joinAllRolesEnabled, we handle this in listApplicationGroups, so we only do this when joinAllRoles is not enabled

		}
		/// TODO(lauren) need to cache

		nextPage, annos, err := parseResp(respContext.OktaResponse)
		if err != nil {
			return nil, "nil", nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
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
	return rv, "", nil, nil
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
	apiUrl := fmt.Sprintf("/api/v1/internal/apps/%s/types", o.awsConfig.OktaAppId)

	rq := o.client.CloneRequestExecutor()

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
