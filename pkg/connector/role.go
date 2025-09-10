package connector

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/okta/okta-sdk-golang/v2/okta"

	oktav5 "github.com/conductorone/okta-sdk-golang/v5/okta"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	sdkEntitlement "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	sdkGrant "github.com/conductorone/baton-sdk/pkg/types/grant"
	sdkResource "github.com/conductorone/baton-sdk/pkg/types/resource"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

var errMissingRolePermissions = errors.New("okta-connectorv2: missing role permissions")
var alreadyAssignedRole = "E0000090"

// Roles that can only be assigned at the org-wide scope.
// For full list of roles see: https://developer.okta.com/docs/reference/api/roles/#role-types
var standardRoleTypes = []*oktav5.Role{
	{
		Type:  oktav5.PtrString("API_ACCESS_MANAGEMENT_ADMIN"),
		Label: oktav5.PtrString("API Access Management Administrator"),
	},
	{
		Type:  oktav5.PtrString("MOBILE_ADMIN"),
		Label: oktav5.PtrString("Mobile Administrator"),
	},
	{
		Type:  oktav5.PtrString("ORG_ADMIN"),
		Label: oktav5.PtrString("Organizational Administrator"),
	},
	{
		Type:  oktav5.PtrString("READ_ONLY_ADMIN"),
		Label: oktav5.PtrString("Read-Only Administrator"),
	},
	{
		Type:  oktav5.PtrString("REPORT_ADMIN"),
		Label: oktav5.PtrString("Report Administrator"),
	},
	{
		Type:  oktav5.PtrString("SUPER_ADMIN"),
		Label: oktav5.PtrString("Super Administrator"),
	},
	// The type name is strange, but it is what Okta uses for the Group Administrator standard role
	{
		Type:  oktav5.PtrString("USER_ADMIN"),
		Label: oktav5.PtrString("Group Administrator"),
	},
	{
		Type:  oktav5.PtrString("HELP_DESK_ADMIN"),
		Label: oktav5.PtrString("Help Desk Administrator"),
	},
	{
		Type:  oktav5.PtrString("APP_ADMIN"),
		Label: oktav5.PtrString("Application Administrator"),
	},
	{
		Type:  oktav5.PtrString("GROUP_MEMBERSHIP_ADMIN"),
		Label: oktav5.PtrString("Group Membership Administrator"),
	},
}

type roleResourceType struct {
	resourceType *v2.ResourceType
	client       *oktav5.APIClient
	connector    *Okta
}

type RoleAssignment struct {
	Id    string      `json:"id,omitempty"`
	Orn   string      `json:"orn,omitempty"`
	Links interface{} `json:"_links,omitempty"`
}

type RoleAssignments struct {
	RoleAssignments []*RoleAssignment `json:"value,omitempty"`
	Links           interface{}       `json:"_links,omitempty"`
}

const (
	apiPathListAdministrators = "/api/internal/administrators"
	ContentType               = "application/json"
	NF                        = -1
)

func (o *roleResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *roleResourceType) List(
	ctx context.Context,
	resourceID *v2.ResourceId,
	token *pagination.Token,
) ([]*v2.Resource, string, annotations.Annotations, error) {
	var (
		nextPageToken string
		rv            []*v2.Resource
	)
	bag, _, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeRole.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	rv, err = o.listSystemRoles(ctx, resourceID, token)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list system roles: %w", err)
	}

	err = bag.Next(nextPageToken)
	if err != nil {
		return nil, "", nil, err
	}

	nextPageToken, err = bag.Marshal()
	if err != nil {
		return nil, "", nil, err
	}

	return rv, nextPageToken, nil, nil
}

func (o *roleResourceType) Entitlements(
	ctx context.Context,
	resource *v2.Resource,
	token *pagination.Token,
) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var (
		rv   []*v2.Entitlement
		role *oktav5.Role
	)
	role = standardRoleFromType(resource.Id.GetResource())
	if role == nil {
		role = &oktav5.Role{
			Label: oktav5.PtrString(resource.DisplayName),
			Type:  oktav5.PtrString(resource.Id.Resource),
		}
	}

	en := sdkEntitlement.NewAssignmentEntitlement(resource, "assigned",
		sdkEntitlement.WithDisplayName(fmt.Sprintf("%s Role Member", nullableStr(role.Label))),
		sdkEntitlement.WithDescription(fmt.Sprintf("Has the %s role in Okta", nullableStr(role.Label))),
		sdkEntitlement.WithAnnotation(&v2.V1Identifier{
			Id: V1MembershipEntitlementID(nullableStr(role.Type)),
		}),
		sdkEntitlement.WithGrantableTo(resourceTypeUser, resourceTypeGroup),
	)
	rv = append(rv, en)

	return rv, "", nil, nil
}

func (o *roleResourceType) Grants(
	ctx context.Context,
	resource *v2.Resource,
	token *pagination.Token,
) ([]*v2.Grant, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	var rv []*v2.Grant

	bag, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeRole.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	v5, err := paginateV5(ctx, o.connector.clientV5, page, func(ctx2 context.Context) (*oktav5.RoleAssignedUsers, *oktav5.APIResponse, error) {
		return listAllUsersWithRoleAssignmentsV5(ctx, o.connector.clientV5)
	})
	if err != nil {
		return nil, "", nil, err
	}

	usersWithRoleAssignments := v5.value
	nextPage, annos := v5.nextPage, v5.annos

	err = bag.Next(nextPage)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
	}

	for _, user := range usersWithRoleAssignments.Value {
		if user.Id == nil {
			l.Warn("okta-connectorv2: user has no ID, skipping")
			continue
		}

		userId := *user.Id

		// check if the user should be included after filtering by email domains
		shouldInclude, ok := o.connector.shouldIncludeUserFromCache(ctx, userId)
		if !ok {
			user, _, err := o.connector.client.User.GetUser(ctx, userId)
			if err != nil {
				return nil, "", nil, err
			}
			shouldInclude = o.connector.shouldIncludeUserAndSetCache(ctx, user)
		}
		if !shouldInclude {
			continue
		}

		userRoles, err := o.getUserRolesFromCache(ctx, userId)
		if err != nil {
			return nil, "", nil, err
		}

		if userRoles == nil {
			userRoles = mapset.NewSet[string]()
			roles, _, err := listAssignedRolesForUserV5(ctx, o.connector.clientV5, userId)
			if err != nil {
				return nil, "", nil, err
			}
			for _, role := range roles {
				if role.Status == nil || role.AssignmentType == nil || role.Type == nil {
					continue
				}

				if *role.Status == roleStatusInactive {
					continue
				}

				if *role.AssignmentType != "USER" {
					continue
				}

				if !o.connector.syncCustomRoles && *role.Type == roleTypeCustom {
					continue
				}

				if *role.Type == roleTypeCustom {
					roleId, ok := role.AdditionalProperties["role"].(string)
					if !ok {
						l.Warn("okta-connectorv2: custom role has no role in additional properties, skipping")
						continue
					}

					userRoles.Add(roleId)
				} else {
					userRoles.Add(*role.Type)
				}
			}
			o.connector.userRoleCache.Store(userId, userRoles)
		}

		if userRoles.ContainsOne(resource.Id.GetResource()) {
			rv = append(rv, roleGrant(userId, resource))
		}
	}

	pageToken, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, err
	}

	return rv, pageToken, annos, nil
}

func userHasRoleAccess(administratorRoleFlags *administratorRoleFlags, resource *v2.Resource) bool {
	roleName := strings.ReplaceAll(strings.ToLower(resource.Id.GetResource()), "_", "")
	for _, role := range administratorRoleFlags.RolesFromIndividualAssignments {
		if strings.ToLower(role) == roleName {
			return true
		}
	}

	for _, role := range administratorRoleFlags.RolesFromGroup {
		if strings.ToLower(role) == roleName {
			return true
		}
	}

	return false
}

func (o *roleResourceType) listSystemRoles(
	ctx context.Context,
	_ *v2.ResourceId,
	_ *pagination.Token,
) ([]*v2.Resource, error) {
	rv := make([]*v2.Resource, 0, len(standardRoleTypes))
	for _, role := range standardRoleTypes {
		resource, err := roleResourceV5(ctx, role)
		if err != nil {
			return nil, fmt.Errorf("okta-connectorv2: failed to create role resource: %w", err)
		}

		rv = append(rv, resource)
	}

	return rv, nil
}

func listAllUsersWithRoleAssignmentsV5(ctx context.Context, client *oktav5.APIClient) (*oktav5.RoleAssignedUsers, *oktav5.APIResponse, error) {
	execute, resp, err := client.RoleAssignmentAPI.ListUsersWithRoleAssignments(ctx).
		Limit(defaultLimit).
		Execute()
	if err != nil {
		return nil, nil, err
	}

	return execute, resp, nil
}

func getOrgSettings(ctx context.Context, client *oktav5.APIClient, token *pagination.Token) (*oktav5.OrgSetting, *responseContextV5, error) {
	orgSettings, resp, err := client.OrgSettingAPI.GetOrgSettings(ctx).Execute()
	if err != nil {
		return nil, nil, handleOktaResponseErrorV5(resp, err)
	}

	respCtx, err := responseToContextV5(token, resp)
	if err != nil {
		return nil, nil, err
	}

	return orgSettings, respCtx, nil
}

type administratorRoleFlags struct {
	UserId                           string   `json:"userId"`
	SuperAdmin                       bool     `json:"superAdmin"`
	OrgAdmin                         bool     `json:"orgAdmin"`
	ReadOnlyAdmin                    bool     `json:"readOnlyAdmin"`
	MobileAdmin                      bool     `json:"mobileAdmin"`
	AppAdmin                         bool     `json:"appAdmin"`
	HelpDeskAdmin                    bool     `json:"helpDeskAdmin"`
	GroupMembershipAdmin             bool     `json:"groupMembershipAdmin"`
	ApiAccessManagementAdmin         bool     `json:"apiAccessManagementAdmin"`
	UserAdmin                        bool     `json:"userAdmin"`
	ReportAdmin                      bool     `json:"reportAdmin"`
	ForAllApps                       bool     `json:"forAllApps"`
	ForAllUserAdminGroups            bool     `json:"forAllUserAdminGroups"`
	ForAllHelpDeskAdminGroups        bool     `json:"forAllHelpDeskAdminGroups"`
	ForAllGroupMembershipAdminGroups bool     `json:"forAllGroupMembershipAdminGroups"`
	RolesFromIndividualAssignments   []string `json:"rolesFromIndividualAssignments"`
	RolesFromGroup                   []string `json:"rolesFromGroup"`
}

func listAdministratorRoleFlags(
	ctx context.Context,
	client *okta.Client,
	token *pagination.Token,
	encodedQueryParams string,
) ([]*administratorRoleFlags, *responseContext, error) {
	// TODO(golds): Needs oktav5 export do and request to change this
	reqUrl, err := url.Parse(apiPathListAdministrators)
	if err != nil {
		return nil, nil, err
	}

	if encodedQueryParams != "" {
		reqUrl.RawQuery = encodedQueryParams
	}

	rq := client.CloneRequestExecutor()
	req, err := rq.
		WithAccept(ContentType).
		WithContentType(ContentType).
		NewRequest(http.MethodGet, reqUrl.String(), nil)
	if err != nil {
		return nil, nil, err
	}

	var adminFlags []*administratorRoleFlags
	resp, err := rq.Do(ctx, req, &adminFlags)
	if err != nil {
		// If we don't have access to the role endpoint, we should just return nil
		if resp.StatusCode == http.StatusForbidden {
			return nil, nil, errMissingRolePermissions
		}

		return nil, nil, handleOktaResponseError(resp, err)
	}

	respCtx, err := responseToContext(token, resp)
	if err != nil {
		return nil, nil, err
	}

	return adminFlags, respCtx, nil
}

func standardRoleFromType(roleType string) *oktav5.Role {
	for _, standardRoleType := range standardRoleTypes {
		if nullableStr(standardRoleType.Type) == roleType {
			return standardRoleType
		}
	}

	return nil
}

func StandardRoleTypeFromLabel(label string) *oktav5.Role {
	for _, role := range standardRoleTypes {
		if nullableStr(role.Label) == label {
			return role
		}
	}
	return nil
}

func roleResourceV5(ctx context.Context, role *oktav5.Role) (*v2.Resource, error) {
	var objectID = nullableStr(role.Type)
	if objectID == "" && nullableStr(role.Id) != "" {
		objectID = *role.Id
	}

	profile := map[string]interface{}{
		"id":    nullableStr(role.Id),
		"label": nullableStr(role.Label),
		"type":  nullableStr(role.Type),
	}

	return sdkResource.NewRoleResource(
		nullableStr(role.Label),
		resourceTypeRole,
		objectID,
		[]sdkResource.RoleTraitOption{sdkResource.WithRoleProfile(profile)},
		sdkResource.WithAnnotation(&v2.V1Identifier{
			Id: fmtResourceIdV1(objectID),
		}),
	)
}

func roleGrant(userID string, resource *v2.Resource) *v2.Grant {
	ur := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeUser.Id, Resource: userID}}

	return sdkGrant.NewGrant(resource, "assigned", ur,
		sdkGrant.WithAnnotation(&v2.V1Identifier{
			Id: fmtGrantIdV1(V1MembershipEntitlementID(resource.Id.Resource), userID),
		}),
	)
}

func roleGroupGrant(groupID string, resource *v2.Resource, shouldExpand bool) *v2.Grant {
	gr := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeGroup.Id, Resource: groupID}}

	grantOpts := []sdkGrant.GrantOption{
		sdkGrant.WithAnnotation(&v2.V1Identifier{
			Id: fmtGrantIdV1(V1MembershipEntitlementID(resource.Id.Resource), groupID),
		}),
	}

	if shouldExpand {
		grantOpts = append(grantOpts, sdkGrant.WithAnnotation(&v2.GrantExpandable{
			EntitlementIds: []string{fmt.Sprintf("group:%s:member", groupID)},
			Shallow:        true,
		}))
	}

	return sdkGrant.NewGrant(resource, "assigned", gr, grantOpts...)
}

func (g *roleResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	if principal.Id.ResourceType != resourceTypeUser.Id {
		l.Warn(
			"okta-connector: only users or groups can be granted role membership",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("okta-connector: only users or groups can be granted repo membership")
	}

	roleId := entitlement.Resource.Id.Resource
	switch principal.Id.ResourceType {
	case resourceTypeUser.Id:
		userId := principal.Id.Resource

		createdRole, response, err := g.client.RoleAssignmentAPI.AssignRoleToUser(ctx, userId).
			AssignRoleRequest(oktav5.AssignRoleRequest{
				Type: oktav5.PtrString(roleId),
			}).
			Execute()
		if err != nil {
			defer response.Body.Close()
			errOkta, err := getErrorV5(response)
			if err != nil {
				return nil, err
			}

			if errOkta.ErrorCode == nil {
				l.Warn("okta-connector: nil error code from okta v5 client")
				return nil, fmt.Errorf("okta-connector: nil error code from okta v5 client: %v", errOkta)
			}

			if *errOkta.ErrorCode == alreadyAssignedRole {
				l.Warn(
					"okta-connector: The role specified is already assigned to the user",
					zap.String("principal_id", principal.Id.String()),
					zap.String("principal_type", principal.Id.ResourceType),
					zap.String("ErrorCode", *errOkta.ErrorCode),
					zap.String("ErrorSummary", *errOkta.ErrorSummary),
				)
			}

			return nil, fmt.Errorf("okta-connector: %v", errOkta)
		}

		l.Warn("Role Membership has been created.",
			zap.String("ID", nullableStr(createdRole.Id)),
			zap.String("Description", nullableStr(createdRole.Description)),
			zap.Time("CreatedAt", *createdRole.Created),
			zap.String("Label", nullableStr(createdRole.Label)),
			zap.String("Status", nullableStr(createdRole.Status)),
			zap.String("Type", nullableStr(createdRole.Type)),
		)
	case resourceTypeGroup.Id:
		groupId := principal.Id.Resource
		createdRole, response, err := g.client.RoleAssignmentAPI.AssignRoleToGroup(ctx, groupId).
			AssignRoleRequest(oktav5.AssignRoleRequest{
				Type: oktav5.PtrString(roleId),
			}).
			Execute()
		if err != nil {
			defer response.Body.Close()
			errOkta, err := getErrorV5(response)
			if err != nil {
				return nil, err
			}

			if errOkta.ErrorCode == nil {
				l.Warn("okta-connector: nil error code from okta v5 client")
				return nil, fmt.Errorf("okta-connector: nil error code from okta v5 client: %v", errOkta)
			}

			if *errOkta.ErrorCode == alreadyAssignedRole {
				l.Warn(
					"okta-connector: The role specified is already assigned to the group",
					zap.String("principal_id", principal.Id.String()),
					zap.String("principal_type", principal.Id.ResourceType),
					zap.String("ErrorCode", *errOkta.ErrorCode),
					zap.String("ErrorSummary", nullableStr(errOkta.ErrorSummary)),
				)
			}

			return nil, fmt.Errorf("okta-connector: %v", errOkta)
		}

		l.Warn("Role Membership has been created.",
			zap.String("ID", nullableStr(createdRole.Id)),
			zap.String("Description", nullableStr(createdRole.Description)),
			zap.Time("CreatedAt", *createdRole.Created),
			zap.String("Label", nullableStr(createdRole.Label)),
			zap.String("Status", nullableStr(createdRole.Status)),
			zap.String("Type", nullableStr(createdRole.Type)),
		)
	default:
		return nil, fmt.Errorf("okta-connector: invalid grant resource type: %s", principal.Id.ResourceType)
	}

	return nil, nil
}

func (g *roleResourceType) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	entitlement := grant.Entitlement
	principal := grant.Principal
	roleId := ""
	if principal.Id.ResourceType != resourceTypeUser.Id {
		l.Warn(
			"okta-connector: only users or groups can have role membership revoked",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("okta-connector:only users or groups can have role membership revoked")
	}

	roleType := entitlement.Resource.Id.Resource
	switch principal.Id.ResourceType {
	case resourceTypeUser.Id:
		userId := principal.Id.Resource
		roles, response, err := g.client.RoleAssignmentAPI.ListAssignedRolesForUser(ctx, userId).Execute()
		if err != nil {
			return nil, fmt.Errorf("okta-connector: failed to get roles: %s %s", err.Error(), response.Body)
		}

		rolePos := slices.IndexFunc(roles, func(r oktav5.Role) bool {
			if r.Id == nil || r.Type == nil || r.Status == nil {
				return false
			}

			return *r.Type == roleType && *r.Status == userStatusActive
		})
		if rolePos == NF {
			l.Warn(
				"okta-connector: user does not have role membership",
				zap.String("principal_id", principal.Id.String()),
				zap.String("principal_type", principal.Id.ResourceType),
				zap.String("role_type", entitlement.Resource.Id.Resource),
			)
			return annotations.New(&v2.GrantAlreadyRevoked{}), nil
		}

		roleId = *roles[rolePos].Id
		response, err = g.client.RoleAssignmentAPI.UnassignRoleFromUser(ctx, userId, roleId).Execute()
		if err != nil {
			return nil, fmt.Errorf("okta-connector: failed to remove role: %s %s", err.Error(), response.Body)
		}

		if response.StatusCode == http.StatusNoContent {
			l.Warn("Membership has been revoked",
				zap.String("Status", response.Status),
			)
		}
	case resourceTypeGroup.Id:
		groupId := principal.Id.Resource
		roles, response, err := g.client.RoleAssignmentAPI.ListGroupAssignedRoles(ctx, groupId).Execute()
		if err != nil {
			return nil, fmt.Errorf("okta-connector: failed to get roles: %s %s", err.Error(), response.Body)
		}

		rolePos := slices.IndexFunc(roles, func(r oktav5.Role) bool {
			if r.Type == nil || r.Status == nil {
				return false
			}

			return *r.Type == roleType && *r.Status == userStatusActive
		})
		if rolePos == NF {
			l.Warn(
				"okta-connector: group does not have role membership",
				zap.String("principal_id", principal.Id.String()),
				zap.String("principal_type", principal.Id.ResourceType),
				zap.String("role_type", entitlement.Resource.Id.Resource),
			)
			return annotations.New(&v2.GrantAlreadyRevoked{}), nil
		}

		// TODO(golds): needs to validate system role
		roleId = *roles[rolePos].Id
		response, err = g.client.RoleAssignmentAPI.UnassignRoleFromGroup(ctx, groupId, roleId).Execute()
		if err != nil {
			return nil, fmt.Errorf("okta-connector: failed to remove role: %s %s", err.Error(), response.Body)
		}

		if response.StatusCode == http.StatusNoContent {
			l.Warn("Membership has been revoked",
				zap.String("Status", response.Status),
			)
		}
	default:
		return nil, fmt.Errorf("okta-connector: invalid grant resource type: %s", principal.Id.ResourceType)
	}

	return nil, nil
}

func (o *roleResourceType) getUserRolesFromCache(ctx context.Context, userId string) (mapset.Set[string], error) {
	appUserRoleCacheVal, ok := o.connector.userRoleCache.Load(userId)
	if !ok {
		return nil, nil
	}
	userRoles, ok := appUserRoleCacheVal.(mapset.Set[string])
	if !ok {
		return nil, fmt.Errorf("error converting user '%s' roles map from cache", userId)
	}
	return userRoles, nil
}

func (o *roleResourceType) Get(ctx context.Context, resourceId *v2.ResourceId, parentResourceId *v2.ResourceId) (*v2.Resource, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	l.Debug("getting role", zap.String("role_id", resourceId.Resource))

	for _, role := range standardRoleTypes {
		if nullableStr(role.Type) == resourceId.Resource {
			resource, err := roleResourceV5(ctx, role)
			if err != nil {
				return nil, nil, err
			}
			return resource, nil, nil
		}
	}

	return nil, nil, nil
}

func roleBuilder(client *oktav5.APIClient, connector *Okta) *roleResourceType {
	return &roleResourceType{
		resourceType: resourceTypeRole,
		client:       client,
		connector:    connector,
	}
}
