package connector

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	sdkEntitlement "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	sdkGrant "github.com/conductorone/baton-sdk/pkg/types/grant"
	sdkResource "github.com/conductorone/baton-sdk/pkg/types/resource"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"go.uber.org/zap"
)

var errMissingRolePermissions = errors.New("okta-connectorv2: missing role permissions")
var alreadyAssignedRole = "E0000090"

// Roles that can only be assigned at the org-wide scope.
// For full list of roles see: https://developer.okta.com/docs/reference/api/roles/#role-types
var standardRoleTypes = []*okta.Role{
	{Type: "API_ACCESS_MANAGEMENT_ADMIN", Label: "API Access Management Administrator"},
	{Type: "MOBILE_ADMIN", Label: "Mobile Administrator"},
	{Type: "ORG_ADMIN", Label: "Organizational Administrator"},
	{Type: "READ_ONLY_ADMIN", Label: "Read-Only Administrator"},
	{Type: "REPORT_ADMIN", Label: "Report Administrator"},
	{Type: "SUPER_ADMIN", Label: "Super Administrator"},
	// The type name is strange, but it is what Okta uses for the Group Administrator standard role
	{Type: "USER_ADMIN", Label: "Group Administrator"},
	{Type: "HELP_DESK_ADMIN", Label: "Help Desk Administrator"},
	{Type: "APP_ADMIN", Label: "Application Administrator"},
	{Type: "GROUP_MEMBERSHIP_ADMIN", Label: "Group Membership Administrator"},
}

type roleResourceType struct {
	resourceType *v2.ResourceType
	client       *okta.Client
	connector    *Okta
}

type CustomRoles struct {
	Roles []*okta.Role `json:"roles,omitempty"`
	Links interface{}  `json:"_links,omitempty"`
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
	apiPathListAdministrators              = "/api/internal/administrators"
	apiPathListIamCustomRoles              = "/api/v1/iam/roles"
	apiPathListAllUsersWithRoleAssignments = "/api/v1/iam/assignees/users"
	ContentType                            = "application/json"
	NF                                     = -1
)

func (o *roleResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *roleResourceType) List(
	ctx context.Context,
	resourceID *v2.ResourceId,
	attrs sdkResource.SyncOpAttrs,
) ([]*v2.Resource, *sdkResource.SyncOpResults, error) {
	token := &attrs.PageToken
	var (
		nextPageToken string
		rv            []*v2.Resource
	)
	bag, _, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeRole.Id})
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	rv, err = o.listSystemRoles(ctx, resourceID, token)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to list system roles: %w", err)
	}

	err = bag.Next(nextPageToken)
	if err != nil {
		return nil, nil, err
	}

	nextPageToken, err = bag.Marshal()
	if err != nil {
		return nil, nil, err
	}

	return rv, &sdkResource.SyncOpResults{NextPageToken: nextPageToken}, nil
}

func (o *roleResourceType) Entitlements(
	ctx context.Context,
	resource *v2.Resource,
	attrs sdkResource.SyncOpAttrs,
) ([]*v2.Entitlement, *sdkResource.SyncOpResults, error) {
	var (
		rv   []*v2.Entitlement
		role *okta.Role
	)
	role = standardRoleFromType(resource.Id.GetResource())
	if role == nil {
		role = &okta.Role{
			Label: resource.DisplayName,
			Type:  resource.Id.Resource,
		}
	}

	en := sdkEntitlement.NewAssignmentEntitlement(resource, "assigned",
		sdkEntitlement.WithDisplayName(fmt.Sprintf("%s Role Member", role.Label)),
		sdkEntitlement.WithDescription(fmt.Sprintf("Has the %s role in Okta", role.Label)),
		sdkEntitlement.WithAnnotation(&v2.V1Identifier{
			Id: V1MembershipEntitlementID(role.Type),
		}),
		sdkEntitlement.WithGrantableTo(resourceTypeUser, resourceTypeGroup),
	)
	rv = append(rv, en)

	return rv, nil, nil
}

func (o *roleResourceType) Grants(
	ctx context.Context,
	resource *v2.Resource,
	attrs sdkResource.SyncOpAttrs,
) ([]*v2.Grant, *sdkResource.SyncOpResults, error) {
	token := &attrs.PageToken
	var rv []*v2.Grant

	bag, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeRole.Id})
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	qp := queryParams(token.Size, page)

	usersWithRoleAssignments, respCtx, err := listAllUsersWithRoleAssignments(ctx, o.connector.client, token, qp)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to list all users with role assignments: %w", err)
	}

	nextPage, annos, err := parseResp(respCtx.OktaResponse)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
	}

	for _, user := range usersWithRoleAssignments {
		userId := user.Id

		// check if the user should be included after filtering by email domains
		shouldInclude, ok := o.connector.shouldIncludeUserFromCache(ctx, attrs.Session, userId)
		if !ok {
			user, _, err := o.connector.client.User.GetUser(ctx, userId)
			if err != nil {
				return nil, nil, err
			}
			shouldInclude = o.connector.shouldIncludeUserAndSetCache(ctx, attrs.Session, user)
		}
		if !shouldInclude {
			continue
		}

		userRoles, found, err := o.connector.getUserRolesFromCache(ctx, attrs.Session, userId)
		if err != nil {
			return nil, nil, err
		}

		if !found {
			userRoles = mapset.NewSet[string]()
			roles, _, err := listAssignedRolesForUser(ctx, o.connector.client, userId)
			if err != nil {
				return nil, nil, err
			}
			for _, role := range roles {
				if role.Status == roleStatusInactive {
					continue
				}

				if role.AssignmentType != "USER" {
					continue
				}

				if !o.connector.syncCustomRoles && role.Type == roleTypeCustom {
					continue
				}

				if role.Type == roleTypeCustom {
					userRoles.Add(role.Role)
				} else {
					userRoles.Add(role.Type)
				}
			}
			_ = o.connector.setUserRolesInCache(ctx, attrs.Session, userId, userRoles)
		}

		if userRoles.ContainsOne(resource.Id.GetResource()) {
			rv = append(rv, roleGrant(userId, resource))
		}
	}

	pageToken, err := bag.Marshal()
	if err != nil {
		return nil, nil, err
	}

	return rv, &sdkResource.SyncOpResults{NextPageToken: pageToken, Annotations: annos}, nil
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
		resource, err := roleResource(ctx, role, resourceTypeRole)
		if err != nil {
			return nil, fmt.Errorf("okta-connectorv2: failed to create role resource: %w", err)
		}

		rv = append(rv, resource)
	}

	return rv, nil
}

func listOktaIamCustomRoles(
	ctx context.Context,
	client *okta.Client,
	token *pagination.Token,
	qp *query.Params,
) ([]*okta.Role, *responseContext, error) {
	url := apiPathListIamCustomRoles
	if qp != nil {
		url += qp.String()
	}

	rq := client.CloneRequestExecutor()
	req, err := rq.
		WithAccept(ContentType).
		WithContentType(ContentType).
		NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}

	var role *CustomRoles
	resp, err := rq.Do(ctx, req, &role)
	if err != nil {
		return nil, nil, err
	}

	respCtx, err := responseToContext(token, resp)
	if err != nil {
		return nil, nil, err
	}

	return role.Roles, respCtx, nil
}

func listAllUsersWithRoleAssignments(
	ctx context.Context,
	client *okta.Client,
	token *pagination.Token,
	qp *query.Params,
) ([]*RoleAssignment, *responseContext, error) {
	url := apiPathListAllUsersWithRoleAssignments
	if qp != nil {
		url += qp.String()
	}

	rq := client.CloneRequestExecutor()
	req, err := rq.
		WithAccept(ContentType).
		WithContentType(ContentType).
		NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}

	var role *RoleAssignments
	resp, err := rq.Do(ctx, req, &role)
	if err != nil {
		return nil, nil, err
	}

	respCtx, err := responseToContext(token, resp)
	if err != nil {
		return nil, nil, err
	}

	return role.RoleAssignments, respCtx, nil
}

func getOrgSettings(ctx context.Context, client *okta.Client, token *pagination.Token) (*okta.OrgSetting, *responseContext, error) {
	orgSettings, resp, err := client.OrgSetting.GetOrgSettings(ctx)
	if err != nil {
		return nil, nil, handleOktaResponseError(resp, err)
	}

	respCtx, err := responseToContext(token, resp)
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

func standardRoleFromType(roleType string) *okta.Role {
	for _, standardRoleType := range standardRoleTypes {
		if standardRoleType.Type == roleType {
			return standardRoleType
		}
	}

	return nil
}

func StandardRoleTypeFromLabel(label string) *okta.Role {
	for _, role := range standardRoleTypes {
		if role.Label == label {
			return role
		}
	}
	return nil
}

func roleResource(ctx context.Context, role *okta.Role, ctype *v2.ResourceType) (*v2.Resource, error) {
	var objectID = role.Type
	if role.Type == "" && role.Id != "" {
		objectID = role.Id
	}

	profile := map[string]interface{}{
		"id":    role.Id,
		"label": role.Label,
		"type":  role.Type,
	}

	return sdkResource.NewRoleResource(
		role.Label,
		ctype,
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
		role := okta.AssignRoleRequest{
			Type: roleId,
		}
		createdRole, response, err := g.client.User.AssignRoleToUser(ctx, userId, role, nil)
		if err != nil {
			if response == nil {
				l.Warn("okta-connector: failed to assign role to user, nil response",
					zap.String("user_id", userId), zap.String("role_id", roleId), zap.Error(err))
				return nil, fmt.Errorf("okta-connector: failed to assign role to user: %s", err.Error())
			}
			defer response.Body.Close()
			errOkta, err := getError(response)
			if err != nil {
				return nil, err
			}

			if errOkta.ErrorCode == alreadyAssignedRole {
				l.Warn(
					"okta-connector: The role specified is already assigned to the user",
					zap.String("principal_id", principal.Id.String()),
					zap.String("principal_type", principal.Id.ResourceType),
					zap.String("ErrorCode", errOkta.ErrorCode),
					zap.String("ErrorSummary", errOkta.ErrorSummary),
				)
			}

			return nil, fmt.Errorf("okta-connector: %v", errOkta)
		}

		l.Warn("Role Membership has been created.",
			zap.String("ID", createdRole.Id),
			zap.String("Description", createdRole.Description),
			zap.Time("CreatedAt", *createdRole.Created),
			zap.String("Label", createdRole.Label),
			zap.String("Status", createdRole.Status),
			zap.String("Type", createdRole.Type),
		)
	case resourceTypeGroup.Id:
		groupId := principal.Id.Resource
		role := okta.AssignRoleRequest{
			Type: roleId,
		}
		createdRole, response, err := g.client.Group.AssignRoleToGroup(ctx, groupId, role, nil)
		if err != nil {
			if response == nil {
				l.Warn("okta-connector: failed to assign role to group, nil response",
					zap.String("group_id", groupId), zap.String("role_id", roleId), zap.Error(err))
				return nil, fmt.Errorf("okta-connector: failed to assign role to group: %s", err.Error())
			}
			defer response.Body.Close()
			errOkta, err := getError(response)
			if err != nil {
				return nil, err
			}

			if errOkta.ErrorCode == alreadyAssignedRole {
				l.Warn(
					"okta-connector: The role specified is already assigned to the group",
					zap.String("principal_id", principal.Id.String()),
					zap.String("principal_type", principal.Id.ResourceType),
					zap.String("ErrorCode", errOkta.ErrorCode),
					zap.String("ErrorSummary", errOkta.ErrorSummary),
				)
			}

			return nil, fmt.Errorf("okta-connector: %v", errOkta)
		}

		l.Warn("Role Membership has been created.",
			zap.String("ID", createdRole.Id),
			zap.String("Description", createdRole.Description),
			zap.Time("CreatedAt", *createdRole.Created),
			zap.String("Label", createdRole.Label),
			zap.String("Status", createdRole.Status),
			zap.String("Type", createdRole.Type),
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
		roles, _, err := g.client.User.ListAssignedRolesForUser(ctx, userId, nil)
		if err != nil {
			return nil, fmt.Errorf("okta-connector: failed to get roles: %s", err.Error())
		}

		rolePos := slices.IndexFunc(roles, func(r *okta.Role) bool {
			return r.Type == roleType && r.Status == userStatusActive
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

		roleId = roles[rolePos].Id
		response, err := g.client.User.RemoveRoleFromUser(ctx, userId, roleId)
		if err != nil {
			return nil, fmt.Errorf("okta-connector: failed to remove role: %s", err.Error())
		}

		if response != nil && response.StatusCode == http.StatusNoContent {
			l.Warn("Membership has been revoked",
				zap.String("Status", response.Status),
			)
		}
	case resourceTypeGroup.Id:
		groupId := principal.Id.Resource
		roles, _, err := g.client.Group.ListGroupAssignedRoles(ctx, groupId, nil)
		if err != nil {
			return nil, fmt.Errorf("okta-connector: failed to get roles: %s", err.Error())
		}

		rolePos := slices.IndexFunc(roles, func(r *okta.Role) bool {
			return r.Type == roleType && r.Status == userStatusActive
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

		roleId = roles[rolePos].Id
		response, err := g.client.Group.RemoveRoleFromGroup(ctx, groupId, roleId)
		if err != nil {
			return nil, fmt.Errorf("okta-connector: failed to remove role: %s", err.Error())
		}

		if response != nil && response.StatusCode == http.StatusNoContent {
			l.Warn("Membership has been revoked",
				zap.String("Status", response.Status),
			)
		}
	default:
		return nil, fmt.Errorf("okta-connector: invalid grant resource type: %s", principal.Id.ResourceType)
	}

	return nil, nil
}

func (o *roleResourceType) Get(ctx context.Context, resourceId *v2.ResourceId, parentResourceId *v2.ResourceId) (*v2.Resource, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	l.Debug("getting role", zap.String("role_id", resourceId.Resource))

	for _, role := range standardRoleTypes {
		if role.Type == resourceId.Resource {
			resource, err := roleResource(ctx, role, resourceTypeRole)
			if err != nil {
				return nil, nil, err
			}
			return resource, nil, nil
		}
	}

	return nil, nil, nil
}

func roleBuilder(client *okta.Client, connector *Okta) *roleResourceType {
	return &roleResourceType{
		resourceType: resourceTypeRole,
		client:       client,
		connector:    connector,
	}
}
