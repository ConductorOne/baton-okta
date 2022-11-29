package connector

import (
	"context"
	"fmt"
	"net/http"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"google.golang.org/protobuf/types/known/structpb"
)

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
	domain       string
	apiToken     string
	client       *okta.Client
}

func (o *roleResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *roleResourceType) List(
	ctx context.Context,
	resourceID *v2.ResourceId,
	token *pagination.Token,
) ([]*v2.Resource, string, annotations.Annotations, error) {
	bag, _, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeRole.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	var rv []*v2.Resource

	bag.Pop()
	rv, err = o.listSystemRoles(ctx, resourceID, token)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list system roles: %w", err)
	}

	pageToken, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, err
	}

	return rv, pageToken, nil, nil
}

func (o *roleResourceType) Entitlements(
	ctx context.Context,
	resource *v2.Resource,
	token *pagination.Token,
) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	bag, _, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeRole.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	var rv []*v2.Entitlement

	bag.Pop()
	rv, err = o.listSystemEntitlements(ctx, resource, token)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list system entitlements: %w", err)
	}

	pageToken, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, err
	}

	return rv, pageToken, nil, nil
}

func (o *roleResourceType) Grants(
	ctx context.Context,
	resource *v2.Resource,
	token *pagination.Token,
) ([]*v2.Grant, string, annotations.Annotations, error) {
	bag, page, err := parsePageToken(token.Token, resource.Id)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	var rv []*v2.Grant
	var reqAnnos annotations.Annotations

	qp := queryParams(token.Size, page)

	administratorRoleFlags, respCtx, err := listAdministratorRoleFlags(ctx, o.client, token, qp)

	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list users: %w", err)
	}

	nextPage, annos, err := parseResp(respCtx.OktaResponse)
	reqAnnos = annos
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
	}

	for _, administratorRoleFlag := range administratorRoleFlags {
		if userHasRoleAccess(administratorRoleFlag, resource) {
			userID := administratorRoleFlag.UserId
			roleID := resource.Id.GetResource()
			ur := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeUser.Id, Resource: userID}}

			var annos annotations.Annotations
			annos.Append(&v2.V1Identifier{
				Id: fmtGrantIdV1(resource.Id.Resource, userID, roleID),
			})
			rv = append(rv, &v2.Grant{
				Id: fmtResourceGrant(resource.Id, ur.Id, roleID),
				Entitlement: &v2.Entitlement{
					Id:       fmtResourceRole(resource.Id, roleID),
					Resource: resource,
				},
				Annotations: annos,
				Principal:   ur,
			})
		}
	}

	pageToken, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, err
	}

	return rv, pageToken, reqAnnos, nil
}

func userHasRoleAccess(administratorRoleFlags *administratorRoleFlags, resource *v2.Resource) bool {
	switch resource.Id.GetResource() {
	case "API_ACCESS_MANAGEMENT_ADMIN":
		return administratorRoleFlags.ApiAccessManagementAdmin
	case "MOBILE_ADMIN":
		return administratorRoleFlags.MobileAdmin
	case "ORG_ADMIN":
		return administratorRoleFlags.OrgAdmin
	case "READ_ONLY_ADMIN":
		return administratorRoleFlags.ReadOnlyAdmin
	case "REPORT_ADMIN":
		return administratorRoleFlags.ReportAdmin
	case "SUPER_ADMIN":
		return administratorRoleFlags.SuperAdmin
	case "USER_ADMIN":
		return administratorRoleFlags.UserAdmin
	case "HELP_DESK_ADMIN":
		return administratorRoleFlags.HelpDeskAdmin
	case "APP_ADMIN":
		return administratorRoleFlags.AppAdmin
	case "GROUP_MEMBERSHIP_ADMIN":
		return administratorRoleFlags.GroupMembershipAdmin
	default:
		return false
	}
}

func (o *roleResourceType) listSystemRoles(
	ctx context.Context,
	resource *v2.ResourceId,
	token *pagination.Token,
) ([]*v2.Resource, error) {
	rv := make([]*v2.Resource, 0, len(standardRoleTypes))
	for _, role := range standardRoleTypes {
		resource, err := roleResource(ctx, role)
		if err != nil {
			return nil, fmt.Errorf("okta-connectorv2: failed to create role resource: %w", err)
		}

		rv = append(rv, resource)
	}

	return rv, nil
}

func (o *roleResourceType) listSystemEntitlements(
	ctx context.Context,
	resource *v2.Resource,
	token *pagination.Token,
) ([]*v2.Entitlement, error) {
	rv := make([]*v2.Entitlement, 0, len(standardRoleTypes))
	for _, role := range standardRoleTypes {
		entitlement, err := roleEntitlement(ctx, resource, role)
		if err != nil {
			return nil, fmt.Errorf("okta-connectorv2: failed to create role entitlement: %w", err)
		}

		rv = append(rv, entitlement)
	}

	return rv, nil
}

func getOrgSettings(ctx context.Context, client *okta.Client, token *pagination.Token) (*okta.OrgSetting, *responseContext, error) {
	orgSettings, resp, err := client.OrgSetting.GetOrgSettings(ctx)
	if err != nil {
		return nil, nil, err
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
}

func listAdministratorRoleFlags(ctx context.Context, client *okta.Client, token *pagination.Token, qp *query.Params) ([]*administratorRoleFlags, *responseContext, error) {
	url := "/api/internal/administrators"
	if qp != nil {
		url += qp.String()
	}

	rq := client.CloneRequestExecutor()

	req, err := rq.WithAccept("application/json").WithContentType("application/json").NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}

	var administratorRoleFlags []*administratorRoleFlags

	resp, err := rq.Do(ctx, req, &administratorRoleFlags)
	if err != nil {
		return nil, nil, err
	}

	respCtx, err := responseToContext(token, resp)
	if err != nil {
		return nil, nil, err
	}

	return administratorRoleFlags, respCtx, nil
}

func roleEntitlement(ctx context.Context, resource *v2.Resource, role *okta.Role) (*v2.Entitlement, error) {
	var annos annotations.Annotations
	annos.Append(&v2.V1Identifier{
		Id: fmtResourceIdV1(role.Type),
	})
	return &v2.Entitlement{
		Id:          fmtResourceRole(resource.Id, role.Type),
		Resource:    resource,
		DisplayName: fmt.Sprintf("%s Role Member", role.Label),
		Description: fmt.Sprintf("Has the %s role in Okta", role.Label),
		Annotations: annos,
		GrantableTo: []*v2.ResourceType{resourceTypeUser},
		Purpose:     v2.Entitlement_PURPOSE_VALUE_PERMISSION,
		Slug:        role.Type,
	}, nil
}

func roleResource(ctx context.Context, role *okta.Role) (*v2.Resource, error) {
	trait, err := roleTrait(ctx, role)
	if err != nil {
		return nil, err
	}

	var annos annotations.Annotations
	annos.Append(trait)
	annos.Append(&v2.V1Identifier{
		Id: fmtResourceIdV1(role.Type),
	})

	return &v2.Resource{
		Id:          fmtResourceId(resourceTypeRole.Id, role.Type),
		DisplayName: role.Type,
		Annotations: annos,
	}, nil
}

func roleTrait(ctx context.Context, role *okta.Role) (*v2.RoleTrait, error) {
	profile, err := structpb.NewStruct(map[string]interface{}{
		"type":  role.Type,
		"label": role.Label,
	})
	if err != nil {
		return nil, fmt.Errorf("okta-connectorv2: failed to construct role profile for role trait: %w", err)
	}

	ret := &v2.RoleTrait{
		Profile: profile,
	}

	return ret, nil
}

func roleBuilder(domain string, apiToken string, client *okta.Client) *roleResourceType {
	return &roleResourceType{
		resourceType: resourceTypeRole,
		domain:       domain,
		apiToken:     apiToken,
		client:       client,
	}
}
