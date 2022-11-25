package connector

import (
	"context"
	"fmt"
	"net/http"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"google.golang.org/protobuf/types/known/structpb"
)

type Role struct {
	ID    string
	Type  string
	Label string
}

type ResponseContext struct {
	token *pagination.Token

	requestID string

	status     string
	statusCode uint32

	hasRateLimit       bool
	rateLimit          int64
	rateLimitRemaining int64
	rateLimitReset     time.Time

	OktaResponse *okta.Response
}

// Roles that can only be assigned at the org-wide scope.
// For full list of roles see: https://developer.okta.com/docs/reference/api/roles/#role-types
var standardRoleTypes = []*okta.Role{
	{Id: "API_ACCESS_MANAGEMENT_ADMIN", Label: "API Access Management Administrator"},
	{Id: "MOBILE_ADMIN", Label: "Mobile Administrator"},
	{Id: "ORG_ADMIN", Label: "Organizational Administrator"},
	{Id: "READ_ONLY_ADMIN", Label: "Read-Only Administrator"},
	{Id: "REPORT_ADMIN", Label: "Report Administrator"},
	{Id: "SUPER_ADMIN", Label: "Super Administrator"},
	// The type name is strange, but it is what Okta uses for the Group Administrator standard role
	{Id: "USER_ADMIN", Label: "Group Administrator"},
	{Id: "HELP_DESK_ADMIN", Label: "Help Desk Administrator"},
	{Id: "APP_ADMIN", Label: "Application Administrator"},
	{Id: "GROUP_MEMBERSHIP_ADMIN", Label: "Group Membership Administrator"},
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

const (
	listRoleStandard = "standard"
	listRoleCustom   = "custom"
)

var listRoleTypes = []string{
	listRoleStandard,
	listRoleCustom,
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
	switch bag.ResourceID() {
	case "":
		bag.Pop()
		for _, listRoleType := range listRoleTypes {
			bag.Push(pagination.PageState{
				ResourceTypeID: resourceTypeRole.Id,
				ResourceID:     listRoleType,
			})
		}
	case listRoleStandard:
		bag.Pop()
		rv, err = o.listSystemRoles(ctx, resourceID, token)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list system roles: %w", err)
		}
	case listRoleCustom:
		bag.Pop()
		rv, err = o.listCustomRoles(ctx, resourceID, token)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list custom roles: %w", err)
		}
	default:
		return nil, "", nil, fmt.Errorf("okta-connectorv2: unexpected resource type for role: %w", err)
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
	switch bag.ResourceID() {
	case "":
		bag.Pop()
		for _, listRoleType := range listRoleTypes {
			bag.Push(pagination.PageState{
				ResourceTypeID: resourceTypeRole.Id,
				ResourceID:     listRoleType,
			})
		}
	case listRoleStandard:
		bag.Pop()
		rv, err = o.listSystemEntitlements(ctx, resource, token)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list system entitlements: %w", err)
		}
	case listRoleCustom:
		bag.Pop()
		rv, err = o.listCustomEntitlements(ctx, resource, token)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list custom entitlements: %w", err)
		}
	default:
		return nil, "", nil, fmt.Errorf("okta-connectorv2: unexpected resource type for role: %w", err)
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

	switch bag.ResourceTypeID() {
	case resourceTypeRole.Id:
		qp := queryParams(token.Size, page)

		users, respCtx, err := listUsers(ctx, o.client, token, qp)
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

		for _, user := range users {
			bag.Push(pagination.PageState{
				ResourceTypeID: resourceTypeUser.Id,
				ResourceID:     user.Id,
			})
		}

	case resourceTypeUser.Id:
		userID := bag.ResourceID()
		qp := queryParams(token.Size, page)

		userRoles, respCtx, err := listUserRoles(ctx, o.client, userID, token, qp)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list user roles: %w", err)
		}

		nextPage, annos, err := parseResp(respCtx.OktaResponse)
		reqAnnos = annos
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
		}

		err = bag.Next(nextPage)
		if err != nil {
			return nil, "", nil, err
		}

		for _, role := range userRoles {
			ur := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeUser.Id, Resource: userID}}

			var annos annotations.Annotations
			annos.Append(&v2.V1Identifier{
				Id: fmtGrantIdV1(resource.Id.Resource, userID, role.Id),
			})
			rv = append(rv, &v2.Grant{
				Id: fmtResourceGrant(resource.Id, ur.Id, role.Id),
				Entitlement: &v2.Entitlement{
					Id:       fmtResourceRole(resource.Id, role.Id),
					Resource: resource,
				},
				Annotations: annos,
				Principal:   ur,
			})
		}

	default:
		return nil, "", nil, fmt.Errorf("okta-connectorv2: unexpected resource type while fetching grants for repo")
	}

	pageToken, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, err
	}

	return rv, pageToken, reqAnnos, nil
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

func (o *roleResourceType) listCustomRoles(
	ctx context.Context,
	resource *v2.ResourceId,
	token *pagination.Token,
) ([]*v2.Resource, error) {
	_, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeRole.Id})
	if err != nil {
		return nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	qp := queryParams(token.Size, page)

	roles, _, err := listOktaIamCustomRoles(ctx, o.client, token, qp)
	if err != nil {
		return nil, fmt.Errorf("okta-connectorv2: failed to list custom roles: %w", err)
	}

	rv := make([]*v2.Resource, 0)

	for _, role := range roles {
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

func (o *roleResourceType) listCustomEntitlements(
	ctx context.Context,
	resource *v2.Resource,
	token *pagination.Token,
) ([]*v2.Entitlement, error) {
	_, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeRole.Id})
	if err != nil {
		return nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	qp := queryParams(token.Size, page)

	roles, _, err := listOktaIamCustomRoles(ctx, o.client, token, qp)
	if err != nil {
		return nil, fmt.Errorf("okta-connectorv2: failed to list custom entitlements: %w", err)
	}

	rv := make([]*v2.Entitlement, 0)

	for _, role := range roles {
		resource, err := roleEntitlement(ctx, resource, role)
		if err != nil {
			return nil, fmt.Errorf("okta-connectorv2: failed to create role entitlement: %w", err)
		}

		rv = append(rv, resource)
	}

	return rv, nil
}

func getOrgSettings(ctx context.Context, client *okta.Client, token *pagination.Token) (*okta.OrgSetting, *ResponseContext, error) {
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

type CustomRole struct {
	Id          string      `json:"id,omitempty"`
	Label       string      `json:"label,omitempty"`
	Description string      `json:"description,omitempty"`
	Created     string      `json:"created,omitempty"`
	LastUpdated string      `json:"lastUpdated,omitempty"`
	Links       interface{} `json:"_links,omitempty"`
}

type CustomRoles struct {
	Roles []*okta.Role `json:"roles,omitempty"`
	Links interface{}  `json:"_links,omitempty"`
}

func listOktaIamCustomRoles(ctx context.Context, client *okta.Client, token *pagination.Token, qp *query.Params) ([]*okta.Role, *ResponseContext, error) {
	url := "/api/v1/iam/roles"
	if qp != nil {
		url += qp.String()
	}

	rq := client.CloneRequestExecutor()

	req, err := rq.WithAccept("application/json").WithContentType("application/json").NewRequest(http.MethodGet, url, nil)
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

func roleEntitlement(ctx context.Context, resource *v2.Resource, role *okta.Role) (*v2.Entitlement, error) {
	var annos annotations.Annotations
	annos.Append(&v2.V1Identifier{
		Id: fmtResourceIdV1(role.Id),
	})
	return &v2.Entitlement{
		Id:          fmtResourceRole(resource.Id, role.Id),
		Resource:    resource,
		DisplayName: fmt.Sprintf("%s Role Member", role.Label),
		Description: fmt.Sprintf("Has the %s role in Okta", role.Label),
		Annotations: annos,
		GrantableTo: []*v2.ResourceType{resourceTypeUser},
		Purpose:     v2.Entitlement_PURPOSE_VALUE_PERMISSION,
		Slug:        role.Id,
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
		Id: fmtResourceIdV1(role.Id),
	})

	return &v2.Resource{
		Id:          fmtResourceId(resourceTypeRole.Id, role.Id),
		DisplayName: resourceTypeRole.DisplayName,
		Annotations: annos,
	}, nil
}

func roleTrait(ctx context.Context, role *okta.Role) (*v2.RoleTrait, error) {
	profile, err := structpb.NewStruct(map[string]interface{}{
		"id":    role.Id,
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
