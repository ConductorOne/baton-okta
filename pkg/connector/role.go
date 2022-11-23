package connector

import (
	"context"
	"fmt"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/okta/okta-sdk-golang/v2/okta"
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
	resource *v2.ResourceId,
	token *pagination.Token,
) ([]*v2.Resource, string, annotations.Annotations, error) {
	rv := make([]*v2.Resource, 0, len(standardRoleTypes))
	for _, role := range standardRoleTypes {
		resource, err := roleResource(ctx, role)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to create role resource: %w", err)
		}

		var annos annotations.Annotations
		annos.Append(&v2.V1Identifier{
			Id: fmtResourceIdV1(role.Type),
		})
		rv = append(rv, resource)
	}

	return rv, "", nil, nil
}

func (o *roleResourceType) Entitlements(
	_ context.Context,
	resource *v2.Resource,
	_ *pagination.Token,
) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	rv := make([]*v2.Entitlement, 0, len(standardRoleTypes))
	for _, role := range standardRoleTypes {
		var annos annotations.Annotations
		annos.Append(&v2.V1Identifier{
			Id: fmtResourceIdV1(role.Type),
		})
		rv = append(rv, &v2.Entitlement{
			Id:          fmtResourceRole(resource.Id, role.Type),
			Resource:    resource,
			DisplayName: fmt.Sprintf("%s Role Member", role.Label),
			Description: fmt.Sprintf("Has the %s role in Okta", role.Label),
			Annotations: annos,
			GrantableTo: []*v2.ResourceType{resourceTypeUser},
			Purpose:     v2.Entitlement_PURPOSE_VALUE_PERMISSION,
			Slug:        role.Type,
		})
	}

	return rv, "", nil, nil
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
				Id: fmtGrantIdV1(resource.Id.Resource, userID, role.Type),
			})
			rv = append(rv, &v2.Grant{
				Id: fmtResourceGrant(resource.Id, ur.Id, role.Type),
				Entitlement: &v2.Entitlement{
					Id:       fmtResourceRole(resource.Id, role.Type),
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
		Id:          fmtResourceId(resourceTypeRole.Id, role.Type),
		DisplayName: resourceTypeRole.DisplayName,
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
