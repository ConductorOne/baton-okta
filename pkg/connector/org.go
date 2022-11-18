package connector

import (
	"context"
	"fmt"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/okta/okta-sdk-golang/v2/okta"
)

type Role struct {
	ID    string
	Type  string
	Label string
}

const DefaultLimit = 2

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

func NewPaginationToken(limit int, nextPageToken string) *pagination.Token {
	if limit == 0 || limit > DefaultLimit {
		limit = DefaultLimit
	}

	return &pagination.Token{
		Size:  limit,
		Token: nextPageToken,
	}
}

// Roles that can only be assigned at the org-wide scope.
// For full list of roles see: https://developer.okta.com/docs/reference/api/roles/#role-types
var OrgRoleTypes = []*okta.Role{
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

type orgResourceType struct {
	resourceType *v2.ResourceType
	domain       string
	apiToken     string
	client       *okta.Client
}

// var titleCaser = cases.Title(language.English)

func (o *orgResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *orgResourceType) List(
	ctx context.Context,
	_ *v2.ResourceId,
	token *pagination.Token,
) ([]*v2.Resource, string, annotations.Annotations, error) {
	settings, respCtx, err := getOrgSettings(ctx, o.client, token)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connector: failed to fetch org: %w", err)
	}

	var annos annotations.Annotations
	annos.Append(&v2.ExternalLink{
		Url: orgUrl(o.domain),
	})
	annos.Append(&v2.V1Identifier{
		Id: orgId(settings.Id),
	})

	nextPage, respAnnos, err := parseResp(respCtx.OktaResponse)
	if err != nil {
		return nil, "", nil, err
	}

	return []*v2.Resource{
		{
			Id:          fmtResourceId(resourceTypeOrg.Id, settings.Id),
			DisplayName: resourceTypeOrg.DisplayName,
			Annotations: annos,
		},
	}, nextPage, respAnnos, nil
}

func (o *orgResourceType) Entitlements(
	_ context.Context,
	resource *v2.Resource,
	_ *pagination.Token,
) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	rv := make([]*v2.Entitlement, 0, len(OrgRoleTypes))
	for _, role := range OrgRoleTypes {
		var annos annotations.Annotations
		annos.Append(&v2.V1Identifier{
			Id: fmt.Sprintf("org:%s:role:%s", resource.Id, role),
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

func (o *orgResourceType) Grants(
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
	case resourceTypeOrg.Id:
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
			if !roleIn(OrgRoleTypes, role) {
				continue // Only handle org-wide roles
			}

			ur := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeUser.Id, Resource: userID}}

			var annos annotations.Annotations
			annos.Append(&v2.V1Identifier{
				Id: fmt.Sprintf("org-grant:%s:%s:%s", resource.Id.Resource, userID, role.Type),
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

func orgUrl(domain string) string {
	return fmt.Sprintf("https://%s/", domain)
}

func orgId(id string) string {
	return fmt.Sprintf("org:%s", id)
}

func orgBuilder(domain string, apiToken string, client *okta.Client) *orgResourceType {
	return &orgResourceType{
		resourceType: resourceTypeOrg,
		domain:       domain,
		apiToken:     apiToken,
		client:       client,
	}
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
