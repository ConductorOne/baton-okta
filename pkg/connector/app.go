package connector

import (
	"context"
	"encoding/json"
	"fmt"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/structpb"
)

type appResourceType struct {
	resourceType     *v2.ResourceType
	domain           string
	apiToken         string
	syncInactiveApps bool
	client           *okta.Client
}

const (
	appGrantGroup = "group"
	appGrantUser  = "user"
)

var appGrantTypes = []string{
	appGrantGroup,
	appGrantUser,
}

func (o *appResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func appBuilder(domain string, apiToken string, syncInactiveApps bool, client *okta.Client) *appResourceType {
	return &appResourceType{
		resourceType:     resourceTypeApp,
		domain:           domain,
		apiToken:         apiToken,
		client:           client,
		syncInactiveApps: syncInactiveApps,
	}
}

func (o *appResourceType) List(
	ctx context.Context,
	resourceID *v2.ResourceId,
	token *pagination.Token,
) ([]*v2.Resource, string, annotations.Annotations, error) {
	bag, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeUser.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	var rv []*v2.Resource
	qp := queryParams(token.Size, page)
	apps, respCtx, err := listApps(ctx, o.client, o.syncInactiveApps, token, qp)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list users: %w", err)
	}

	nextPage, annos, err := parseResp(respCtx.OktaResponse)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
	}

	for _, app := range apps {
		resource, err := appResource(ctx, app)
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

func (o *appResourceType) Entitlements(
	ctx context.Context,
	resource *v2.Resource,
	token *pagination.Token,
) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement
	for _, level := range standardRoleTypes {
		rv = append(rv, appEntitlement(ctx, resource, level.Type))
	}

	return rv, "", nil, nil
}

func (o *appResourceType) Grants(
	ctx context.Context,
	resource *v2.Resource,
	token *pagination.Token,
) ([]*v2.Grant, string, annotations.Annotations, error) {
	var (
		rv    []*v2.Grant
		annos annotations.Annotations
	)
	bag, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeUser.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	switch bag.ResourceID() {
	case "":
		bag.Pop()
		for _, appGrantType := range appGrantTypes {
			bag.Push(pagination.PageState{
				ResourceTypeID: resourceTypeApp.Id,
				ResourceID:     appGrantType,
			})
		}
	case appGrantGroup:
		rv, annos, bag, err = o.listAppGroupGrants(ctx, resource, token, bag, page)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list app group grants: %w", err)
		}
	case appGrantUser:
		rv, annos, bag, err = o.listAppUsersGrants(ctx, resource, token, bag, page)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list app users grants: %w", err)
		}
	default:
		return nil, "", nil, fmt.Errorf("okta-connectorv2: unexpected resource for app: %w", err)
	}

	pageToken, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, err
	}

	return rv, pageToken, annos, nil
}

func (o *appResourceType) listAppGroupGrants(
	ctx context.Context,
	resource *v2.Resource,
	token *pagination.Token,
	bag *pagination.Bag,
	page string,
) ([]*v2.Grant, annotations.Annotations, *pagination.Bag, error) {
	var rv []*v2.Grant
	qp := queryParams(token.Size, page)
	applicationGroupAssignments, respCtx, err := listApplicationGroupAssignments(ctx, o.client, resource.Id.GetResource(), token, qp)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("okta-connectorv2: failed to list group users: %w", err)
	}

	nextPage, annos, err := parseResp(respCtx.OktaResponse)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
	}

	for _, applicationGroupAssignment := range applicationGroupAssignments {
		roles, _, err := o.client.Group.ListGroupAssignedRoles(ctx, applicationGroupAssignment.Id, nil)
		if err != nil {
			return nil, annos, bag, err
		}

		for _, role := range roles {
			rv = append(rv, appGroupGrant(resource, applicationGroupAssignment, role.Type))
		}
	}

	return rv, annos, bag, nil
}

func (o *appResourceType) listAppUsersGrants(
	ctx context.Context,
	resource *v2.Resource,
	token *pagination.Token,
	bag *pagination.Bag,
	page string,
) ([]*v2.Grant, annotations.Annotations, *pagination.Bag, error) {
	var rv []*v2.Grant
	qp := queryParams(token.Size, page)
	applicationUsers, respCtx, err := listApplicationUsers(ctx, o.client, resource.Id.GetResource(), token, qp)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("okta-connectorv2: failed to list group users: %w", err)
	}

	nextPage, annos, err := parseResp(respCtx.OktaResponse)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
	}

	for _, applicationUser := range applicationUsers {
		roles, _, err := o.client.User.ListAssignedRolesForUser(ctx, applicationUser.Id, nil)
		if err != nil {
			return nil, annos, bag, err
		}

		for _, role := range roles {
			rv = append(rv, appUserGrant(resource, applicationUser, role.Type))
		}
	}

	return rv, annos, bag, nil
}

func listApps(ctx context.Context, client *okta.Client, syncInactiveApps bool, token *pagination.Token, qp *query.Params) ([]*okta.Application, *responseContext, error) {
	if !syncInactiveApps {
		qp.Filter = "status eq \"ACTIVE\""
	}

	apps, resp, err := client.Application.ListApplications(ctx, qp)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch apps from okta: %w", err)
	}

	reqCtx, err := responseToContext(token, resp)
	if err != nil {
		return nil, nil, err
	}

	applications, err := oktaAppsToOktaApplications(ctx, apps)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: error converting okta apps to applications: %w", err)
	}

	return applications, reqCtx, nil
}

func listApplicationGroupAssignments(ctx context.Context, client *okta.Client, appID string, token *pagination.Token, qp *query.Params) ([]*okta.ApplicationGroupAssignment, *responseContext, error) {
	applicationGroupAssignments, resp, err := client.Application.ListApplicationGroupAssignments(ctx, appID, qp)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch app group assignments from okta: %w", err)
	}

	reqCtx, err := responseToContext(token, resp)
	if err != nil {
		return nil, nil, err
	}

	return applicationGroupAssignments, reqCtx, nil
}

func listApplicationUsers(ctx context.Context, client *okta.Client, appID string, token *pagination.Token, qp *query.Params) ([]*okta.AppUser, *responseContext, error) {
	applicationUsers, resp, err := client.Application.ListApplicationUsers(ctx, appID, qp)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch app users from okta: %w", err)
	}

	reqCtx, err := responseToContext(token, resp)
	if err != nil {
		return nil, nil, err
	}

	return applicationUsers, reqCtx, nil
}

func oktaAppsToOktaApplications(ctx context.Context, apps []okta.App) ([]*okta.Application, error) {
	var applications []*okta.Application
	for _, iapp := range apps {
		var oktaApp okta.Application

		b, err := json.Marshal(iapp)
		if err != nil {
			return nil, fmt.Errorf("okta-connectorv2: error marshalling okta app: %w", err)
		}
		err = json.Unmarshal(b, &oktaApp)
		if err != nil {
			return nil, fmt.Errorf("okta-connectorv2: error unmarshalling okta app: %w", err)
		}

		applications = append(applications, &oktaApp)
	}

	return applications, nil
}

func appResource(ctx context.Context, app *okta.Application) (*v2.Resource, error) {
	trait, err := appTrait(ctx, app)
	if err != nil {
		return nil, err
	}

	var annos annotations.Annotations
	annos.Update(trait)
	annos.Update(&v2.V1Identifier{
		Id: fmtResourceIdV1(app.Id),
	})

	return &v2.Resource{
		Id:          fmtResourceId(resourceTypeApp.Id, app.Id),
		DisplayName: app.Label,
		Annotations: annos,
	}, nil
}

func appTrait(ctx context.Context, app *okta.Application) (*v2.AppTrait, error) {
	profile, err := structpb.NewStruct(map[string]interface{}{
		"status": app.Status,
	})
	if err != nil {
		return nil, fmt.Errorf("okta-connectorv2: failed to construct role profile for role trait: %w", err)
	}

	ret := &v2.AppTrait{
		Profile: profile,
	}

	return ret, nil
}

func appEntitlement(ctx context.Context, resource *v2.Resource, permission string) *v2.Entitlement {
	var annos annotations.Annotations
	annos.Update(&v2.V1Identifier{
		Id: V1MembershipEntitlementID(resource.Id.GetResource()),
	})
	return &v2.Entitlement{
		Id: fmt.Sprintf("%s:%s:%s",
			resource.Id.ResourceType,
			resource.Id.Resource,
			permission,
		),
		Resource:    resource,
		DisplayName: fmt.Sprintf("%s app access", resource.DisplayName),
		Description: fmt.Sprintf("Has access to the %s app in Okta", resource.DisplayName),
		Annotations: annos,
		GrantableTo: []*v2.ResourceType{resourceTypeGroup, resourceTypeUser},
		Purpose:     v2.Entitlement_PURPOSE_VALUE_ASSIGNMENT,
		Slug:        resource.DisplayName,
	}
}

func appGroupGrant(resource *v2.Resource, applicationGroupAssignment *okta.ApplicationGroupAssignment, roleType string) *v2.Grant {
	var annos annotations.Annotations
	// appID := resource.Id.GetResource()
	groupID := applicationGroupAssignment.Id
	ur := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeGroup.Id, Resource: groupID}}
	annos.Update(&v2.V1Identifier{
		Id: fmtGrantIdV1(V1MembershipEntitlementID(resource.Id.Resource), groupID),
	})

	return &v2.Grant{
		Id: fmtResourceGrant(resource.Id, ur.Id, roleType),
		Entitlement: &v2.Entitlement{
			Id: fmtResourceRole(resource.Id, roleType),
			// Id: fmt.Sprintf("%s:%s:%s",resource.Id.ResourceType,
			// 	resource.Id.Resource,
			// 	roleType,
			// ),
			Resource: resource,
		},
		Annotations: annos,
		Principal:   ur,
	}
}

func appUserGrant(resource *v2.Resource, applicationUser *okta.AppUser, roleType string) *v2.Grant {
	var annos annotations.Annotations
	// appID := resource.Id.GetResource()
	userID := applicationUser.Id
	ur := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeUser.Id, Resource: userID}}
	annos.Update(&v2.V1Identifier{
		Id: fmtGrantIdV1(V1MembershipEntitlementID(resource.Id.Resource), userID),
	})

	return &v2.Grant{
		Id: fmtResourceGrant(resource.Id, ur.Id, roleType),
		Entitlement: &v2.Entitlement{
			Id: fmtResourceRole(resource.Id, roleType),
			// Id: fmt.Sprintf(
			// 	"%s:%s:%s",
			// 	resource.Id.ResourceType,
			// 	resource.Id.Resource,
			// 	roleType,
			// ),
			Resource: resource,
		},
		Annotations: annos,
		Principal:   ur,
	}
}

func (g *appResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	if principal.Id.ResourceType != resourceTypeUser.Id {
		l.Warn(
			"okta-connector: only users or groups can be granted role membership",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("okta-connector: only users or groups can be granted repo membership")
	}

	return nil, nil
}

func (g *appResourceType) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	return nil, nil
}
