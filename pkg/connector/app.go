package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	oktav5 "github.com/conductorone/okta-sdk-golang/v5/okta"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/ratelimit"
	sdkEntitlement "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	sdkGrant "github.com/conductorone/baton-sdk/pkg/types/grant"
	sdkResource "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"go.uber.org/zap"
)

type appResourceType struct {
	resourceType     *v2.ResourceType
	domain           string
	apiToken         string
	syncInactiveApps bool
	userEmailFilters []string
	client           *okta.Client
	clientV5         *oktav5.APIClient
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

func appBuilder(domain string, apiToken string, syncInactiveApps bool, filterEmailDomains []string, client *okta.Client, clientv5 *oktav5.APIClient) *appResourceType {
	return &appResourceType{
		resourceType:     resourceTypeApp,
		domain:           domain,
		apiToken:         apiToken,
		client:           client,
		syncInactiveApps: syncInactiveApps,
		userEmailFilters: filterEmailDomains,
		clientV5:         clientv5,
	}
}

func (o *appResourceType) List(
	ctx context.Context,
	resourceID *v2.ResourceId,
	token *pagination.Token,
) ([]*v2.Resource, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	bag, page, err := parsePageTokenV5(token.Token, &v2.ResourceId{ResourceType: resourceTypeUser.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	var rv []*v2.Resource
	apps, respCtx, err := listAppsV5(ctx, o.clientV5, o.syncInactiveApps, page)
	if err != nil {
		anno, err := wrapErrorV5(respCtx, err, errors.New("okta-connector: verify failed to fetch apps list"))
		return nil, "", anno, err
	}

	nextPage, annos, err := parseRespV5(respCtx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
	}

	for _, app := range apps {
		if app.Id == nil {
			l.Warn("okta-connectorv2: app.Id is nil, skipping")
			continue
		}

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
	rv = append(rv, sdkEntitlement.NewAssignmentEntitlement(resource, "access",
		sdkEntitlement.WithDisplayName(fmt.Sprintf("%s App Access", resource.DisplayName)),
		sdkEntitlement.WithDescription(fmt.Sprintf("Has access to the %s app in Okta", resource.DisplayName)),
	))

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

	bag, page, err := parsePageTokenV5(token.Token, &v2.ResourceId{ResourceType: resourceTypeUser.Id})
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
		rv, annos, bag, err = o.listAppGroupGrants(ctx, resource, bag, page)
	case appGrantUser:
		rv, annos, bag, err = o.listAppUsersGrants(ctx, resource, bag, page)
	default:
		return nil, "", nil, fmt.Errorf("okta-connectorv2: unexpected resource for app: %w", err)
	}

	if err != nil {
		return nil, "", annos, err
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
	bag *pagination.Bag,
	page string,
) ([]*v2.Grant, annotations.Annotations, *pagination.Bag, error) {
	l := ctxzap.Extract(ctx)

	var rv []*v2.Grant
	applicationGroupAssignments, respCtx, err := listApplicationGroupAssignmentsV5(
		ctx,
		o.clientV5,
		resource.Id.GetResource(),
		func(r oktav5.ApiListApplicationGroupAssignmentsRequest) oktav5.ApiListApplicationGroupAssignmentsRequest {
			return r.After(page)
		},
	)
	if err != nil {
		annon, err := wrapErrorV5(respCtx, err, errors.New("okta-connectorv2: verify failed to fetch application group assignments list"))
		return nil, annon, bag, err
	}

	nextPage, annos, err := parseRespV5(respCtx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
	}

	for _, applicationGroupAssignment := range applicationGroupAssignments {
		if applicationGroupAssignment.Id == nil {
			l.Warn("okta-connectorv2: applicationGroupAssignment.Id is nil, skipping")
			continue
		}

		groupID := *applicationGroupAssignment.Id
		principalID := &v2.ResourceId{ResourceType: resourceTypeGroup.Id, Resource: groupID}
		rv = append(rv, sdkGrant.NewGrant(resource, "access", principalID,
			sdkGrant.WithAnnotation(
				&v2.V1Identifier{
					Id: fmtGrantIdV1(V1MembershipEntitlementID(resource.Id.Resource), groupID),
				},
			),
		))
	}

	return rv, annos, bag, nil
}

func (o *appResourceType) listAppUsersGrants(
	ctx context.Context,
	resource *v2.Resource,
	bag *pagination.Bag,
	page string,
) ([]*v2.Grant, annotations.Annotations, *pagination.Bag, error) {
	var rv []*v2.Grant
	applicationUsers, respCtx, err := listApplicationUsersV5(ctx, o.clientV5, resource.Id.GetResource(), page)
	if err != nil {
		anno, err := wrapErrorV5(respCtx, err, errors.New("okta-connectorv2: failed to list group users"))
		return nil, anno, bag, err
	}

	nextPage, annos, err := parseRespV5(respCtx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
	}

	for _, applicationUser := range applicationUsers {
		// for okta v2, we only attempt to filter app users by email domains when a list is provided
		if len(o.userEmailFilters) > 0 && !shouldIncludeOktaAppUser(&applicationUser, o.userEmailFilters) {
			continue
		}

		if applicationUser.Id == nil {
			continue
		}

		userID := *applicationUser.Id

		principalID := &v2.ResourceId{ResourceType: resourceTypeUser.Id, Resource: userID}
		rv = append(rv, sdkGrant.NewGrant(resource, "access", principalID,
			sdkGrant.WithAnnotation(
				&v2.V1Identifier{
					Id: fmtGrantIdV1(V1MembershipEntitlementID(resource.Id.Resource), userID),
				},
			),
		))
	}

	return rv, annos, bag, nil
}

func listAppsV5(ctx context.Context, client *oktav5.APIClient, syncInactiveApps bool, page string) ([]oktav5.Application, *oktav5.APIResponse, error) {
	request := client.ApplicationAPI.ListApplications(ctx).After(page).Limit(defaultLimit)

	if !syncInactiveApps {
		request = request.Filter("status eq \"ACTIVE\"")
	}

	apps, resp, err := request.Execute()
	if err != nil {
		return nil, resp, fmt.Errorf("okta-connectorv2: failed to fetch apps from okta: %w", err)
	}

	applications, err := oktaAppsToOktaApplicationsv5(ctx, apps)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: error converting okta apps to applications: %w", err)
	}

	return applications, resp, nil
}

type ApiListApplicationGroupAssignmentsRequestOpt func(r oktav5.ApiListApplicationGroupAssignmentsRequest) oktav5.ApiListApplicationGroupAssignmentsRequest

func listApplicationGroupAssignmentsV5(
	ctx context.Context,
	client *oktav5.APIClient,
	appID string,
	opts ...ApiListApplicationGroupAssignmentsRequestOpt,
) ([]oktav5.ApplicationGroupAssignment, *oktav5.APIResponse, error) {
	request := client.ApplicationGroupsAPI.ListApplicationGroupAssignments(ctx, appID).Limit(defaultLimit)

	for _, opt := range opts {
		request = opt(request)
	}

	applicationGroupAssignments, resp, err := request.Execute()
	if err != nil {
		return nil, resp, fmt.Errorf("okta-connectorv2: failed to fetch app group assignments from okta: %w", err)
	}

	return applicationGroupAssignments, resp, nil
}

func listApplicationUsersV5(ctx context.Context, client *oktav5.APIClient, appID string, after string) ([]oktav5.AppUser, *oktav5.APIResponse, error) {
	applicationUsers, resp, err := client.ApplicationUsersAPI.ListApplicationUsers(ctx, appID).After(after).Limit(defaultLimit).Execute()
	if err != nil {
		return nil, resp, fmt.Errorf("okta-connectorv2: failed to fetch app users from oktav5: %w", err)
	}

	return applicationUsers, resp, nil
}

func oktaAppsToOktaApplicationsv5(ctx context.Context, apps []oktav5.ListApplications200ResponseInner) ([]oktav5.Application, error) {
	var applications []oktav5.Application
	for _, iapp := range apps {
		var app *oktav5.Application

		switch {
		case iapp.AutoLoginApplication != nil:
			app = &iapp.AutoLoginApplication.Application
		case iapp.BasicAuthApplication != nil:
			app = &iapp.BasicAuthApplication.Application
		case iapp.BookmarkApplication != nil:
			app = &iapp.BookmarkApplication.Application
		case iapp.BrowserPluginApplication != nil:
			app = &iapp.BrowserPluginApplication.Application
		case iapp.OpenIdConnectApplication != nil:
			app = &iapp.OpenIdConnectApplication.Application
		case iapp.Saml11Application != nil:
			app = &iapp.Saml11Application.Application
		case iapp.SamlApplication != nil:
			app = &iapp.SamlApplication.Application
		case iapp.SecurePasswordStoreApplication != nil:
			app = &iapp.SecurePasswordStoreApplication.Application
		case iapp.WsFederationApplication != nil:
			app = &iapp.WsFederationApplication.Application
		default:
			return nil, fmt.Errorf("okta-connectorv2: unknown application type: %T", iapp.GetActualInstance())
		}

		if app == nil {
			return nil, fmt.Errorf("okta-connectorv2: application is nil")
		}

		applications = append(applications, *app)
	}

	return applications, nil
}

func oktaAppToOktaApplication(ctx context.Context, app okta.App) (*okta.Application, error) {
	var oktaApp okta.Application
	b, err := json.Marshal(app)
	if err != nil {
		return nil, fmt.Errorf("okta-connectorv2: error marshalling okta app: %w", err)
	}
	err = json.Unmarshal(b, &oktaApp)
	if err != nil {
		return nil, fmt.Errorf("okta-connectorv2: error unmarshalling okta app: %w", err)
	}
	return &oktaApp, nil
}

func oktaAppToOktaApplicationV5(ctx context.Context, app oktav5.ListApplications200ResponseInner) (*oktav5.Application, error) {
	var oktaApp oktav5.Application
	b, err := json.Marshal(app.GetActualInstance())
	if err != nil {
		return nil, fmt.Errorf("okta-connectorv2: error marshalling okta app: %w", err)
	}
	err = json.Unmarshal(b, &oktaApp)
	if err != nil {
		return nil, fmt.Errorf("okta-connectorv2: error unmarshalling okta app: %w", err)
	}
	return &oktaApp, nil
}

func appResource(ctx context.Context, app oktav5.Application) (*v2.Resource, error) {
	appProfile := map[string]interface{}{
		"status": nullableStr(app.Status),
	}
	var appTraitOpts []sdkResource.AppTraitOption
	appTraitOpts = append(appTraitOpts, sdkResource.WithAppProfile(appProfile))

	return sdkResource.NewAppResource(app.Label, resourceTypeApp, *app.Id, appTraitOpts,
		sdkResource.WithAnnotation(&v2.V1Identifier{Id: fmtResourceIdV1(*app.Id)}),
		sdkResource.WithAnnotation(&v2.RawId{Id: *app.Id}),
	)
}

func (g *appResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	var (
		ok    bool
		email string
	)
	l := ctxzap.Extract(ctx)
	if principal.Id.ResourceType != resourceTypeUser.Id && principal.Id.ResourceType != resourceTypeGroup.Id {
		l.Warn(
			"okta-connector: only users or groups can be granted app membership",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("okta-connector: only users or groups can be granted app membership")
	}

	appID := entitlement.Resource.Id.Resource
	switch principal.Id.ResourceType {
	case resourceTypeUser.Id:
		userID := principal.Id.Resource
		appUser, response, err := g.client.Application.GetApplicationUser(ctx, appID, userID, nil)
		if err != nil {
			defer response.Body.Close()
			errOkta, err := getError(response)
			if err != nil {
				return nil, err
			}

			if errOkta.ErrorCode != ResourceNotFoundExceptionErrorCode {
				l.Warn(
					"okta-connector: ",
					zap.String("principal_id", principal.Id.String()),
					zap.String("principal_type", principal.Id.ResourceType),
					zap.String("ErrorCode", errOkta.ErrorCode),
					zap.String("ErrorSummary", errOkta.ErrorSummary),
				)

				return nil, fmt.Errorf("okta-connector: %v", errOkta)
			}
		}

		if appUser != nil && userID == appUser.Id {
			l.Warn(
				"okta-connector: The app specified is already assigned to the user",
				zap.String("principal_id", principal.Id.String()),
				zap.String("principal_type", principal.Id.ResourceType),
				zap.Any("Profile", appUser.Profile),
			)
			return annotations.New(&v2.GrantAlreadyExists{}), nil
		}

		user, _, err := g.client.User.GetUser(ctx, userID)
		if err != nil {
			return nil, err
		}

		profile := *user.Profile
		if email, ok = profile["email"].(string); !ok {
			email = unknownProfileValue
		}

		payload := okta.AppUser{
			Credentials: &okta.AppUserCredentials{
				UserName: email,
			},
			Id:    userID,
			Scope: strings.ToUpper(principal.Id.ResourceType),
		}
		assignedUser, response, err := g.client.Application.AssignUserToApplication(ctx, appID, payload)
		if err != nil {
			l.Warn(
				"okta-connector: The app specified cannot be assigned to the user",
				zap.String("principal_id", principal.Id.String()),
				zap.String("principal_type", principal.Id.ResourceType),
			)
			return nil, fmt.Errorf("okta-connector: The app specified cannot be assigned to the user %s %s",
				err.Error(), response.Body)
		}

		l.Warn("App Membership has been created.",
			zap.String("userID", assignedUser.Id),
			zap.String("Status", assignedUser.Status),
			zap.Time("LastUpdated", *assignedUser.LastUpdated),
			zap.String("Scope", assignedUser.Scope),
		)
	case resourceTypeGroup.Id:
		groupID := principal.Id.Resource
		appGroup, response, err := g.client.Application.GetApplicationGroupAssignment(ctx, appID, groupID, nil)
		if err != nil {
			defer response.Body.Close()
			errOkta, err := getError(response)
			if err != nil {
				return nil, err
			}

			if errOkta.ErrorCode != ResourceNotFoundExceptionErrorCode {
				l.Warn(
					"okta-connector: ",
					zap.String("principal_id", principal.Id.String()),
					zap.String("principal_type", principal.Id.ResourceType),
					zap.String("ErrorCode", errOkta.ErrorCode),
					zap.String("ErrorSummary", errOkta.ErrorSummary),
				)

				return nil, fmt.Errorf("okta-connector: %v", errOkta)
			}
		}

		if appGroup != nil && groupID == appGroup.Id {
			l.Warn(
				"okta-connector: The app specified is already assigned to the group",
				zap.String("principal_id", principal.Id.String()),
				zap.String("principal_type", principal.Id.ResourceType),
				zap.Any("Profile", appGroup.Profile),
			)
			return annotations.New(&v2.GrantAlreadyExists{}), nil
		}

		payload := okta.ApplicationGroupAssignment{}
		assignedGroup, _, err := g.client.Application.CreateApplicationGroupAssignment(ctx, appID, groupID, payload)
		if err != nil {
			return nil, err
		}

		l.Warn("App Membership has been created.",
			zap.String("userID", assignedGroup.Id),
			zap.Time("LastUpdated", *assignedGroup.LastUpdated),
		)
	default:
		return nil, fmt.Errorf("okta-connector: invalid grant resource type: %s", principal.Id.ResourceType)
	}

	return nil, nil
}

func (g *appResourceType) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	entitlement := grant.Entitlement
	principal := grant.Principal
	if principal.Id.ResourceType != resourceTypeUser.Id && principal.Id.ResourceType != resourceTypeGroup.Id {
		l.Warn(
			"okta-connector: only users or groups can have app membership revoked",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("okta-connector:only users or groups can have app membership revoked")
	}

	appID := entitlement.Resource.Id.Resource
	switch principal.Id.ResourceType {
	case resourceTypeUser.Id:
		userID := principal.Id.Resource
		_, resp, err := g.client.Application.GetApplicationUser(ctx, appID, userID, nil)
		if err != nil {
			if resp != nil && resp.StatusCode == http.StatusNotFound {
				l.Debug(
					"okta-connector: revoke: user does not have app membership",
					zap.String("principal_id", principal.Id.String()),
					zap.String("principal_type", principal.Id.ResourceType),
				)
				return annotations.New(&v2.GrantAlreadyRevoked{}), nil
			}
			l.Warn(
				"okta-connector: user does not have app membership",
				zap.String("principal_id", principal.Id.String()),
				zap.String("principal_type", principal.Id.ResourceType),
			)
			return nil, fmt.Errorf("okta-connector: user does not have app membership: %s", err.Error())
		}

		response, err := g.client.Application.DeleteApplicationUser(ctx, appID, userID, nil)
		if err != nil {
			return nil, fmt.Errorf("okta-connector: failed to remove user from application: %s %s", err.Error(), response.Body)
		}

		if response.StatusCode == http.StatusNoContent {
			l.Warn("Membership has been revoked",
				zap.String("Status", response.Status),
			)
		}
	case resourceTypeGroup.Id:
		groupID := principal.Id.Resource
		_, _, err := g.client.Application.GetApplicationGroupAssignment(ctx, appID, groupID, nil)
		if err != nil {
			l.Warn(
				"okta-connector: group does not have app membership",
				zap.String("principal_id", principal.Id.String()),
				zap.String("principal_type", principal.Id.ResourceType),
			)
			return nil, fmt.Errorf("okta-connector: group does not have app membership: %s", err.Error())
		}

		response, err := g.client.Application.DeleteApplicationGroupAssignment(ctx, appID, groupID)
		if err != nil {
			return nil, fmt.Errorf("okta-connector: failed to remove group from application: %s %s", err.Error(), response.Body)
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

func (o *appResourceType) Get(ctx context.Context, resourceId *v2.ResourceId, parentResourceId *v2.ResourceId) (*v2.Resource, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	l.Debug("getting app", zap.String("app_id", resourceId.Resource))

	var annos annotations.Annotations

	app, resp, err := getApp(ctx, o.clientV5, resourceId.Resource)
	if err != nil {
		anno, err := wrapErrorV5(resp, err, fmt.Errorf("okta-connectorv2: verify failed to fetch application"))
		return nil, anno, err
	}

	if desc, err := ratelimit.ExtractRateLimitData(resp.StatusCode, &resp.Header); err == nil {
		annos.WithRateLimiting(desc)
	}

	if app == nil {
		return nil, annos, nil
	}

	if !o.syncInactiveApps && nullableStr(app.Status) != "ACTIVE" {
		return nil, annos, nil
	}

	resource, err := appResource(ctx, *app)
	if err != nil {
		return nil, annos, err
	}

	return resource, annos, nil
}

func getApp(ctx context.Context, client *oktav5.APIClient, appID string) (*oktav5.Application, *oktav5.APIResponse, error) {
	app, resp, err := client.ApplicationAPI.GetApplication(ctx, appID).Execute()
	if err != nil {
		return nil, resp, fmt.Errorf("okta-connectorv2: failed to fetch app from okta: %w", err)
	}

	oktaApp, err := oktaAppToOktaApplicationV5(ctx, *app)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: error converting okta app to application: %w", err)
	}

	return oktaApp, resp, nil
}
