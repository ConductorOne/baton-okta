package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/ratelimit"
	sdkEntitlement "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	sdkGrant "github.com/conductorone/baton-sdk/pkg/types/grant"
	sdkResource "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"go.uber.org/zap"
)

type appResourceType struct {
	resourceType     *v2.ResourceType
	domain           string
	apiToken         string
	syncInactiveApps bool
	skipAppGroups    bool
	userEmailFilters []string
	client           *okta.Client
}

const (
	appGrantGroup = "group"
	appGrantUser  = "user"

	// Okta reports how each app assignment was conferred: USER for a direct
	// assignment, GROUP for one derived from group membership.
	appUserScopeGroup = "GROUP"

	// expandGroup asks Okta to embed the assigned group in the app group
	// assignment response, which is the only way to read its type without a
	// per-group lookup.
	expandGroup = "group"

	// appGrantUnsyncedMarker is appended to a phase's pagination ResourceID to
	// carry "this app is assigned a group that was not synced" from the group
	// pass to the user pass.
	appGrantUnsyncedMarker = "unsynced"
)

// appGrantPhaseID builds the pagination ResourceID for a phase, tagging it when
// the app has a group source that was not synced.
func appGrantPhaseID(phase string, unsyncedGroupSource bool) string {
	if unsyncedGroupSource {
		return phase + ":" + appGrantUnsyncedMarker
	}
	return phase
}

// parseAppGrantPhaseID splits a pagination ResourceID back into its phase and
// the unsynced-group-source marker. A token written before the marker existed
// parses as an untagged phase.
func parseAppGrantPhaseID(resourceID string) (string, bool) {
	phase, marker, tagged := strings.Cut(resourceID, ":")
	return phase, tagged && marker == appGrantUnsyncedMarker
}

func (o *appResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func appBuilder(domain string, apiToken string, syncInactiveApps bool, skipAppGroups bool, filterEmailDomains []string, client *okta.Client) *appResourceType {
	return &appResourceType{
		resourceType:     resourceTypeApp,
		domain:           domain,
		apiToken:         apiToken,
		client:           client,
		syncInactiveApps: syncInactiveApps,
		skipAppGroups:    skipAppGroups,
		userEmailFilters: filterEmailDomains,
	}
}

func (o *appResourceType) List(
	ctx context.Context,
	resourceID *v2.ResourceId,
	attrs sdkResource.SyncOpAttrs,
) ([]*v2.Resource, *sdkResource.SyncOpResults, error) {
	token := &attrs.PageToken
	bag, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeUser.Id})
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	var rv []*v2.Resource
	qp := queryParams(token.Size, page)
	apps, respCtx, err := listApps(ctx, o.client, o.syncInactiveApps, token, qp)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to list users: %w", err)
	}

	nextPage, annos, err := parseResp(respCtx.OktaResponse)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
	}

	for _, app := range apps {
		resource, err := appResource(app)
		if err != nil {
			return nil, nil, err
		}

		rv = append(rv, resource)
	}

	pageToken, err := bag.Marshal()
	if err != nil {
		return nil, nil, err
	}

	return rv, &sdkResource.SyncOpResults{NextPageToken: pageToken, Annotations: annos}, nil
}

func (o *appResourceType) Entitlements(
	ctx context.Context,
	resource *v2.Resource,
	attrs sdkResource.SyncOpAttrs,
) ([]*v2.Entitlement, *sdkResource.SyncOpResults, error) {
	var rv []*v2.Entitlement
	rv = append(rv, sdkEntitlement.NewAssignmentEntitlement(resource, "access",
		sdkEntitlement.WithDisplayName(fmt.Sprintf("%s App Access", resource.DisplayName)),
		sdkEntitlement.WithDescription(fmt.Sprintf("Has access to the %s app in Okta", resource.DisplayName)),
		sdkEntitlement.WithAnnotation(&v2.V1Identifier{
			Id: V1MembershipEntitlementID(resource.Id.GetResource()),
		}),
	))

	return rv, nil, nil
}

func (o *appResourceType) Grants(
	ctx context.Context,
	resource *v2.Resource,
	attrs sdkResource.SyncOpAttrs,
) ([]*v2.Grant, *sdkResource.SyncOpResults, error) {
	token := &attrs.PageToken
	var (
		rv    []*v2.Grant
		annos annotations.Annotations
	)
	bag, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeUser.Id})
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	phase, unsyncedGroupSource := parseAppGrantPhaseID(bag.ResourceID())
	switch phase {
	case "":
		bag.Pop()
		// Only the group phase is queued here. It pushes the user phase itself
		// once it has paged every assignment, so the state it pushes can carry
		// whether this app has a group source the sync dropped.
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceTypeApp.Id,
			ResourceID:     appGrantGroup,
		})
	case appGrantGroup:
		rv, annos, bag, err = o.listAppGroupGrants(ctx, resource, token, bag, page, unsyncedGroupSource)
		if err != nil {
			return nil, nil, err
		}
	case appGrantUser:
		rv, annos, bag, err = o.listAppUsersGrants(ctx, resource, token, bag, page, unsyncedGroupSource)
		if err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, fmt.Errorf("okta-connectorv2: unexpected resource for app: %s", bag.ResourceID())
	}

	pageToken, err := bag.Marshal()
	if err != nil {
		return nil, nil, err
	}

	return rv, &sdkResource.SyncOpResults{NextPageToken: pageToken, Annotations: annos}, nil
}

func (o *appResourceType) listAppGroupGrants(
	ctx context.Context,
	resource *v2.Resource,
	token *pagination.Token,
	bag *pagination.Bag,
	page string,
	unsyncedGroupSource bool,
) ([]*v2.Grant, annotations.Annotations, *pagination.Bag, error) {
	l := ctxzap.Extract(ctx)
	var rv []*v2.Grant
	appID := resource.Id.GetResource()
	// The embedded group is only read to tell a dropped APP_GROUP from a synced
	// one, which only matters under skip-app-groups. Requesting it otherwise
	// pulls a full group object per assignment -- up to defaultLimit of them per
	// page -- and discards every one.
	qp := queryParams(token.Size, page)
	if o.skipAppGroups {
		qp = queryParamsExpand(token.Size, page, expandGroup)
	}
	applicationGroupAssignments, respCtx, err := listApplicationGroupAssignments(ctx, o.client, appID, token, qp)
	if err != nil {
		return nil, nil, bag, err
	}

	nextPage, annos, err := parseResp(respCtx.OktaResponse)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
	}

	for _, applicationGroupAssignment := range applicationGroupAssignments {
		groupID := applicationGroupAssignment.Id
		groupType, groupTypeKnown := appGroupAssignmentGroupType(applicationGroupAssignment)

		// The group syncer drops APP_GROUP resources when skip-app-groups is
		// set, so the platform has nothing to expand this grant into. Record
		// that and let the user pass keep emitting direct grants, which is the
		// pre-existing behavior, rather than dropping the access entirely.
		// An unreadable group type is treated the same way: without proof that
		// the group was synced, suppressing the direct grant is not safe.
		if o.skipAppGroups && (!groupTypeKnown || groupType == appGroupType) {
			l.Debug("okta-connectorv2: app has a group source that was not synced; keeping direct app user grants",
				zap.String("app_id", appID),
				zap.String("group_id", groupID),
				zap.String("group_type", groupType),
				zap.Bool("group_type_known", groupTypeKnown),
			)
			unsyncedGroupSource = true

			// Only skip the grant itself when the group is known to have been
			// dropped; emitting it would point at a resource that never synced.
			if groupTypeKnown {
				continue
			}
		}

		principalID := &v2.ResourceId{ResourceType: resourceTypeGroup.Id, Resource: groupID}
		grantOpts := []sdkGrant.GrantOption{
			sdkGrant.WithAnnotation(
				&v2.V1Identifier{
					Id: fmtGrantIdV1(V1MembershipEntitlementID(resource.Id.Resource), groupID),
				},
			),
		}

		// Reaching here with an unreadable type under skip-app-groups means the
		// group may be an APP_GROUP the group syncer dropped. Pointing the
		// expansion at an entitlement that was never synced would add a
		// dangling edge on top of the dangling principal; the direct grants the
		// marker keeps already carry that access, so degrade to no attribution
		// rather than attribution to something that does not exist. The type is
		// only read under the flag, so with it off this always attaches.
		if groupTypeKnown || !o.skipAppGroups {
			grantOpts = append(grantOpts, sdkGrant.WithAnnotation(&v2.GrantExpandable{
				EntitlementIds: []string{fmt.Sprintf("group:%s:member", groupID)},
				Shallow:        true,
			}))
		}

		rv = append(rv, sdkGrant.NewGrant(resource, "access", principalID, grantOpts...))
	}

	// Advance by hand instead of bag.Next: the marker has to ride on the state
	// being pushed, and Next only carries the page token forward. Once the
	// assignments are exhausted the user phase is queued in the group phase's
	// place, tagged with what this pass learned.
	//
	// A sync resuming on a pre-marker token runs the user phase a second time:
	// the old code queued both phases up front and ran user first, so by the
	// time the group phase lands here the stack is empty and the earlier pass
	// is undetectable. The replay re-emits identical grant ids, so it is an
	// idempotent upsert that costs one extra page-through per in-flight app and
	// stops after the first sync on the new token shape.
	bag.Pop()
	if nextPage != "" {
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceTypeApp.Id,
			ResourceID:     appGrantPhaseID(appGrantGroup, unsyncedGroupSource),
			Token:          nextPage,
		})
	} else {
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceTypeApp.Id,
			ResourceID:     appGrantPhaseID(appGrantUser, unsyncedGroupSource),
		})
	}

	return rv, annos, bag, nil
}

// appGroupAssignmentGroupType reads the assigned group's type out of the group
// Okta embeds when the assignment is fetched with expand=group. The second
// return reports whether the type could be determined at all; Okta omits the
// embed when the expand is unsupported or the caller lacks group read access.
func appGroupAssignmentGroupType(assignment *okta.ApplicationGroupAssignment) (string, bool) {
	if assignment.Embedded == nil {
		return "", false
	}

	embeddedMap, ok := assignment.Embedded.(map[string]interface{})
	if !ok {
		return "", false
	}

	groupMap, ok := embeddedMap["group"].(map[string]interface{})
	if !ok {
		return "", false
	}

	groupType, ok := groupMap["type"].(string)
	if !ok || groupType == "" {
		return "", false
	}

	return groupType, true
}

func (o *appResourceType) listAppUsersGrants(
	ctx context.Context,
	resource *v2.Resource,
	token *pagination.Token,
	bag *pagination.Bag,
	page string,
	unsyncedGroupSource bool,
) ([]*v2.Grant, annotations.Annotations, *pagination.Bag, error) {
	l := ctxzap.Extract(ctx)
	var rv []*v2.Grant
	appID := resource.Id.GetResource()
	qp := queryParams(token.Size, page)
	applicationUsers, respCtx, err := listApplicationUsers(ctx, o.client, appID, token, qp)
	if err != nil {
		return nil, nil, bag, err
	}

	nextPage, annos, err := parseResp(respCtx.OktaResponse)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
	}

	// When a group conferring access to this app was not synced, expansion
	// cannot reattribute the affected users, so every app user keeps a direct
	// grant. Correct source attribution is worth less than not losing access.
	// The group pass is the only writer of this marker, and only sets it under
	// skip-app-groups, so no extra flag check is needed here.
	keepGroupScopedUsers := unsyncedGroupSource

	for _, applicationUser := range applicationUsers {
		// for okta v2, we only attempt to filter app users by email domains when a list is provided
		if len(o.userEmailFilters) > 0 && !shouldIncludeOktaAppUser(applicationUser, o.userEmailFilters) {
			continue
		}

		groupScoped := strings.EqualFold(applicationUser.Scope, appUserScopeGroup)

		// Group-derived access is modeled as a group grant the platform expands,
		// which records the group as the source. Emitting a user grant here as
		// well would report that same access as a direct assignment.
		if !keepGroupScopedUsers && groupScoped {
			l.Debug("okta-connectorv2: skipping group-scoped app user; access is granted through the group",
				zap.String("app_id", appID),
				zap.String("user_id", applicationUser.Id),
			)
			continue
		}

		userID := applicationUser.Id
		principalID := &v2.ResourceId{ResourceType: resourceTypeUser.Id, Resource: userID}
		grantOpts := []sdkGrant.GrantOption{
			sdkGrant.WithAnnotation(
				&v2.V1Identifier{
					Id: fmtGrantIdV1(V1MembershipEntitlementID(resource.Id.Resource), userID),
				},
			),
		}

		// Reaching here while group-scoped means the conferring group was not
		// synced, so no group membership exists for a reviewer to act on. Okta
		// refuses a direct unassign for a group-scoped assignment, so the grant
		// is not really revocable; mark it rather than implying it is.
		if groupScoped {
			grantOpts = append(grantOpts, sdkGrant.WithAnnotation(&v2.GrantImmutable{}))
		}

		rv = append(rv, sdkGrant.NewGrant(resource, "access", principalID, grantOpts...))
	}

	return rv, annos, bag, nil
}

func listApps(ctx context.Context, client *okta.Client, syncInactiveApps bool, token *pagination.Token, qp *query.Params) ([]*okta.Application, *responseContext, error) {
	if !syncInactiveApps {
		qp.Filter = "status eq \"ACTIVE\""
	}

	apps, resp, err := client.Application.ListApplications(ctx, qp)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch apps from okta: %w", handleOktaResponseError(resp, err))
	}

	reqCtx, err := responseToContext(token, resp)
	if err != nil {
		return nil, nil, err
	}

	applications, err := oktaAppsToOktaApplications(apps)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: error converting okta apps to applications: %w", err)
	}

	return applications, reqCtx, nil
}

func listApplicationGroupAssignments(ctx context.Context, client *okta.Client, appID string, token *pagination.Token, qp *query.Params) ([]*okta.ApplicationGroupAssignment, *responseContext, error) {
	applicationGroupAssignments, resp, err := client.Application.ListApplicationGroupAssignments(ctx, appID, qp)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch app group assignments from okta: %w", handleOktaResponseError(resp, err))
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
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch app users from okta: %w", handleOktaResponseError(resp, err))
	}

	reqCtx, err := responseToContext(token, resp)
	if err != nil {
		return nil, nil, err
	}

	return applicationUsers, reqCtx, nil
}

func oktaAppsToOktaApplications(apps []okta.App) ([]*okta.Application, error) {
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

func oktaAppToOktaApplication(app okta.App) (*okta.Application, error) {
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

// nhiExcludedSignOnModes are the Okta app sign-on modes that are not non-human
// identity app-registrations: BOOKMARK apps are link launchers and the SWA
// family are human-facing password-fill apps, neither of which holds machine
// credentials. Values match the okta-sdk-golang/v2 app constructors
// (bookmarkApplication.go, swaApplication.go, autoLoginApplication.go,
// basicAuthApplication.go, securePasswordStoreApplication.go).
var nhiExcludedSignOnModes = map[string]struct{}{
	"BOOKMARK":              {},
	"BROWSER_PLUGIN":        {},
	"AUTO_LOGIN":            {},
	"BASIC_AUTH":            {},
	"SECURE_PASSWORD_STORE": {},
}

// nhiAppDetail returns the RFC §2.8 axis-2 detail (<platform>.<object>.<purpose>,
// dotted lowercase) for an app sign-on mode, and whether the app is an NHI
// app-registration at all. BOOKMARK and SWA apps are excluded.
func nhiAppDetail(signOnMode string) (string, bool) {
	if _, excluded := nhiExcludedSignOnModes[signOnMode]; excluded {
		return "", false
	}
	if signOnMode == "" {
		return "okta.app", true
	}
	return "okta.app." + strings.ToLower(signOnMode), true
}

func appResource(app *okta.Application) (*v2.Resource, error) {
	appProfile := map[string]interface{}{
		"status": app.Status,
	}
	var appTraitOpts []sdkResource.AppTraitOption

	resourceOpts := []sdkResource.ResourceOption{
		sdkResource.WithResourceProfile(appProfile),
		sdkResource.WithAnnotation(&v2.V1Identifier{Id: fmtResourceIdV1(app.Id)}),
		sdkResource.WithAnnotation(&v2.RawId{Id: app.Id}),
	}
	if detail, ok := nhiAppDetail(app.SignOnMode); ok {
		resourceOpts = append(resourceOpts,
			sdkResource.WithNHIType(v2.NonHumanIdentityTrait_NHI_TYPE_APP_REGISTRATION, detail))
	}

	return sdkResource.NewAppResource(app.Label, resourceTypeApp, app.Id, appTraitOpts, resourceOpts...)
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
			if response == nil {
				l.Warn("okta-connector: failed to fetch application user, nil response",
					zap.String("app_id", appID), zap.String("user_id", userID), zap.Error(err))
				return nil, fmt.Errorf("okta-connector: failed to fetch application user: %s", err.Error())
			}
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
		if email, ok = profile[profileFieldEmail].(string); !ok {
			email = unknownProfileValue
		}

		payload := okta.AppUser{
			Credentials: &okta.AppUserCredentials{
				UserName: email,
			},
			Id:    userID,
			Scope: strings.ToUpper(principal.Id.ResourceType),
		}
		assignedUser, _, err := g.client.Application.AssignUserToApplication(ctx, appID, payload)
		if err != nil {
			l.Warn(
				"okta-connector: The app specified cannot be assigned to the user",
				zap.String("principal_id", principal.Id.String()),
				zap.String("principal_type", principal.Id.ResourceType),
			)
			return nil, fmt.Errorf("okta-connector: The app specified cannot be assigned to the user %s",
				err.Error())
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
			if response == nil {
				l.Warn("okta-connector: failed to fetch application group assignment, nil response",
					zap.String("app_id", appID), zap.String("group_id", groupID), zap.Error(err))
				return nil, fmt.Errorf("okta-connector: failed to fetch application group assignment: %s", err.Error())
			}
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
			return nil, fmt.Errorf("okta-connector: failed to remove user from application: %s", err.Error())
		}

		if response != nil && response.StatusCode == http.StatusNoContent {
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
			return nil, fmt.Errorf("okta-connector: failed to remove group from application: %s", err.Error())
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

func (o *appResourceType) Get(ctx context.Context, resourceId *v2.ResourceId, parentResourceId *v2.ResourceId) (*v2.Resource, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	l.Debug("getting app", zap.String("app_id", resourceId.Resource))

	var annos annotations.Annotations

	app, respCtx, err := getApp(ctx, o.client, resourceId.Resource)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to get application: %w", err)
	}

	resp := respCtx.OktaResponse
	if desc, err := ratelimit.ExtractRateLimitData(resp.StatusCode, &resp.Header); err == nil {
		annos.WithRateLimiting(desc)
	}

	if app == nil {
		return nil, annos, nil
	}

	if !o.syncInactiveApps && app.Status != "ACTIVE" {
		return nil, annos, nil
	}

	resource, err := appResource(app)
	if err != nil {
		return nil, annos, err
	}

	return resource, annos, nil
}

func getApp(ctx context.Context, client *okta.Client, appID string) (*okta.Application, *responseContext, error) {
	app, resp, err := client.Application.GetApplication(ctx, appID, okta.NewApplication(), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch app from okta: %w", handleOktaResponseError(resp, err))
	}

	reqCtx := &responseContext{OktaResponse: resp}

	oktaApp, err := oktaAppToOktaApplication(app)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: error converting okta app to application: %w", err)
	}

	return oktaApp, reqCtx, nil
}
