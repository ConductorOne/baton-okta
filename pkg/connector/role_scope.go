package connector

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/session"
	sdkEntitlement "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	sdkGrant "github.com/conductorone/baton-sdk/pkg/types/grant"
	"github.com/conductorone/baton-sdk/pkg/types/sessions"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	roleEntitlementAssigned = "assigned"
	// Granted on the role resource when a scopable role assignment has no targets.
	roleEntitlementEntireOrg = "entire-organization"

	roleTargetKindGroup = "group"
	roleTargetKindApp   = "app"

	roleTargetsPageLimit = 100

	// Okta's assignmentType for a role assigned directly to a user, as opposed
	// to one inherited through group membership.
	roleAssignmentTypeUser = "USER"
)

type scopedRoleType struct {
	roleType   string
	targetKind string
	// Entitlement slug on the target group or app resource.
	targetSlug string
}

// scopedRoleTypes are the standard admin roles that Okta lets an admin constrain
// to specific groups or apps. An assignment with no targets applies to the entire
// organization; the Okta admin console labels that "Entire organization". Custom
// roles are scoped through resource sets instead (see resource_sets_bindings.go),
// and Okta does not allow binding a standard role to a resource set.
var scopedRoleTypes = []scopedRoleType{
	{roleType: "USER_ADMIN", targetKind: roleTargetKindGroup, targetSlug: "group-admin"},
	{roleType: "HELP_DESK_ADMIN", targetKind: roleTargetKindGroup, targetSlug: "help-desk-admin"},
	{roleType: "GROUP_MEMBERSHIP_ADMIN", targetKind: roleTargetKindGroup, targetSlug: "group-membership-admin"},
	{roleType: "APP_ADMIN", targetKind: roleTargetKindApp, targetSlug: "app-admin"},
}

func scopedRoleFromType(roleType string) (scopedRoleType, bool) {
	for _, sr := range scopedRoleTypes {
		if sr.roleType == roleType {
			return sr, true
		}
	}
	return scopedRoleType{}, false
}

func scopedRolesForTargetKind(kind string) []scopedRoleType {
	var rv []scopedRoleType
	for _, sr := range scopedRoleTypes {
		if sr.targetKind == kind {
			rv = append(rv, sr)
		}
	}
	return rv
}

func isRoleScopeTargetSlug(slug string) bool {
	for _, sr := range scopedRoleTypes {
		if sr.targetSlug == slug {
			return true
		}
	}
	return false
}

// isRoleScopeTargetEntitlement reports whether e is one of the review-only group
// or app scope entitlements. It fails closed: C1 lets admins edit an
// entitlement's slug, so a match on either the immutable connector ID suffix or
// the slug counts.
func isRoleScopeTargetEntitlement(e *v2.Entitlement) bool {
	return isRoleScopeTargetSlug(entitlementIDSlug(e)) || isRoleScopeTargetSlug(e.GetSlug())
}

// isEntireOrgEntitlement matches on the connector ID suffix, which C1 does not
// let admins edit, and falls back to the slug only when the ID is absent.
func isEntireOrgEntitlement(e *v2.Entitlement) bool {
	if e.GetId() != "" {
		return entitlementIDSlug(e) == roleEntitlementEntireOrg
	}
	return e.GetSlug() == roleEntitlementEntireOrg
}

// entitlementIDSlug returns the slug segment of a connector entitlement ID
// (<resource type>:<resource id>:<slug>), or "" when the ID does not have that shape.
func entitlementIDSlug(e *v2.Entitlement) string {
	rid := e.GetResource().GetId()
	prefix := rid.GetResourceType() + ":" + rid.GetResource() + ":"
	if rest, ok := strings.CutPrefix(e.GetId(), prefix); ok {
		return rest
	}
	return ""
}

func roleScopeLabel(roleType string) string {
	if role := standardRoleFromType(roleType); role != nil {
		return role.Label
	}
	return roleType
}

func entireOrgRoleEntitlement(resource *v2.Resource, role *okta.Role) *v2.Entitlement {
	return sdkEntitlement.NewAssignmentEntitlement(resource, roleEntitlementEntireOrg,
		sdkEntitlement.WithDisplayName(fmt.Sprintf("%s (Entire organization)", role.Label)),
		sdkEntitlement.WithDescription(fmt.Sprintf("Has the %s role in Okta constrained to the entire organization", role.Label)),
		sdkEntitlement.WithGrantableTo(resourceTypeUser, resourceTypeGroup),
	)
}

func roleScopeTargetEntitlements(resource *v2.Resource, kind string) []*v2.Entitlement {
	srs := scopedRolesForTargetKind(kind)
	rv := make([]*v2.Entitlement, 0, len(srs))
	for _, sr := range srs {
		label := roleScopeLabel(sr.roleType)
		rv = append(rv, sdkEntitlement.NewAssignmentEntitlement(resource, sr.targetSlug,
			sdkEntitlement.WithDisplayName(fmt.Sprintf("%s %s", resource.DisplayName, label)),
			sdkEntitlement.WithDescription(fmt.Sprintf("Has the %s role in Okta constrained to the %s %s", label, resource.DisplayName, kind)),
			sdkEntitlement.WithGrantableTo(resourceTypeUser, resourceTypeGroup),
		))
	}
	return rv
}

func roleScopeTargetNotProvisionable(e *v2.Entitlement) error {
	return status.Errorf(codes.Unimplemented,
		"okta-connector: %s is synced for review only; change admin role resources in Okta", e.GetId())
}

// roleTargets is what an admin role assignment is constrained to. Both empty means
// the entire organization.
type roleTargets struct {
	groups []*okta.Group
	apps   []*okta.CatalogApplication
}

func (t roleTargets) isEntireOrg() bool {
	return len(t.groups) == 0 && len(t.apps) == 0
}

type rolePrincipal struct {
	resourceType string
	id           string
}

func (p rolePrincipal) apiPath() string {
	if p.resourceType == resourceTypeGroup.Id {
		return groupsUrl
	}
	return usersUrl
}

// listRoleTargets lists what a role assignment is constrained to. fresh bypasses
// the client's response cache on every page; Grant and Revoke need it because a
// cached "no targets" answer would let them act on an assignment that has since
// been narrowed.
func (o *Okta) listRoleTargets(ctx context.Context, principal rolePrincipal, assignmentID string, sr scopedRoleType, fresh bool) (roleTargets, error) {
	var suffix string
	switch sr.targetKind {
	case roleTargetKindGroup:
		suffix = "groups"
	case roleTargetKindApp:
		suffix = "catalog/apps"
	default:
		return roleTargets{}, fmt.Errorf("okta-connector: unknown role target kind %q", sr.targetKind)
	}
	apiPath, err := url.JoinPath(principal.apiPath(), principal.id, "roles", assignmentID, "targets", suffix)
	if err != nil {
		return roleTargets{}, err
	}
	reqURL := apiPath + query.NewQueryParams(query.WithLimit(roleTargetsPageLimit)).String()

	var rv roleTargets
	for reqURL != "" {
		rq := o.client.CloneRequestExecutor()
		if fresh {
			rq.RefreshNext()
		}
		req, err := rq.WithAccept(ContentType).WithContentType(ContentType).NewRequest(http.MethodGet, reqURL, nil)
		if err != nil {
			return roleTargets{}, err
		}

		var resp *okta.Response
		switch sr.targetKind {
		case roleTargetKindGroup:
			var page []*okta.Group
			resp, err = rq.Do(ctx, req, &page)
			rv.groups = append(rv.groups, page...)
		case roleTargetKindApp:
			var page []*okta.CatalogApplication
			resp, err = rq.Do(ctx, req, &page)
			rv.apps = append(rv.apps, page...)
		}
		if err != nil {
			return roleTargets{}, fmt.Errorf("okta-connector: failed to list %s targets of %s role assignment %s for %s %s: %w",
				sr.targetKind, sr.roleType, assignmentID, principal.resourceType, principal.id, handleOktaResponseError(resp, err))
		}
		reqURL = ""
		if resp != nil {
			reqURL = resp.NextPage
		}
	}
	return rv, nil
}

var catalogAppInstancesPrefix = sessions.WithPrefix("catalogAppInstances")

// catalogAppInstanceIDs resolves an OIN catalog app target, which covers every
// instance of that app, to the app instance IDs in the org.
func (o *Okta) catalogAppInstanceIDs(ctx context.Context, ss sessions.SessionStore, appName string) ([]string, error) {
	if ss != nil {
		ids, found, err := session.GetJSON[[]string](ctx, ss, appName, catalogAppInstancesPrefix)
		if err == nil && found {
			return ids, nil
		}
	}

	var ids []string
	after := ""
	for {
		qp := query.NewQueryParams(
			query.WithFilter(fmt.Sprintf("name eq %q", appName)),
			query.WithLimit(defaultLimit),
		)
		if after != "" {
			qp.After = after
		}
		apps, resp, err := o.client.Application.ListApplications(ctx, qp)
		if err != nil {
			return nil, fmt.Errorf("okta-connector: failed to list instances of catalog app %q: %w", appName, handleOktaResponseError(resp, err))
		}
		converted, err := oktaAppsToOktaApplications(apps)
		if err != nil {
			return nil, fmt.Errorf("okta-connector: failed to decode instances of catalog app %q: %w", appName, err)
		}
		for _, app := range converted {
			// Matches the app syncer: grants on an app resource that was never
			// synced would be dropped anyway.
			if !o.syncInactiveApps && app.Status != "ACTIVE" {
				continue
			}
			ids = append(ids, app.Id)
		}
		after, _, err = parseResp(resp)
		if err != nil {
			return nil, fmt.Errorf("okta-connector: failed to parse instances page of catalog app %q: %w", appName, err)
		}
		if after == "" {
			break
		}
	}

	if ss != nil {
		if err := session.SetJSON(ctx, ss, appName, ids, catalogAppInstancesPrefix); err != nil {
			ctxzap.Extract(ctx).Debug("failed to cache catalog app instances", zap.Error(err))
		}
	}
	return ids, nil
}

// roleScopeGrants emits grants describing what one scopable admin role assignment
// is constrained to: the role's entire-organization entitlement when it has no
// targets, otherwise the matching admin entitlement on each target group or app.
func (o *Okta) roleScopeGrants(
	ctx context.Context,
	ss sessions.SessionStore,
	principal rolePrincipal,
	assignmentID string,
	sr scopedRoleType,
	grantOpts ...sdkGrant.GrantOption,
) ([]*v2.Grant, error) {
	targets, err := o.listRoleTargets(ctx, principal, assignmentID, sr, false)
	if err != nil {
		// The assignment was removed after it was listed. Failing here would
		// drop every other grant on this page, so emit no scope for it.
		if status.Code(err) == codes.NotFound {
			ctxzap.Extract(ctx).Debug("okta-connector: role assignment disappeared while listing its targets",
				zap.String("role_type", sr.roleType),
				zap.String("principal_type", principal.resourceType),
				zap.String("principal_id", principal.id),
			)
			return nil, nil
		}
		return nil, err
	}

	pr := &v2.Resource{Id: &v2.ResourceId{ResourceType: principal.resourceType, Resource: principal.id}}

	if targets.isEntireOrg() {
		roleRes := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeRole.Id, Resource: sr.roleType}}
		return []*v2.Grant{sdkGrant.NewGrant(roleRes, roleEntitlementEntireOrg, pr, grantOpts...)}, nil
	}

	seen := make(map[string]struct{})
	var rv []*v2.Grant
	add := func(resourceType, id string) {
		if _, ok := seen[id]; ok {
			return
		}
		seen[id] = struct{}{}
		target := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceType, Resource: id}}
		rv = append(rv, sdkGrant.NewGrant(target, sr.targetSlug, pr, grantOpts...))
	}

	for _, g := range targets.groups {
		// Matches the group syncer, which never emits these groups.
		if o.skipAppGroups && g.Type == appGroupType {
			continue
		}
		add(resourceTypeGroup.Id, g.Id)
	}
	for _, app := range targets.apps {
		// App instance targets carry the instance ID; catalog targets only name
		// the OIN app and cover all of its instances.
		if app.Id != "" {
			add(resourceTypeApp.Id, app.Id)
			continue
		}
		if app.Name == "" {
			continue
		}
		ids, err := o.catalogAppInstanceIDs(ctx, ss, app.Name)
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			add(resourceTypeApp.Id, id)
		}
	}
	return rv, nil
}

var userRoleAssignmentPrefix = sessions.WithPrefix("userRoleAssignment")

// userRoleAssignmentIDs maps a user's directly assigned, active standard role
// types to their role assignment IDs.
func (o *Okta) userRoleAssignmentIDs(ctx context.Context, ss sessions.SessionStore, userID string) (map[string]string, error) {
	if ss != nil {
		ids, found, err := session.GetJSON[map[string]string](ctx, ss, userID, userRoleAssignmentPrefix)
		if err == nil && found {
			return ids, nil
		}
	}

	roles, resp, err := listAssignedRolesForUser(ctx, o.client, userID)
	if err != nil {
		return nil, fmt.Errorf("okta-connector: failed to list roles for user: %w", handleOktaResponseError(resp, err))
	}
	ids := standardRoleAssignmentIDs(roles, roleAssignmentTypeUser)
	if ss != nil {
		if err := session.SetJSON(ctx, ss, userID, ids, userRoleAssignmentPrefix); err != nil {
			ctxzap.Extract(ctx).Debug("failed to cache user role assignments", zap.Error(err))
		}
	}
	return ids, nil
}

func standardRoleAssignmentIDs(roles []*Roles, assignmentType string) map[string]string {
	ids := make(map[string]string)
	for _, role := range roles {
		if role.Status == roleStatusInactive || role.AssignmentType != assignmentType || role.Type == roleTypeCustom {
			continue
		}
		ids[role.Type] = role.Id
	}
	return ids
}
