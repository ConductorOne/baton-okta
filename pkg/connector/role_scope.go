package connector

import (
	"context"
	"fmt"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/session"
	sdkEntitlement "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	sdkGrant "github.com/conductorone/baton-sdk/pkg/types/grant"
	"github.com/conductorone/baton-sdk/pkg/types/sessions"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Standard admin roles that Okta lets an admin constrain to specific groups or
// apps. An assignment with no targets applies to the entire organization; the
// Okta admin console labels that "Entire organization". Custom roles are scoped
// through resource sets instead (see resource_sets_bindings.go), and Okta does
// not allow binding a standard role to a resource set.

const (
	roleEntitlementAssigned = "assigned"
	// Granted on the role resource when a scopable role assignment has no targets.
	roleEntitlementEntireOrg = "entire-organization"

	roleTargetKindGroup = "group"
	roleTargetKindApp   = "app"

	roleTargetsPageLimit = 100
)

type scopedRoleType struct {
	roleType   string
	targetKind string
	// Entitlement slug on the target group or app resource.
	targetSlug string
}

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

// entitlementSlug returns the entitlement's slug, falling back to the suffix of
// its ID when the caller did not populate Slug.
func entitlementSlug(e *v2.Entitlement) string {
	if slug := e.GetSlug(); slug != "" {
		return slug
	}
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

func roleScopeTargetNotProvisionable(slug string) error {
	return status.Errorf(codes.Unimplemented,
		"okta-connector: %s is synced for review only; change admin role resources in Okta", slug)
}

// roleTargets is what an admin role assignment is constrained to. Both empty means
// the entire organization.
type roleTargets struct {
	groupIDs []string
	apps     []*okta.CatalogApplication
}

func (t roleTargets) isEntireOrg() bool {
	return len(t.groupIDs) == 0 && len(t.apps) == 0
}

type rolePrincipal struct {
	resourceType string
	id           string
}

func (o *Okta) listRoleTargets(ctx context.Context, principal rolePrincipal, assignmentID string, sr scopedRoleType) (roleTargets, error) {
	qp := query.NewQueryParams(query.WithLimit(roleTargetsPageLimit))
	var (
		rv   roleTargets
		resp *okta.Response
		err  error
	)
	switch sr.targetKind {
	case roleTargetKindGroup:
		var groups []*okta.Group
		if principal.resourceType == resourceTypeGroup.Id {
			groups, resp, err = o.client.Group.ListGroupTargetsForGroupRole(ctx, principal.id, assignmentID, qp)
		} else {
			groups, resp, err = o.client.User.ListGroupTargetsForRole(ctx, principal.id, assignmentID, qp)
		}
		for {
			if err != nil {
				return roleTargets{}, fmt.Errorf("okta-connector: failed to list group targets for %s role: %w", sr.roleType, handleOktaResponseError(resp, err))
			}
			for _, g := range groups {
				rv.groupIDs = append(rv.groupIDs, g.Id)
			}
			if resp == nil || !resp.HasNextPage() {
				break
			}
			groups = nil
			resp, err = resp.Next(ctx, &groups)
		}
	case roleTargetKindApp:
		var apps []*okta.CatalogApplication
		if principal.resourceType == resourceTypeGroup.Id {
			apps, resp, err = o.client.Group.ListApplicationTargetsForApplicationAdministratorRoleForGroup(ctx, principal.id, assignmentID, qp)
		} else {
			apps, resp, err = o.client.User.ListApplicationTargetsForApplicationAdministratorRoleForUser(ctx, principal.id, assignmentID, qp)
		}
		for {
			if err != nil {
				return roleTargets{}, fmt.Errorf("okta-connector: failed to list app targets for %s role: %w", sr.roleType, handleOktaResponseError(resp, err))
			}
			rv.apps = append(rv.apps, apps...)
			if resp == nil || !resp.HasNextPage() {
				break
			}
			apps = nil
			resp, err = resp.Next(ctx, &apps)
		}
	default:
		return roleTargets{}, fmt.Errorf("okta-connector: unknown role target kind %q", sr.targetKind)
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
			return nil, err
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
			return nil, err
		}
		if after == "" {
			break
		}
	}

	if ss != nil {
		_ = session.SetJSON(ctx, ss, appName, ids, catalogAppInstancesPrefix)
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
	targets, err := o.listRoleTargets(ctx, principal, assignmentID, sr)
	if err != nil {
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

	for _, gid := range targets.groupIDs {
		add(resourceTypeGroup.Id, gid)
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
	ids := standardRoleAssignmentIDs(roles, "USER")
	if ss != nil {
		_ = session.SetJSON(ctx, ss, userID, ids, userRoleAssignmentPrefix)
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
