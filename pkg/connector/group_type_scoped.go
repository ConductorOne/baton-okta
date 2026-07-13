package connector

// Type-scoped group grants: source-cache replay validated by Okta's
// lastMembershipUpdated timestamp (dirty-scope model — see
// baton-microsoft-entra/docs/okta-replay-brief.md and the probe results in
// docs/replay-probe-results.md).
//
// Okta has no delta endpoints and no useful ETags, but every group row in
// the ordinary GET /api/v1/groups listing carries lastMembershipUpdated,
// which bumps on every membership change (direct add/remove, rule-driven
// evaluation, user deletion — all probed live). The connector compares
// that value ITSELF against the validator stored by the previous sync:
//
//   - equal     → the group's member grants are REPLAYED (no overlay, no
//                 tombstones), spending zero API requests on the group;
//   - different → the group is dirty and its members are re-enumerated
//                 cold (there are no membership deltas to apply);
//   - missing/empty → cold. Every surprise fails toward cold.
//
// Comparison is per-group EQUALITY against the group's own previous
// value, never "since T" against a clock: Okta's timestamps are Okta's,
// filter results lag writes, and equality is immune to both.
//
// Shape: the group resource type carries TypeScopedGrants, so the SDK
// issues one planning call instead of a per-resource fan-out. Planning
// pages the groups listing (which returns lastMembershipUpdated for free)
// and spawns one cursor per group via SpawnCursors. Each cursor runs two
// legs:
//
//   1. members — replay or cold enumeration as decided above;
//   2. group role assignments — ALWAYS a fresh enumeration. Role
//      assign/revoke changes neither group timestamp (probed live), so
//      the API offers nothing to validate with; per the brief the leg is
//      not forced into the model. This bounds a fully-warm sync at one
//      /groups/{id}/roles request per group.
//
// The per-resource Grants path in group.go remains for targeted syncs.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/sourcecache"
	sdkResource "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"go.uber.org/zap"
)

var _ connectorbuilder.TypeScopedGrantsSyncer = (*groupResourceType)(nil)

const (
	groupCursorPhaseMembers = "m"
	groupCursorPhaseRoles   = "r"

	replayModeWarm = "warm"
	replayModeCold = "cold"
)

// groupGrantsCursor rides the SDK page token. Planning pages carry Plan +
// PlanPage (the groups listing's after-cursor); per-group cursors carry
// the group id, the validator read from the planning listing, the
// users_count stat (nil when the listing's expand=stats was absent), and
// the current leg's phase + after-cursor.
type groupGrantsCursor struct {
	Plan     bool   `json:"p,omitempty"`
	PlanPage string `json:"pp,omitempty"`

	GroupID    string `json:"g,omitempty"`
	Validator  string `json:"v,omitempty"`
	UsersCount *int64 `json:"uc,omitempty"`

	Phase string `json:"ph,omitempty"`
	Page  string `json:"pg,omitempty"`
}

func (t *groupGrantsCursor) marshal() (string, error) {
	b, err := json.Marshal(t)
	if err != nil {
		return "", fmt.Errorf("okta-connectorv2: failed to marshal group grants cursor: %w", err)
	}
	return string(b), nil
}

// scopeSig hashes the request properties that shape a cached row set.
// Any change yields a different scope — a clean lookup miss and a full
// re-enumeration, exactly what an under- or over-filtered cache requires.
func scopeSig(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:8])
}

// memberScope identifies one group's member-grant rows. The signature
// covers the client-side email-domain filter applied during enumeration
// (shouldIncludeUserAndSetCache): a config change must invalidate every
// group's scope. skipAppGroups is deliberately absent — it decides which
// groups get planned at all, not which rows a planned group's scope holds.
func (o *groupResourceType) memberScope(groupID string) string {
	parts := []string{"v1"}
	if o.connector.userFilters != nil && len(o.connector.userFilters.includedEmailDomains) > 0 {
		domains := make([]string, len(o.connector.userFilters.includedEmailDomains))
		copy(domains, o.connector.userFilters.includedEmailDomains)
		sort.Strings(domains)
		parts = append(parts, domains...)
	}
	return fmt.Sprintf("groups/%s/users?sig=%s", groupID, scopeSig(parts...))
}

// groupMembershipValidator formats a group's lastMembershipUpdated as the
// scope validator. Empty (never observed live; every group gets the value
// at creation) means the scope cannot be validated and stays cold.
func groupMembershipValidator(group *okta.Group) string {
	if group.LastMembershipUpdated == nil {
		return ""
	}
	return group.LastMembershipUpdated.UTC().Format(time.RFC3339Nano)
}

// GrantsForResourceType implements connectorbuilder.TypeScopedGrantsSyncer
// for the group type: the planning walk pages the groups listing and
// spawns one cursor per group; each cursor replays or re-enumerates that
// group's member grants and freshly enumerates its role assignments.
func (o *groupResourceType) GrantsForResourceType(
	ctx context.Context,
	resourceTypeID string,
	attrs sdkResource.SyncOpAttrs,
) ([]*v2.Grant, *sdkResource.SyncOpResults, error) {
	if resourceTypeID != resourceTypeGroup.Id {
		return nil, nil, fmt.Errorf("okta-connectorv2: type-scoped grants for unexpected resource type %s", resourceTypeID)
	}

	tok := &groupGrantsCursor{Plan: true}
	if attrs.PageToken.Token != "" {
		tok = &groupGrantsCursor{}
		if err := json.Unmarshal([]byte(attrs.PageToken.Token), tok); err != nil {
			return nil, nil, fmt.Errorf("okta-connectorv2: invalid group grants cursor: %w", err)
		}
	}

	if tok.Plan {
		return o.planGroupCursorsPage(ctx, tok, attrs)
	}
	if tok.GroupID == "" {
		return nil, nil, fmt.Errorf("okta-connectorv2: malformed group grants cursor: missing group id")
	}

	switch tok.Phase {
	case "":
		return o.startGroupCursor(ctx, tok, attrs)
	case groupCursorPhaseMembers:
		return o.coldMembersPage(ctx, tok, attrs)
	case groupCursorPhaseRoles:
		return o.groupRolesPage(ctx, tok, attrs)
	default:
		return nil, nil, fmt.Errorf("okta-connectorv2: malformed group grants cursor: unknown phase %q", tok.Phase)
	}
}

// planGroupCursorsPage processes ONE page of the groups listing and spawns
// a cursor per group carrying (id, lastMembershipUpdated, users_count).
// Planning state never leaves the page token. The listing is the entire
// fixed cost of a warm sync's member legs: expand=stats rides along so the
// users_count==0 shortcut works exactly like the per-resource path.
func (o *groupResourceType) planGroupCursorsPage(
	ctx context.Context,
	tok *groupGrantsCursor,
	attrs sdkResource.SyncOpAttrs,
) ([]*v2.Grant, *sdkResource.SyncOpResults, error) {
	l := ctxzap.Extract(ctx)

	token := newPaginationToken(attrs.PageToken.Size, tok.PlanPage)
	qp := queryParamsExpand(token.Size, tok.PlanPage, "stats")
	groups, respCtx, err := listGroupsHelper(ctx, o.connector.client, token, qp)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: group grants planning page failed: %w", err)
	}

	nextPage, annos, err := parseResp(respCtx.OktaResponse)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
	}

	tokens := make([]string, 0, len(groups))
	for _, group := range groups {
		if o.connector.skipAppGroups && group.Type == appGroupType {
			l.Debug("okta-connectorv2: skipping APP_GROUP type group", zap.String("group_id", group.Id))
			continue
		}
		cursor := &groupGrantsCursor{
			GroupID:   group.Id,
			Validator: groupMembershipValidator(group),
		}
		if usersCount, exists := getGroupUserCount(group); exists {
			uc := int64(usersCount)
			cursor.UsersCount = &uc
		}
		ct, err := cursor.marshal()
		if err != nil {
			return nil, nil, err
		}
		tokens = append(tokens, ct)
	}

	nextToken := ""
	if nextPage != "" {
		nextToken, err = (&groupGrantsCursor{Plan: true, PlanPage: nextPage}).marshal()
		if err != nil {
			return nil, nil, err
		}
	}

	l.Debug("okta-connectorv2: planned group grant cursors (page)",
		zap.Int("groups", len(groups)),
		zap.Int("cursors_spawned", len(tokens)),
		zap.Bool("final_page", nextPage == ""),
	)

	if len(tokens) > 0 {
		annos.Update(&v2.SpawnCursors{PageTokens: tokens})
	}
	return nil, &sdkResource.SyncOpResults{NextPageToken: nextToken, Annotations: annos}, nil
}

// startGroupCursor runs one group cursor's first call: source-cache
// lookup, then either a replay of the member scope (zero API calls) or
// the first page of a cold member enumeration. The roles leg follows
// either way.
func (o *groupResourceType) startGroupCursor(
	ctx context.Context,
	tok *groupGrantsCursor,
	attrs sdkResource.SyncOpAttrs,
) ([]*v2.Grant, *sdkResource.SyncOpResults, error) {
	l := ctxzap.Extract(ctx)
	scope := o.memberScope(tok.GroupID)

	lookup := attrs.SourceCache
	if lookup == nil {
		lookup = sourcecache.NoopLookup{}
	}
	entry, found, err := lookup.LookupPreviousSourceCache(ctx, sourcecache.RowKindGrants, scope)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: group member scope lookup failed: %w", err)
	}

	if found && tok.Validator != "" && entry.ETag == tok.Validator {
		l.Debug("okta-connectorv2: group members scope",
			zap.String("mode", replayModeWarm),
			zap.String("group_id", tok.GroupID),
			zap.String("scope", scope),
		)
		var annos annotations.Annotations
		annos.Update(&v2.SourceCacheReplay{
			ScopeHash: scope,
			Etag:      tok.Validator,
		})
		next, err := (&groupGrantsCursor{
			GroupID:    tok.GroupID,
			UsersCount: tok.UsersCount,
			Phase:      groupCursorPhaseRoles,
		}).marshal()
		if err != nil {
			return nil, nil, err
		}
		return nil, &sdkResource.SyncOpResults{NextPageToken: next, Annotations: annos}, nil
	}

	l.Debug("okta-connectorv2: group members scope",
		zap.String("mode", replayModeCold),
		zap.String("group_id", tok.GroupID),
		zap.String("scope", scope),
		zap.Bool("validator_found", found),
	)
	tok.Phase = groupCursorPhaseMembers
	tok.Page = ""
	return o.coldMembersPage(ctx, tok, attrs)
}

// coldMembersPage serves one page of a group's full member enumeration,
// stamping rows with the member scope. The validator (read from the
// planning listing) is written on the final page; a membership change
// between planning and enumeration stores a validator OLDER than the rows
// it describes, which the next sync sees as dirty — fails toward cold.
func (o *groupResourceType) coldMembersPage(
	ctx context.Context,
	tok *groupGrantsCursor,
	attrs sdkResource.SyncOpAttrs,
) ([]*v2.Grant, *sdkResource.SyncOpResults, error) {
	l := ctxzap.Extract(ctx)
	scope := o.memberScope(tok.GroupID)

	rolesToken, err := (&groupGrantsCursor{
		GroupID:    tok.GroupID,
		UsersCount: tok.UsersCount,
		Phase:      groupCursorPhaseRoles,
	}).marshal()
	if err != nil {
		return nil, nil, err
	}

	// users_count==0 shortcut (parity with the per-resource path): skip
	// the members call. A zero-row page still persists the scope entry,
	// so the group replays next sync if its validator holds.
	if tok.Page == "" && tok.UsersCount != nil && *tok.UsersCount == 0 {
		l.Debug("okta-connectorv2: skipping list group users (users_count is 0)",
			zap.String("group_id", tok.GroupID))
		var annos annotations.Annotations
		annos.Update(&v2.SourceCacheScope{ScopeHash: scope, Etag: tok.Validator})
		return nil, &sdkResource.SyncOpResults{NextPageToken: rolesToken, Annotations: annos}, nil
	}

	token := newPaginationToken(attrs.PageToken.Size, tok.Page)
	qp := queryParams(token.Size, tok.Page)
	users, respCtx, err := o.listGroupUsers(ctx, tok.GroupID, token, qp)
	if err != nil {
		return nil, nil, convertNotFoundError(err, "okta-connectorv2: failed to list group users")
	}

	nextPage, annos, err := parseResp(respCtx.OktaResponse)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
	}

	groupStub := &v2.Resource{Id: fmtResourceId(resourceTypeGroup.Id, tok.GroupID)}
	var rv []*v2.Grant
	for _, user := range users {
		if !o.connector.shouldIncludeUserAndSetCache(ctx, attrs.Session, user) {
			continue
		}
		rv = append(rv, groupGrant(groupStub, user))
	}

	// The validator rides only the final page; interim pages stamp rows
	// with an empty etag (the SDK writes the manifest entry when the
	// non-empty etag arrives).
	etag := tok.Validator
	nextToken := rolesToken
	if nextPage != "" {
		etag = ""
		nextToken, err = (&groupGrantsCursor{
			GroupID:    tok.GroupID,
			Validator:  tok.Validator,
			UsersCount: tok.UsersCount,
			Phase:      groupCursorPhaseMembers,
			Page:       nextPage,
		}).marshal()
		if err != nil {
			return nil, nil, err
		}
	}
	annos.Update(&v2.SourceCacheScope{ScopeHash: scope, Etag: etag})

	l.Debug("okta-connectorv2: group members page",
		zap.String("mode", replayModeCold),
		zap.String("group_id", tok.GroupID),
		zap.Int("rows", len(rv)),
		zap.Bool("final_page", nextPage == ""),
	)

	return rv, &sdkResource.SyncOpResults{NextPageToken: nextToken, Annotations: annos}, nil
}

// groupRolesPage enumerates the group's role assignments — always fresh,
// never scope-stamped: role assign/revoke does not bump either group
// timestamp (probed live), so there is nothing to validate replay with.
// Mirrors the role leg of the per-resource Grants path, including the
// access-denied skip. The endpoint is effectively unpaginated (the
// per-resource path also issues a single unparameterized call).
func (o *groupResourceType) groupRolesPage(
	ctx context.Context,
	tok *groupGrantsCursor,
	attrs sdkResource.SyncOpAttrs,
) ([]*v2.Grant, *sdkResource.SyncOpResults, error) {
	l := ctxzap.Extract(ctx)

	roles, resp, err := listGroupAssignedRoles(ctx, o.connector.client, tok.GroupID, nil)
	if err != nil {
		if resp == nil {
			return nil, nil, fmt.Errorf("okta-connectorv2: failed to list group roles: %w", err)
		}
		defer resp.Body.Close()
		errOkta, err2 := getError(resp)
		if err2 != nil {
			return nil, nil, err2
		}
		if errOkta.ErrorCode == AccessDeniedErrorCode {
			l.Debug("okta-connectorv2: skipping group role grants (access denied)",
				zap.String("group_id", tok.GroupID))
			return nil, &sdkResource.SyncOpResults{}, nil
		}
		return nil, nil, convertNotFoundError(&errOkta, "okta-connectorv2: failed to list group roles")
	}

	_, annos, err := parseResp(resp)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
	}

	shouldExpand := tok.UsersCount == nil || *tok.UsersCount > 0
	var rv []*v2.Grant
	for _, role := range roles {
		if role.Status == roleStatusInactive || role.AssignmentType != groupRoleAssignmentType {
			continue
		}
		if !o.connector.SyncCustomRoles && role.Type == roleTypeCustom {
			continue
		}

		var roleResourceVal *v2.Resource
		if role.Type == roleTypeCustom {
			roleResourceVal, err = roleResource(ctx, &okta.Role{
				Id:    role.Role,
				Label: role.Label,
			}, resourceTypeCustomRole)
		} else {
			roleResourceVal, err = roleResource(ctx, &okta.Role{
				Id:    role.Role,
				Label: role.Label,
				Type:  role.Type,
			}, resourceTypeRole)
		}
		if err != nil {
			return nil, nil, err
		}

		if !shouldExpand {
			l.Debug("okta-connectorv2: skipping expand for role group grant since users_count is 0")
		}
		rv = append(rv, roleGroupGrant(tok.GroupID, roleResourceVal, shouldExpand))
	}

	return rv, &sdkResource.SyncOpResults{Annotations: annos}, nil
}
