package connector

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/conductorone/baton-sdk/pkg/ratelimit"
	sdkResource "github.com/conductorone/baton-sdk/pkg/types/resource"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/structpb"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	sdkEntitlement "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	sdkGrant "github.com/conductorone/baton-sdk/pkg/types/grant"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
)

const membershipUpdatedField = "lastMembershipUpdated"
const usersCountProfileKey = "users_count"
const builtInGroupType = "BUILT_IN"
const apiPathGetGroupFmt = "/api/v1/groups/%s"

type groupResourceType struct {
	resourceType *v2.ResourceType
	connector    *Okta
}

func (o *groupResourceType) ResourceType(ctx context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *groupResourceType) List(
	ctx context.Context,
	resourceID *v2.ResourceId,
	attrs sdkResource.SyncOpAttrs,
) ([]*v2.Resource, *sdkResource.SyncOpResults, error) {
	token := &attrs.PageToken
	bag, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeGroup.Id})
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	var rv []*v2.Resource
	qp := queryParamsExpand(token.Size, page, "stats")
	groups, respCtx, err := o.listGroups(ctx, token, qp)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to list groups: %w", err)
	}

	nextPage, annos, err := parseResp(respCtx.OktaResponse)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
	}

	for _, group := range groups {
		resource, err := o.groupResource(ctx, group)
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

func (o *groupResourceType) Entitlements(
	ctx context.Context,
	resource *v2.Resource,
	attrs sdkResource.SyncOpAttrs,
) ([]*v2.Entitlement, *sdkResource.SyncOpResults, error) {
	var rv []*v2.Entitlement
	rv = append(rv, o.groupEntitlement(ctx, resource))

	return rv, nil, nil
}

func (o *groupResourceType) etagMd(group *okta.Group) (*v2.ETagMetadata, error) {
	if group.LastMembershipUpdated != nil {
		data, err := structpb.NewStruct(map[string]interface{}{
			membershipUpdatedField: group.LastMembershipUpdated.Format(time.RFC3339Nano),
		})
		if err != nil {
			return nil, err
		}
		return &v2.ETagMetadata{
			Metadata: data,
		}, nil
	}

	return nil, nil
}

func (o *groupResourceType) Grants(
	ctx context.Context,
	resource *v2.Resource,
	attrs sdkResource.SyncOpAttrs,
) ([]*v2.Grant, *sdkResource.SyncOpResults, error) {
	token := &attrs.PageToken
	l := ctxzap.Extract(ctx)

	var rv []*v2.Grant
	bag := &pagination.Bag{}
	err := bag.Unmarshal(token.Token)
	if err != nil {
		return nil, nil, err
	}

	if bag.Current() == nil {
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceTypeRole.Id,
		})
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceTypeUser.Id,
		})
	}

	page := bag.PageToken()

	groupID := resource.Id.GetResource()

	switch bag.ResourceTypeID() {
	case resourceTypeUser.Id:
		groupTrait, err := sdkResource.GetGroupTrait(resource)
		if err != nil {
			return nil, nil, fmt.Errorf("okta-connectorv2: failed to get group trait: %w", err)
		}
		usersCount, ok := sdkResource.GetProfileInt64Value(groupTrait.Profile, usersCountProfileKey)

		var annos annotations.Annotations
		nextPage := ""
		if !ok || usersCount > 0 {
			if !ok {
				l.Debug("okta-connectorv2: making list group users call because users_count profile attribute was not present")
			}

			qp := queryParams(token.Size, page)

			users, respCtx, err := o.listGroupUsers(ctx, groupID, token, qp)
			if err != nil {
				return nil, nil, convertNotFoundError(err, "okta-connectorv2: failed to list group users")
			}

			nextPage, annos, err = parseResp(respCtx.OktaResponse)
			if err != nil {
				return nil, nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
			}

			for _, user := range users {
				shouldInclude := o.connector.shouldIncludeUserAndSetCache(ctx, attrs.Session, user)
				if !shouldInclude {
					continue
				}

				rv = append(rv, groupGrant(resource, user))
			}
		} else {
			l.Debug("okta-connectorv2: skipping list group users")
		}

		err = bag.Next(nextPage)
		if err != nil {
			return nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
		}

		pageToken, err := bag.Marshal()
		if err != nil {
			return nil, nil, err
		}

		if pageToken == "" {
			etag := &v2.ETag{
				Value: time.Now().UTC().Format(time.RFC3339Nano),
			}
			annos.Update(etag)
		}

		return rv, &sdkResource.SyncOpResults{NextPageToken: pageToken, Annotations: annos}, nil
	case resourceTypeRole.Id:
		roles, resp, err := listGroupAssignedRoles(ctx, o.connector.client, groupID, nil)
		if err != nil {
			if resp == nil {
				return nil, nil, fmt.Errorf("okta-connectorv2: failed to list group roles: %w", err)
			}

			defer resp.Body.Close()
			errOkta, err := getError(resp)
			if err != nil {
				return nil, nil, err
			}
			if errOkta.ErrorCode == AccessDeniedErrorCode {
				err = bag.Next("")
				if err != nil {
					return nil, nil, err
				}
				pageToken, err := bag.Marshal()
				if err != nil {
					return nil, nil, err
				}
				return nil, &sdkResource.SyncOpResults{NextPageToken: pageToken}, nil
			} else {
				return nil, nil, convertNotFoundError(&errOkta, "okta-connectorv2: failed to list group roles")
			}
		}

		for _, role := range roles {
			if role.Status == roleStatusInactive || role.AssignmentType != "GROUP" {
				continue
			}

			if !o.connector.syncCustomRoles && role.Type == roleTypeCustom {
				continue
			}

			// TODO(lauren) convert model helper
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

			groupTrait, err := sdkResource.GetGroupTrait(resource)
			if err != nil {
				return nil, nil, fmt.Errorf("okta-connectorv2: failed to get group trait: %w", err)
			}
			usersCount, ok := sdkResource.GetProfileInt64Value(groupTrait.Profile, usersCountProfileKey)
			shouldExpand := !ok || usersCount > 0
			if !shouldExpand {
				l.Debug("okta-connectorv2: skipping expand for role group grant since users_count is 0")
			}
			rv = append(rv, roleGroupGrant(groupID, roleResourceVal, shouldExpand))
		}

		// TODO(lauren) Move this to list method like other methods do
		respCtx, err := responseToContext(token, resp)
		if err != nil {
			return nil, nil, err
		}

		nextPage, annos, err := parseResp(respCtx.OktaResponse)
		if err != nil {
			return nil, nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
		}

		err = bag.Next(nextPage)
		if err != nil {
			return nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
		}

		pageToken, err := bag.Marshal()
		if err != nil {
			return nil, nil, err
		}

		return rv, &sdkResource.SyncOpResults{NextPageToken: pageToken, Annotations: annos}, nil
	default:
		return nil, nil, fmt.Errorf("okta-connector: invalid grant resource type: %s", bag.ResourceTypeID())
	}
}

func (o *groupResourceType) listGroups(ctx context.Context, token *pagination.Token, qp *query.Params) ([]*okta.Group, *responseContext, error) {
	return listGroupsHelper(ctx, o.connector.client, token, qp)
}

func listGroupsHelper(ctx context.Context, client *okta.Client, token *pagination.Token, qp *query.Params) ([]*okta.Group, *responseContext, error) {
	groups, resp, err := client.Group.ListGroups(ctx, qp)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch groups from okta: %w", handleOktaResponseError(resp, err))
	}
	reqCtx, err := responseToContext(token, resp)
	if err != nil {
		return nil, nil, err
	}
	return groups, reqCtx, nil
}

func (o *groupResourceType) GetGroupWithParams(
	ctx context.Context,
	groupID string,
) (*okta.Group, *okta.Response, error) {
	reqUrl, err := url.Parse(fmt.Sprintf(apiPathGetGroupFmt, groupID))
	if err != nil {
		return nil, nil, err
	}

	qp := query.NewQueryParams(query.WithExpand("stats,app")).String()
	reqUrlStr := reqUrl.String() + qp

	rq := o.connector.client.CloneRequestExecutor()
	req, err := rq.
		WithAccept(ContentType).
		WithContentType(ContentType).
		NewRequest(http.MethodGet, reqUrlStr, nil)
	if err != nil {
		return nil, nil, err
	}

	var group *okta.Group
	resp, err := rq.Do(ctx, req, &group)
	if err != nil {
		return nil, resp, err
	}

	return group, resp, nil
}

func (o *groupResourceType) listGroupUsers(ctx context.Context, groupID string, token *pagination.Token, qp *query.Params) ([]*okta.User, *responseContext, error) {
	users, resp, err := o.connector.client.Group.ListGroupUsers(ctx, groupID, qp)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch group users from okta: %w", handleOktaResponseError(resp, err))
	}

	reqCtx, err := responseToContext(token, resp)
	if err != nil {
		return nil, nil, err
	}

	return users, reqCtx, nil
}

func (o *groupResourceType) groupResource(ctx context.Context, group *okta.Group) (*v2.Resource, error) {
	trait, err := o.groupTrait(ctx, group)
	if err != nil {
		return nil, err
	}

	var annos annotations.Annotations
	annos.Update(trait)
	annos.Update(&v2.V1Identifier{
		Id: fmtResourceIdV1(group.Id),
	})
	annos.Update(&v2.RawId{Id: group.Id})

	etagMd, err := o.etagMd(group)
	if err != nil {
		return nil, err
	}
	annos.Update(etagMd)

	if group.Type == builtInGroupType {
		annos.Update(&v2.EntitlementImmutable{})
	}
	return &v2.Resource{
		Id:          fmtResourceId(resourceTypeGroup.Id, group.Id),
		DisplayName: group.Profile.Name,
		Annotations: annos,
	}, nil
}

func (o *groupResourceType) groupTrait(ctx context.Context, group *okta.Group) (*v2.GroupTrait, error) {
	profileMap := map[string]interface{}{
		"description": group.Profile.Description,
		"name":        group.Profile.Name,
	}

	if userCount, exists := getGroupUserCount(group); exists {
		profileMap[usersCountProfileKey] = int64(userCount)
	}

	if appCount, exists := getGroupAppsCount(group); exists {
		profileMap["apps_count"] = int64(appCount)
	}

	profile, err := structpb.NewStruct(profileMap)
	if err != nil {
		return nil, fmt.Errorf("okta-connectorv2: failed to construct group profile for group trait: %w", err)
	}

	ret := &v2.GroupTrait{
		Profile: profile,
	}

	return ret, nil
}

func getGroupStat(group *okta.Group, statName string) (float64, bool) {
	if group.Embedded == nil {
		return 0, false
	}
	embeddedMap, ok := group.Embedded.(map[string]interface{})
	if !ok {
		return 0, false
	}
	stats, ok := embeddedMap["stats"]
	if !ok {
		return 0, false
	}
	statsMap, ok := stats.(map[string]interface{})
	if !ok {
		return 0, false
	}
	statValue, ok := statsMap[statName]
	if !ok {
		return 0, false
	}
	value, ok := statValue.(float64)
	if !ok {
		return 0, false
	}
	return value, true
}

// getGroupUserCount retrieves the user count for a group.
func getGroupUserCount(group *okta.Group) (float64, bool) {
	return getGroupStat(group, "usersCount")
}

// getGroupAppsCount retrieves the apps count for a group.
func getGroupAppsCount(group *okta.Group) (float64, bool) {
	return getGroupStat(group, "appsCount")
}

func (o *groupResourceType) groupEntitlement(ctx context.Context, resource *v2.Resource) *v2.Entitlement {
	return sdkEntitlement.NewAssignmentEntitlement(resource, "member",
		sdkEntitlement.WithAnnotation(&v2.V1Identifier{
			Id: V1MembershipEntitlementID(resource.Id.GetResource()),
		}),
		sdkEntitlement.WithGrantableTo(resourceTypeUser),
		sdkEntitlement.WithDisplayName(fmt.Sprintf("%s Group Member", resource.DisplayName)),
		sdkEntitlement.WithDescription(fmt.Sprintf("Member of %s group in Okta", resource.DisplayName)),
	)
}

func groupGrant(resource *v2.Resource, user *okta.User) *v2.Grant {
	ur := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeUser.Id, Resource: user.Id}}

	return sdkGrant.NewGrant(resource, "member", ur, sdkGrant.WithAnnotation(&v2.V1Identifier{
		Id: fmtGrantIdV1(V1MembershipEntitlementID(resource.Id.Resource), user.Id),
	}))
}

func (g *groupResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	if principal.Id.ResourceType != resourceTypeUser.Id {
		l.Warn(
			"okta-connector: only users can be granted group membership",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("okta-connector: only users can be granted group membership")
	}

	groupId := entitlement.Resource.Id.Resource
	userId := principal.Id.Resource

	response, err := g.connector.client.Group.AddUserToGroup(ctx, groupId, userId)
	if err != nil {
		return nil, handleOktaResponseError(response, err)
	}

	if response != nil {
		l.Debug("Membership has been created", zap.String("Status", response.Status))
	} else {
		l.Debug("Membership has been created")
	}

	return nil, nil
}

func (g *groupResourceType) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	entitlement := grant.Entitlement
	principal := grant.Principal
	if principal.Id.ResourceType != resourceTypeUser.Id {
		l.Warn(
			"okta-connector: only users can have group membership revoked",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("okta-connector:only users can have group membership revoked")
	}

	groupId := entitlement.Resource.Id.Resource
	userId := principal.Id.Resource

	response, err := g.connector.client.Group.RemoveUserFromGroup(ctx, groupId, userId)
	if err != nil {
		return nil, handleOktaResponseError(response, err)
	}

	if response != nil {
		l.Warn("Membership has been revoked", zap.String("Status", response.Status))
	} else {
		l.Warn("Membership has been revoked")
	}

	return nil, nil
}

func (o *groupResourceType) Get(ctx context.Context, resourceId *v2.ResourceId, parentResourceId *v2.ResourceId) (*v2.Resource, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	l.Debug("getting group", zap.String("group_id", resourceId.Resource))

	var annos annotations.Annotations

	group, resp, err := o.GetGroupWithParams(ctx, resourceId.Resource)
	if err != nil {
		return nil, nil, handleOktaResponseErrorWithNotFoundMessage(resp, err, "group not found")
	}

	if resp != nil {
		if desc, err := ratelimit.ExtractRateLimitData(resp.StatusCode, &resp.Header); err == nil {
			annos.WithRateLimiting(desc)
		}
	}

	resource, err := o.groupResource(ctx, group)
	if err != nil {
		return nil, annos, err
	}

	groupTrait, err := sdkResource.GetGroupTrait(resource)
	if err != nil {
		return nil, annos, fmt.Errorf("okta-connectorv2: failed to get group trait: %w", err)
	}
	usersCount, ok := sdkResource.GetProfileInt64Value(groupTrait.Profile, usersCountProfileKey)
	if ok && usersCount == 0 {
		groupAnnos := annotations.Annotations(resource.GetAnnotations())
		groupAnnos.Update(&v2.SkipGrants{})
		resource.Annotations = groupAnnos
	}

	return resource, annos, nil
}

func groupBuilder(connector *Okta) *groupResourceType {
	return &groupResourceType{
		resourceType: resourceTypeGroup,
		connector:    connector,
	}
}
