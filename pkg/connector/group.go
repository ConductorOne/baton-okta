package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	config "github.com/conductorone/baton-sdk/pb/c1/config/v1"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/actions"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/ratelimit"
	sdkEntitlement "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	sdkGrant "github.com/conductorone/baton-sdk/pkg/types/grant"
	sdkResource "github.com/conductorone/baton-sdk/pkg/types/resource"
	oktav5 "github.com/conductorone/okta-sdk-golang/v5/okta"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/structpb"
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
	token *pagination.Token,
) ([]*v2.Resource, string, annotations.Annotations, error) {
	bag, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeGroup.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	var rv []*v2.Resource
	var groups []*okta.Group
	var respCtx *responseContext
	if o.connector.awsConfig != nil && o.connector.awsConfig.Enabled {
		if o.connector.awsConfig.AWSSourceIdentityMode {
			return rv, "", nil, nil
		}
		groups, respCtx, err = o.listAWSGroups(ctx, token, page)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list app groups: %w", err)
		}
	} else {
		qp := queryParamsExpand(token.Size, page, "stats")
		groups, respCtx, err = o.listGroups(ctx, token, qp)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list groups: %w", err)
		}
	}

	nextPage, annos, err := parseResp(respCtx.OktaResponse)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
	}

	for _, group := range groups {
		resource, err := o.groupResource(ctx, group)
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

func (o *groupResourceType) Entitlements(
	ctx context.Context,
	resource *v2.Resource,
	token *pagination.Token,
) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement
	if o.connector.awsConfig != nil && o.connector.awsConfig.Enabled && o.connector.awsConfig.AWSSourceIdentityMode {
		return rv, "", nil, nil
	}

	rv = append(rv, o.groupEntitlement(ctx, resource))

	return rv, "", nil, nil
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
	token *pagination.Token,
) ([]*v2.Grant, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	var rv []*v2.Grant
	bag := &pagination.Bag{}
	err := bag.Unmarshal(token.Token)
	if err != nil {
		return nil, "", nil, err
	}

	if o.connector.awsConfig != nil && o.connector.awsConfig.Enabled && o.connector.awsConfig.AWSSourceIdentityMode {
		return rv, "", nil, nil
	}

	if bag.Current() == nil {
		if o.connector.awsConfig == nil || !o.connector.awsConfig.Enabled {
			bag.Push(pagination.PageState{
				ResourceTypeID: resourceTypeRole.Id,
			})
		}
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
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to get group trait: %w", err)
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
				return nil, "", nil, convertNotFoundError(err, "okta-connectorv2: failed to list group users")
			}

			nextPage, annos, err = parseResp(respCtx.OktaResponse)
			if err != nil {
				return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
			}

			for _, user := range users {
				shouldInclude := o.connector.shouldIncludeUserAndSetCache(ctx, user)
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
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
		}

		pageToken, err := bag.Marshal()
		if err != nil {
			return nil, "", nil, err
		}

		if pageToken == "" {
			etag := &v2.ETag{
				Value: time.Now().UTC().Format(time.RFC3339Nano),
			}
			annos.Update(etag)
		}

		return rv, pageToken, annos, nil
	case resourceTypeRole.Id:
		roles, resp, err := listGroupAssignedRoles(ctx, o.connector.client, groupID, nil)
		if err != nil {
			if resp == nil {
				return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list group roles: %w", err)
			}

			defer resp.Body.Close()
			errOkta, err := getError(resp)
			if err != nil {
				return nil, "", nil, err
			}
			if errOkta.ErrorCode == AccessDeniedErrorCode {
				err = bag.Next("")
				if err != nil {
					return nil, "", nil, err
				}
				pageToken, err := bag.Marshal()
				if err != nil {
					return nil, "", nil, err
				}
				return nil, pageToken, nil, nil
			} else {
				return nil, "", nil, convertNotFoundError(&errOkta, "okta-connectorv2: failed to list group roles")
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
				return nil, "", nil, err
			}

			groupTrait, err := sdkResource.GetGroupTrait(resource)
			if err != nil {
				return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to get group trait: %w", err)
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
			return nil, "", nil, err
		}

		nextPage, annos, err := parseResp(respCtx.OktaResponse)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
		}

		err = bag.Next(nextPage)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
		}

		pageToken, err := bag.Marshal()
		if err != nil {
			return nil, "", nil, err
		}

		return rv, pageToken, annos, nil
	default:
		return nil, "", nil, fmt.Errorf("okta-connector: invalid grant resource type: %s", bag.ResourceTypeID())
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

func (o *groupResourceType) listAWSGroups(ctx context.Context, token *pagination.Token, page string) ([]*okta.Group, *responseContext, error) {
	awsConfig, err := o.connector.getAWSApplicationConfig(ctx)
	if err != nil {
		return nil, nil, err
	}
	groups := make([]*okta.Group, 0)
	if awsConfig.UseGroupMapping {
		qp := queryParams(token.Size, page)
		groups, respCtx, err := listGroupsHelper(ctx, o.connector.client, token, qp)
		if err != nil {
			return nil, nil, err
		}
		for _, group := range groups {
			_, _, matchesRolePattern, err := parseAccountIDAndRoleFromGroupName(ctx, awsConfig.RoleRegex, group.Profile.Name)
			if err != nil {
				return nil, nil, fmt.Errorf("okta-aws-connector: failed to parse account id and role from group name: %w", err)
			}
			if matchesRolePattern {
				groups = append(groups, group)
			}
		}
		return groups, respCtx, nil
	}

	qp := queryParamsExpand(token.Size, page, "group")
	appGroups, respCtx, err := listApplicationGroupAssignments(ctx, o.connector.client, o.connector.awsConfig.OktaAppId, token, qp)
	if err != nil {
		return nil, nil, err
	}

	for _, appGroup := range appGroups {
		appGroupSAMLRoles, err := appGroupSAMLRolesWrapper(ctx, appGroup)
		if err != nil {
			return nil, nil, err
		}
		oktaGroup, err := embeddedOktaGroupFromAppGroup(appGroup)
		if err != nil {
			return nil, nil, fmt.Errorf("okta-aws-connector: failed to fetch groups from okta: %w", err)
		}
		groups = append(groups, oktaGroup)
		awsConfig.appGroupCache.Store(appGroup.Id, appGroupSAMLRoles)
	}
	return groups, respCtx, nil
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

/*
This filter field uses a regular expression to filter AWS-related groups and extract the accountid and role.

If you use the default AWS role group syntax (aws#[account alias]#[role name]#[account #]), then you can use this Regex string:
^aws\#\S+\#(?{{role}}[\w\-]+)\#(?{{accountid}}\d+)$

This Regex expression logically equates to:
find groups that start with AWS, then #, then a string of text, then #, then the AWS role, then #, then the AWS account ID.

You can also use this Regex expression:
aws_(?{{accountid}}\d+)_(?{{role}}[a-zA-Z0-9+=,.@\-_]+)
If you don't use a default Regex expression, create on that properly filters your AWS role groups.
The expression should capture the AWS role name and account ID within two distinct Regex groups named {{role}} and {{accountid}}.
*/
func parseAccountIDAndRoleFromGroupName(ctx context.Context, roleRegex string, groupName string) (string, string, bool, error) {
	// TODO(lauren) move to get app config
	re, err := regexp.Compile(roleRegex)
	if err != nil {
		return "", "", false, fmt.Errorf("error compiling regex '%s': %w", roleRegex, err)
	}
	match := re.FindStringSubmatch(groupName)
	if len(match) != ExpectedGroupNameCaptureGroupsWithGroupFilterForMultipleAWSInstances {
		return "", "", false, nil
	}
	// First element is full string
	accountId := match[1]
	role := match[2]

	return accountId, role, true, nil
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

func listUsersGroupsClient(ctx context.Context, client *okta.Client, userId string) ([]*okta.Group, *responseContext, error) {
	users, resp, err := client.User.ListUserGroups(ctx, userId)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch group users from okta: %w", handleOktaResponseError(resp, err))
	}

	reqCtx, err := responseToContext(&pagination.Token{}, resp)
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

func embeddedOktaGroupFromAppGroup(appGroup *okta.ApplicationGroupAssignment) (*okta.Group, error) {
	embedded := appGroup.Embedded
	if embedded == nil {
		return nil, fmt.Errorf("app group '%s' embedded data was nil", appGroup.Id)
	}
	embeddedMap, ok := embedded.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("app group embedded data was not a map for group with id '%s'", appGroup.Id)
	}
	embeddedGroup, ok := embeddedMap["group"]
	if !ok {
		return nil, fmt.Errorf("embedded group data was nil for app group '%s'", appGroup.Id)
	}
	groupJSON, err := json.Marshal(embeddedGroup)
	if err != nil {
		return nil, fmt.Errorf("error marshalling embedded group data for app group '%s': %w", appGroup.Id, err)
	}
	oktaGroup := &okta.Group{}
	err = json.Unmarshal(groupJSON, &oktaGroup)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling embedded group data for app group '%s': %w", appGroup.Id, err)
	}
	return oktaGroup, nil
}

func (o *groupResourceType) Get(ctx context.Context, resourceId *v2.ResourceId, parentResourceId *v2.ResourceId) (*v2.Resource, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	l.Debug("getting group", zap.String("group_id", resourceId.Resource))

	var annos annotations.Annotations

	var group *okta.Group
	var resp *okta.Response
	var err error
	if o.connector.awsConfig != nil && o.connector.awsConfig.Enabled {
		if o.connector.awsConfig.AWSSourceIdentityMode {
			return nil, annos, nil
		}
		group, resp, err = o.getAWSGroup(ctx, resourceId.Resource)
	} else {
		group, resp, err = o.GetGroupWithParams(ctx, resourceId.Resource)
	}

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

	if o.connector.awsConfig == nil || !o.connector.awsConfig.Enabled {
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
	}

	return resource, annos, nil
}

func (o *groupResourceType) getAWSGroup(ctx context.Context, groupId string) (*okta.Group, *okta.Response, error) {
	awsConfig, err := o.connector.getAWSApplicationConfig(ctx)
	if err != nil {
		return nil, nil, err
	}
	if awsConfig.UseGroupMapping {
		group, resp, err := o.connector.client.Group.GetGroup(ctx, groupId)
		if err != nil {
			return nil, nil, handleOktaResponseError(resp, err)
		}

		_, _, matchesRolePattern, err := parseAccountIDAndRoleFromGroupName(ctx, awsConfig.RoleRegex, group.Profile.Name)
		if err != nil {
			return nil, nil, fmt.Errorf("okta-aws-connector: failed to parse account id and role from group name: %w", err)
		}

		if matchesRolePattern {
			return group, resp, nil
		}

		return nil, nil, nil
	}

	qp := query.NewQueryParams(query.WithExpand("group"))
	appGroup, resp, err := o.connector.client.Application.GetApplicationGroupAssignment(ctx, o.connector.awsConfig.OktaAppId, groupId, qp)
	if err != nil {
		return nil, nil, handleOktaResponseError(resp, err)
	}
	appGroupSAMLRoles, err := appGroupSAMLRolesWrapper(ctx, appGroup)
	if err != nil {
		return nil, nil, err
	}
	oktaGroup, err := embeddedOktaGroupFromAppGroup(appGroup)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-aws-connector: failed to fetch groups from okta: %w", err)
	}
	awsConfig.appGroupCache.Store(appGroup.Id, appGroupSAMLRoles)
	return oktaGroup, resp, nil
}

func groupBuilder(connector *Okta) *groupResourceType {
	return &groupResourceType{
		resourceType: resourceTypeGroup,
		connector:    connector,
	}
}

func (o *groupResourceType) ResourceActions(ctx context.Context, registry actions.ActionRegistry) error {
	l := ctxzap.Extract(ctx)

	// Base arguments for the action
	arguments := []*config.Field{
		{
			Name:        "name",
			DisplayName: "Group Name",
			Description: "The name of the group to create",
			Field:       &config.Field_StringField{},
			IsRequired:  true,
		},
		{
			Name:        "description",
			DisplayName: "Description",
			Description: "Description of the group",
			Field:       &config.Field_StringField{},
			IsRequired:  false,
		},
	}

	// Fetch the group schema to add custom attributes
	customFields := o.getCustomGroupSchemaFields(ctx)
	if len(customFields) > 0 {
		l.Debug("adding custom group schema fields to create action", zap.Int("count", len(customFields)))
		arguments = append(arguments, customFields...)
	}

	return registry.Register(ctx, &v2.BatonActionSchema{
		Name:        "create",
		DisplayName: "Create Group",
		Description: "Creates a new Okta group",
		Arguments:   arguments,
		ReturnTypes: []*config.Field{
			{Name: "success", DisplayName: "Success", Field: &config.Field_BoolField{}},
			{Name: "resource", DisplayName: "Created Group", Field: &config.Field_ResourceField{}},
		},
		ActionType: []v2.ActionType{v2.ActionType_ACTION_TYPE_RESOURCE_CREATE},
	}, o.handleCreateGroupAction)
}

func (o *groupResourceType) handleCreateGroupAction(ctx context.Context, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	name, err := actions.RequireStringArg(args, "name")
	if err != nil {
		return nil, nil, err
	}
	description, _ := actions.GetStringArg(args, "description")

	profile := oktav5.NewGroupProfile()
	profile.SetName(name)
	if description != "" {
		profile.SetDescription(description)
	}

	// Refetch schema to get real types for custom attribute conversion.
	schema, _, err := o.connector.clientV5.SchemaAPI.GetGroupSchema(ctx).Execute()
	if err != nil {
		// Check if caller provided any custom fields - if so, we must fail.
		for k := range args.GetFields() {
			if strings.HasPrefix(k, "custom_") {
				return nil, nil, fmt.Errorf("failed to fetch group schema for custom attributes: %w", err)
			}
		}
		l.Warn("failed to fetch group schema, proceeding without custom attributes", zap.Error(err))
	} else {
		if err := o.applyCustomAttributes(profile, schema, args); err != nil {
			return nil, nil, fmt.Errorf("failed to apply custom attributes: %w", err)
		}
	}

	group := oktav5.NewGroup()
	group.SetProfile(*profile)

	createdGroup, _, err := o.connector.clientV5.GroupAPI.CreateGroup(ctx).Group(*group).Execute()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create group: %w", err)
	}

	l.Info("group created", zap.String("group_id", createdGroup.GetId()), zap.String("name", name))

	resource, err := o.groupResource(ctx, &okta.Group{
		Id: createdGroup.GetId(),
		Profile: &okta.GroupProfile{
			Name:        createdGroup.Profile.GetName(),
			Description: createdGroup.Profile.GetDescription(),
		},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build group resource: %w", err)
	}

	resourceRv, err := actions.NewResourceReturnField("resource", resource)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create resource return field: %w", err)
	}
	return actions.NewReturnValues(true, resourceRv), nil, nil
}

// applyCustomAttributes validates and applies custom schema attributes to the profile.
func (o *groupResourceType) applyCustomAttributes(profile *oktav5.GroupProfile, schema *oktav5.GroupSchema, args *structpb.Struct) error {
	if schema.Definitions == nil || schema.Definitions.Custom == nil || schema.Definitions.Custom.Properties == nil {
		return nil
	}

	required := make(map[string]bool)
	for _, f := range schema.Definitions.Custom.Required {
		required[f] = true
	}

	for attrName, attr := range *schema.Definitions.Custom.Properties {
		val := args.GetFields()["custom_"+attrName]
		isEmpty := val == nil || isEmptyValue(val)

		if (required[attrName] || (attr.Required != nil && *attr.Required)) && isEmpty {
			return fmt.Errorf("required field %q is missing", attrName)
		}
		if isEmpty {
			continue
		}

		attrType := "string"
		if attr.Type != nil {
			attrType = *attr.Type
		}

		converted, err := convertToOktaSchemaType(val, attrType)
		if err != nil {
			return fmt.Errorf("field %q: %w", attrName, err)
		}
		if converted != nil {
			if profile.AdditionalProperties == nil {
				profile.AdditionalProperties = make(map[string]any)
			}
			profile.AdditionalProperties[attrName] = converted
		}
	}
	return nil
}

func isEmptyValue(v *structpb.Value) bool {
	switch val := v.GetKind().(type) {
	case *structpb.Value_NullValue:
		return true
	case *structpb.Value_StringValue:
		return val.StringValue == ""
	case *structpb.Value_ListValue:
		return val.ListValue == nil || len(val.ListValue.Values) == 0
	}
	return false
}

// convertToOktaSchemaType converts a structpb.Value to the Go type expected by the Okta API
// based on the attribute's declared schema type (string, boolean, integer, number, array).
func convertToOktaSchemaType(v *structpb.Value, attrType string) (any, error) {
	switch attrType {
	case "boolean":
		if b, ok := v.GetKind().(*structpb.Value_BoolValue); ok {
			return b.BoolValue, nil
		}
		if s, ok := v.GetKind().(*structpb.Value_StringValue); ok {
			return s.StringValue == "true", nil
		}
	case "integer":
		if n, ok := v.GetKind().(*structpb.Value_NumberValue); ok {
			return int64(n.NumberValue), nil
		}
		if s, ok := v.GetKind().(*structpb.Value_StringValue); ok {
			var i int64
			if _, err := fmt.Sscanf(s.StringValue, "%d", &i); err != nil {
				return nil, fmt.Errorf("invalid integer %q", s.StringValue)
			}
			return i, nil
		}
	case "number":
		if n, ok := v.GetKind().(*structpb.Value_NumberValue); ok {
			return n.NumberValue, nil
		}
		if s, ok := v.GetKind().(*structpb.Value_StringValue); ok {
			var f float64
			if _, err := fmt.Sscanf(s.StringValue, "%f", &f); err != nil {
				return nil, fmt.Errorf("invalid number %q", s.StringValue)
			}
			return f, nil
		}
	case "array":
		if list, ok := v.GetKind().(*structpb.Value_ListValue); ok && list.ListValue != nil {
			result := make([]any, 0, len(list.ListValue.Values))
			for _, item := range list.ListValue.Values {
				switch iv := item.GetKind().(type) {
				case *structpb.Value_StringValue:
					result = append(result, iv.StringValue)
				case *structpb.Value_NumberValue:
					result = append(result, iv.NumberValue)
				case *structpb.Value_BoolValue:
					result = append(result, iv.BoolValue)
				}
			}
			return result, nil
		}
	default:
		if s, ok := v.GetKind().(*structpb.Value_StringValue); ok && s.StringValue != "" {
			return s.StringValue, nil
		}
	}
	return nil, nil
}

// getCustomGroupSchemaFields fetches the Okta group schema and returns config fields
// for any custom attributes defined in the schema.
func (o *groupResourceType) getCustomGroupSchemaFields(ctx context.Context) []*config.Field {
	l := ctxzap.Extract(ctx)

	schema, _, err := o.connector.clientV5.SchemaAPI.GetGroupSchema(ctx).Execute()
	if err != nil {
		l.Warn("failed to fetch group schema for custom attributes", zap.Error(err))
		return nil
	}

	if schema.Definitions == nil || schema.Definitions.Custom == nil || schema.Definitions.Custom.Properties == nil {
		return nil
	}

	// Build a set of required field names from the schema-level Required array
	requiredFields := make(map[string]bool)
	for _, fieldName := range schema.Definitions.Custom.Required {
		requiredFields[fieldName] = true
	}

	var fields []*config.Field
	for attrName, attr := range *schema.Definitions.Custom.Properties {
		if field := oktaSchemaAttrToConfigField(attrName, attr, requiredFields); field != nil {
			fields = append(fields, field)
		}
	}

	return fields
}

// oktaSchemaAttrToConfigField converts an Okta GroupSchemaAttribute to a baton config.Field.
// Returns nil for read-only attributes.
func oktaSchemaAttrToConfigField(name string, attr oktav5.GroupSchemaAttribute, requiredFields map[string]bool) *config.Field {
	if attr.Mutability != nil && *attr.Mutability == "READ_ONLY" {
		return nil
	}

	displayName := name
	if attr.Title != nil && *attr.Title != "" {
		displayName = *attr.Title
	}

	description := ""
	if attr.Description != nil {
		description = *attr.Description
	}

	isRequired := requiredFields[name] || (attr.Required != nil && *attr.Required)

	// Prefix custom attributes to avoid collision with built-in fields
	fieldName := "custom_" + name

	attrType := "string"
	if attr.Type != nil {
		attrType = *attr.Type
	}

	switch attrType {
	case "boolean":
		return &config.Field{
			Name:        fieldName,
			DisplayName: displayName,
			Description: description,
			Field:       &config.Field_BoolField{},
			IsRequired:  isRequired,
		}
	case "integer", "number":
		// Okta's "number" type is float64, but baton-sdk only has IntField (int64).
		var intRules *config.Int64Rules
		minimum, hasMin := attr.AdditionalProperties["minimum"]
		maximum, hasMax := attr.AdditionalProperties["maximum"]
		if hasMin || hasMax {
			intRules = &config.Int64Rules{}
			if hasMin {
				if minVal, ok := minimum.(float64); ok {
					gte := int64(minVal)
					intRules.Gte = &gte
				}
			}
			if hasMax {
				if maxVal, ok := maximum.(float64); ok {
					lte := int64(maxVal)
					intRules.Lte = &lte
				}
			}
		}
		return &config.Field{
			Name:        fieldName,
			DisplayName: displayName,
			Description: description,
			Field: &config.Field_IntField{
				IntField: &config.IntField{
					Rules: intRules,
				},
			},
			IsRequired: isRequired,
		}
	case "array":
		// Check element type from Items.Type if available
		itemType := "string"
		if attr.Items != nil && attr.Items.Type != nil {
			itemType = *attr.Items.Type
		}

		// For integer arrays, we still use StringSliceField since baton-sdk
		// doesn't have an IntSliceField. Values are converted at apply time.
		if itemType == "integer" || itemType == "number" {
			description += " (numeric values)"
		}

		// Okta does not have rules for array fields
		return &config.Field{
			Name:        fieldName,
			DisplayName: displayName,
			Description: description,
			Field: &config.Field_StringSliceField{
				StringSliceField: &config.StringSliceField{},
			},
			IsRequired: isRequired,
		}
	default: // string and others
		var stringRules *config.StringRules
		if attr.MinLength != nil || attr.MaxLength != nil || len(attr.Enum) > 0 {
			stringRules = &config.StringRules{}
			if attr.MinLength != nil {
				minLen := uint64(*attr.MinLength)
				stringRules.MinLen = &minLen
			}
			if attr.MaxLength != nil {
				maxLen := uint64(*attr.MaxLength)
				stringRules.MaxLen = &maxLen
			}
			if len(attr.Enum) > 0 {
				stringRules.In = attr.Enum
			}
		}

		var options []*config.StringFieldOption
		if len(attr.Enum) > 0 {
			options = make([]*config.StringFieldOption, 0, len(attr.Enum))
			for _, enumVal := range attr.Enum {
				options = append(options, &config.StringFieldOption{
					Name:        enumVal,
					DisplayName: enumVal,
					Value:       enumVal,
				})
			}
		}

		return &config.Field{
			Name:        fieldName,
			DisplayName: displayName,
			Description: description,
			Field: &config.Field_StringField{
				StringField: &config.StringField{
					Rules:   stringRules,
					Options: options,
				},
			},
			IsRequired: isRequired,
		}
	}
}
