package connector

import (
	"context"
	"fmt"
	"time"

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

type groupResourceType struct {
	resourceType *v2.ResourceType
	domain       string
	apiToken     string
	client       *okta.Client
}

func (o *groupResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *groupResourceType) List(
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

	groups, respCtx, err := o.listGroups(ctx, token, qp)
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
	bag, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeUser.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	var rv []*v2.Grant
	qp := queryParams(token.Size, page)

	users, respCtx, err := o.listGroupUsers(ctx, resource.Id.GetResource(), token, qp)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list group users: %w", err)
	}

	nextPage, annos, err := parseResp(respCtx.OktaResponse)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
	}

	for _, user := range users {
		rv = append(rv, groupGrant(resource, user))
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
}

func (o *groupResourceType) listGroups(ctx context.Context, token *pagination.Token, qp *query.Params) ([]*okta.Group, *responseContext, error) {
	groups, resp, err := o.client.Group.ListGroups(ctx, qp)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch groups from okta: %w", err)
	}

	reqCtx, err := responseToContext(token, resp)
	if err != nil {
		return nil, nil, err
	}

	return groups, reqCtx, nil
}

func (o *groupResourceType) listGroupUsers(ctx context.Context, groupID string, token *pagination.Token, qp *query.Params) ([]*okta.User, *responseContext, error) {
	users, resp, err := o.client.Group.ListGroupUsers(ctx, groupID, qp)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch group users from okta: %w", err)
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

	etagMd, err := o.etagMd(group)
	if err != nil {
		return nil, err
	}
	annos.Update(etagMd)

	return &v2.Resource{
		Id:          fmtResourceId(resourceTypeGroup.Id, group.Id),
		DisplayName: group.Profile.Name,
		Annotations: annos,
	}, nil
}

func (o *groupResourceType) groupTrait(ctx context.Context, group *okta.Group) (*v2.GroupTrait, error) {
	profile, err := structpb.NewStruct(map[string]interface{}{
		"description": group.Profile.Description,
		"name":        group.Profile.Name,
	})
	if err != nil {
		return nil, fmt.Errorf("okta-connectorv2: failed to construct role profile for role trait: %w", err)
	}

	ret := &v2.GroupTrait{
		Profile: profile,
	}

	return ret, nil
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

	response, err := g.client.Group.AddUserToGroup(ctx, groupId, userId)
	if err != nil {
		return nil, err
	}

	l.Debug("Membership has been created",
		zap.String("Status", response.Status),
	)

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

	response, err := g.client.Group.RemoveUserFromGroup(ctx, groupId, userId)
	if err != nil {
		return nil, err
	}

	l.Warn("Membership has been revoked",
		zap.String("Status", response.Status),
	)

	return nil, nil
}

func groupBuilder(domain string, apiToken string, client *okta.Client) *groupResourceType {
	return &groupResourceType{
		resourceType: resourceTypeGroup,
		domain:       domain,
		apiToken:     apiToken,
		client:       client,
	}
}
