package connector

import (
	"context"
	"fmt"
	"net/http"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	unknownProfileValue     = "unknown"
	userStatusSuspended     = "SUSPENDED"
	userStatusDeprovisioned = "DEPROVISIONED"
	groupAdminRoleID        = "KVJUKUS7IFCE2SKO"
	appAdminRoleID          = "IFIFAX2BIRGUSTQ"
)

type userResourceType struct {
	resourceType *v2.ResourceType
	domain       string
	apiToken     string
	client       *okta.Client
}

func (o *userResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *userResourceType) List(
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

	users, respCtx, err := listUsers(ctx, o.client, token, qp)
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

	for _, user := range users {
		resource, err := userResource(ctx, user)
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

func (o *userResourceType) Entitlements(
	_ context.Context,
	resource *v2.Resource,
	_ *pagination.Token,
) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func (o *userResourceType) Grants(
	ctx context.Context,
	resource *v2.Resource,
	token *pagination.Token,
) ([]*v2.Grant, string, annotations.Annotations, error) {
	bag, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeUser.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	var rv []*v2.Grant
	var nextPage string
	var annos annotations.Annotations

	qp := queryParams(token.Size, page)

	switch bag.Current().ResourceTypeID {
	case resourceTypeUser.Id:
		bag.Pop()
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceTypeGroup.Id,
		})
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceTypeApp.Id,
		})

		npt, err := bag.Marshal()
		if err != nil {
			return nil, "", nil, err
		}

		return rv, npt, nil, nil

	case resourceTypeGroup.Id:
		groups, respCtx, err := listGroupsUserIsAdminOf(ctx, o.client, resource.Id.Resource, token, qp)
		if err != nil {
			return nil, "", nil, err
		}

		if len(groups) == 0 {
			break
		}

		nextPage, annos, err = parseResp(respCtx.OktaResponse)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
		}

		for _, g := range groups {
			rv = append(rv, &v2.Grant{
				Id: fmt.Sprintf("group-grant:%s:admin:%s:%s", g.Id, resource.Id.ResourceType, resource.Id.Resource),
				Entitlement: &v2.Entitlement{
					Id: fmt.Sprintf("group:%s:admin", g.Id),
					Resource: &v2.Resource{
						Id: &v2.ResourceId{
							ResourceType: resourceTypeGroup.Id,
							Resource:     g.Id,
						},
					},
				},
				Principal: resource,
			})
		}

	case resourceTypeApp.Id:
		apps, respCtx, err := listAppsUserIsAdminOf(ctx, o.client, resource.Id.Resource, token, qp)
		if err != nil {
			return nil, "", nil, err
		}

		if len(apps) == 0 {
			break
		}

		nextPage, annos, err = parseResp(respCtx.OktaResponse)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
		}

		for _, a := range apps {
			rv = append(rv, &v2.Grant{
				Id: fmt.Sprintf("app-grant:%s:admin:%s:%s", a.Id, resource.Id.ResourceType, resource.Id.Resource),
				Entitlement: &v2.Entitlement{
					Id: fmt.Sprintf("app:%s:admin", a.Id),
					Resource: &v2.Resource{
						Id: &v2.ResourceId{
							ResourceType: resourceTypeApp.Id,
							Resource:     a.Id,
						},
					},
				},
				Principal: resource,
			})
		}
	}

	npt, err := bag.NextToken(nextPage)
	if err != nil {
		return nil, "", nil, err
	}

	return rv, npt, annos, nil
}

func userName(user *okta.User) (string, string) {
	profile := *user.Profile

	firstName, ok := profile["firstName"].(string)
	if !ok {
		firstName = unknownProfileValue
	}
	lastName, ok := profile["lastName"].(string)
	if !ok {
		lastName = unknownProfileValue
	}

	return firstName, lastName
}

func listUsers(ctx context.Context, client *okta.Client, token *pagination.Token, qp *query.Params) ([]*okta.User, *responseContext, error) {
	oktaUsers, resp, err := client.User.ListUsers(ctx, qp)
	if err != nil {
		return nil, nil, err
	}
	respCtx, err := responseToContext(token, resp)
	if err != nil {
		return nil, nil, err
	}
	return oktaUsers, respCtx, nil
}

func listGroupsUserIsAdminOf(ctx context.Context, client *okta.Client, userID string, token *pagination.Token, qp *query.Params) ([]*okta.Group, *responseContext, error) {
	groups, resp, err := client.User.ListGroupTargetsForRole(ctx, userID, groupAdminRoleID, qp)
	if err != nil {
		// We got an error, but we have a response. If the response is a 404, then the user is not an admin of any groups, can return empty list.
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil, nil, nil
		}

		return nil, nil, err
	}
	respCtx, err := responseToContext(token, resp)
	if err != nil {
		return nil, nil, err
	}
	return groups, respCtx, nil
}

func listAppsUserIsAdminOf(ctx context.Context, client *okta.Client, userID string, token *pagination.Token, qp *query.Params) ([]*okta.CatalogApplication, *responseContext, error) {
	apps, resp, err := client.User.ListApplicationTargetsForApplicationAdministratorRoleForUser(ctx, userID, appAdminRoleID, qp)
	if err != nil {
		// We got an error, but we have a response. If the response is a 404, then the user is not an admin of any apps, can return empty list.
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil, nil, nil
		}

		return nil, nil, err
	}

	respCtx, err := responseToContext(token, resp)
	if err != nil {
		return nil, nil, err
	}
	return apps, respCtx, nil
}
func userBuilder(domain string, apiToken string, client *okta.Client) *userResourceType {
	return &userResourceType{
		resourceType: resourceTypeUser,
		domain:       domain,
		apiToken:     apiToken,
		client:       client,
	}
}

// Create a new connector resource for a okta user.
func userResource(ctx context.Context, user *okta.User) (*v2.Resource, error) {
	firstName, lastName := userName(user)

	trait, err := userTrait(ctx, user)
	if err != nil {
		return nil, err
	}
	var annos annotations.Annotations
	annos.Update(trait)
	annos.Update(&v2.V1Identifier{
		Id: fmtResourceIdV1(user.Id),
	})

	return &v2.Resource{
		Id:          fmtResourceId(resourceTypeUser.Id, user.Id),
		DisplayName: fmt.Sprintf("%s %s", firstName, lastName),
		Annotations: annos,
	}, nil
}

// Create and return a User trait for a okta user.
func userTrait(ctx context.Context, user *okta.User) (*v2.UserTrait, error) {
	oktaProfile := *user.Profile

	email, ok := oktaProfile["email"].(string)
	if !ok {
		email = unknownProfileValue
	}

	profile, err := structpb.NewStruct(oktaProfile)
	if err != nil {
		return nil, fmt.Errorf("okta-connectorv2: failed to construct user profile for user trait: %w", err)
	}

	var status v2.UserTrait_Status_Status
	switch user.Status {
	case userStatusSuspended, userStatusDeprovisioned:
		status = v2.UserTrait_Status_STATUS_DISABLED
	default:
		status = v2.UserTrait_Status_STATUS_ENABLED
	}

	ret := &v2.UserTrait{
		Profile: profile,
		Status: &v2.UserTrait_Status{
			Status:  status,
			Details: user.Status,
		},
	}

	if email != "" {
		ret.Emails = []*v2.UserTrait_Email{
			{
				Address:   email,
				IsPrimary: true,
			},
		}
	}

	return ret, nil
}
