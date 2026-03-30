package connector

import (
	"net/url"

	"github.com/conductorone/baton-sdk/pkg/ratelimit"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/okta/okta-sdk-golang/v2/okta"
)

const (
	defaultLimit = 1000

	// roleAssignmentsPageSize limits the number of users fetched per page from
	// /api/v1/iam/assignees/users during role grants sync (Okta default is 100).
	// Each user on the page triggers an individual API call to
	// /api/v1/users/{id}/roles, so a smaller page size reduces the fan-out of
	// API calls per sync operation. This prevents Lambda execution timeouts when
	// syncing tenants with many users.
	// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleAssignment/#tag/RoleAssignment/operation/listUsersWithRoleAssignments
	roleAssignmentsPageSize = 50

	// groupUsersPageSize limits the number of users fetched per page from
	// /api/v1/groups/{id}/users during group grants sync (Okta default is 1000,
	// but Okta recommends 200). Large pages can produce responses that cause
	// unexpected EOF errors on large groups.
	// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Group/#tag/Group/operation/listGroupUsers
	groupUsersPageSize = 200
)

func parseResp(resp *okta.Response) (string, annotations.Annotations, error) {
	var annos annotations.Annotations
	var nextPage string

	if resp != nil {
		u, err := url.Parse(resp.NextPage)
		if err != nil {
			return "", nil, err
		}
		after := u.Query().Get("after")

		if desc, err := ratelimit.ExtractRateLimitData(resp.StatusCode, &resp.Header); err == nil {
			annos.WithRateLimiting(desc)
		}
		nextPage = after
	}

	return nextPage, annos, nil
}

func parsePageToken(token string, resourceID *v2.ResourceId) (*pagination.Bag, string, error) {
	b := &pagination.Bag{}
	err := b.Unmarshal(token)
	if err != nil {
		return nil, "", err
	}

	if b.Current() == nil {
		b.Push(pagination.PageState{
			ResourceTypeID: resourceID.ResourceType,
			ResourceID:     resourceID.Resource,
		})
	}

	page := b.PageToken()

	return b, page, nil
}

func newPaginationToken(limit int, nextPageToken string) *pagination.Token {
	if limit == 0 || limit > defaultLimit {
		limit = defaultLimit
	}

	return &pagination.Token{
		Size:  limit,
		Token: nextPageToken,
	}
}
