package connector

import (
	"net/url"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/okta/okta-sdk-golang/v2/okta"
)

const defaultLimit = 100

func parseResp(resp *okta.Response) (string, annotations.Annotations, error) {
	var annos annotations.Annotations
	var nextPage string

	if resp != nil {
		u, err := url.Parse(resp.NextPage)
		if err != nil {
			return "", nil, err
		}
		after := u.Query().Get("after")

		if desc, err := extractRateLimitData(resp); err == nil {
			annos.WithRateLimiting(desc)
		}
		nextPage = after
	}

	return nextPage, annos, nil
}

func parseAdminListResp(resp *okta.Response) (string, annotations.Annotations, error) {
	var annos annotations.Annotations
	var nextPage string

	if resp != nil {
		u, err := url.Parse(resp.NextPage)
		if err != nil {
			return "", nil, err
		}

		// Grab entire query param for next page token, drop limit so we can still set it how we want.
		nextQp := u.Query()
		nextQp.Del("limit")
		nextPage = nextQp.Encode()

		if desc, err := extractRateLimitData(resp); err == nil {
			annos.WithRateLimiting(desc)
		}
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
