package connector

import (
	"net/url"

	oktav5 "github.com/conductorone/okta-sdk-golang/v5/okta"

	"github.com/conductorone/baton-sdk/pkg/ratelimit"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/okta/okta-sdk-golang/v2/okta"
)

const defaultLimit = 50

func parseGetResp(resp *okta.Response) (annotations.Annotations, error) {
	var annos annotations.Annotations
	if resp != nil {
		if desc, err := ratelimit.ExtractRateLimitData(resp.StatusCode, &resp.Header); err == nil {
			annos.WithRateLimiting(desc)
		}
	}
	return annos, nil
}

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

// parseRespV5 parses the response from an Okta API call using the Okta v5 SDK.
// It extracts the next Page token and rate limit annotations from the response.
func parseRespV5(resp *oktav5.APIResponse) (string, annotations.Annotations, error) {
	var annos annotations.Annotations

	if resp == nil || resp.Header == nil {
		return "", nil, nil
	}

	if desc, err := ratelimit.ExtractRateLimitData(resp.StatusCode, &resp.Header); err == nil {
		annos.WithRateLimiting(desc)
	}

	nextPage, err := serializeOktaResponseV5(resp)
	if err != nil {
		return "", nil, err
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

		// Grab entire query param for next Page token, drop limit so we can still set it how we want.
		nextQp := u.Query()
		nextQp.Del("limit")
		nextPage = nextQp.Encode()

		if desc, err := ratelimit.ExtractRateLimitData(resp.StatusCode, &resp.Header); err == nil {
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

func parsePageTokenV5(token string, resourceID *v2.ResourceId) (*pagination.Bag, string, error) {
	bag, page, err := parsePageToken(token, resourceID)
	if err != nil {
		return nil, "", err
	}
	page, err = deserializeOktaResponseAfterV5(page)
	if err != nil {
		return nil, "", err
	}

	return bag, page, nil
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
