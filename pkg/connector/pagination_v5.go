package connector

import (
	oktav5 "github.com/okta/okta-sdk-golang/v5/okta"
	"net/url"

	"github.com/conductorone/baton-sdk/pkg/annotations"
)

func parseRespV5(resp *oktav5.APIResponse) (string, annotations.Annotations, error) {
	var annos annotations.Annotations
	var nextPage string

	if resp != nil {
		u, err := url.Parse(resp.NextPage())
		if err != nil {
			return "", nil, err
		}
		after := u.Query().Get("after")

		if desc, err := extractRateLimitData(resp.Response); err == nil {
			annos.WithRateLimiting(desc)
		}
		nextPage = after
	}

	return nextPage, annos, nil
}
