package connector

import (
	"encoding/json"
	"net/url"

	"github.com/conductorone/baton-okta/pkg/okta"
	"github.com/conductorone/baton-sdk/pkg/annotations"
)

// parseRespLinkToken is the pagination used by the device and API token
// listings: the page token stores the response's Link headers and request URL,
// and the next call follows the rel="next" link they describe.
func parseRespLinkToken(resp *okta.Response) (string, annotations.Annotations, error) {
	var annos annotations.Annotations

	if resp == nil {
		return "", nil, nil
	}

	annos = responseRateLimitAnnotations(resp)

	nextPage, err := serializeLinkToken(resp)
	if err != nil {
		return "", nil, err
	}

	return nextPage, annos, nil
}

// linkPageToken is the page-token payload. Its JSON shape is unchanged from
// earlier releases, so an in-flight sync resumes across an upgrade.
type linkPageToken struct {
	Link []string
	Url  string
}

func serializeLinkToken(resp *okta.Response) (string, error) {
	if resp == nil {
		return "", nil
	}

	serializable := &linkPageToken{
		Link: resp.Header["Link"],
		Url:  resp.Request.URL.String(),
	}

	jsonBytes, err := json.Marshal(serializable)
	if err != nil {
		return "", err
	}

	return string(jsonBytes), nil
}

// nextPageFromLinkToken returns the next page path a serialized token points
// at, or "" when the previous page was the last.
func nextPageFromLinkToken(serialized string) (string, error) {
	var serializable linkPageToken
	err := json.Unmarshal([]byte(serialized), &serializable)
	if err != nil {
		return "", err
	}

	parsedUrl, err := url.Parse(serializable.Url)
	if err != nil {
		return "", err
	}

	return okta.NextPageFromLinks(parsedUrl, serializable.Link), nil
}
