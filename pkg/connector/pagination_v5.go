package connector

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/conductorone/baton-sdk/pkg/ratelimit"

	oktav5 "github.com/conductorone/okta-sdk-golang/v5/okta"

	"github.com/conductorone/baton-sdk/pkg/annotations"
)

func parseRespV5(resp *oktav5.APIResponse) (string, annotations.Annotations, error) {
	var annos annotations.Annotations

	if resp == nil {
		return "", nil, nil
	}

	if desc, err := ratelimit.ExtractRateLimitData(resp.Response.StatusCode, &resp.Response.Header); err == nil {
		annos.WithRateLimiting(desc)
	}

	nextPage, err := serializeOktaResponseV5(resp)
	if err != nil {
		return "", nil, err
	}

	return nextPage, annos, nil
}

type SerializableOktaResponseV5 struct {
	Link []string
	Url  string
}

func serializeOktaResponseV5(resp *oktav5.APIResponse) (string, error) {
	if resp == nil {
		return "", nil
	}

	serializable := &SerializableOktaResponseV5{
		Link: resp.Response.Header["Link"],
		Url:  resp.Response.Request.URL.String(),
	}

	jsonBytes, err := json.Marshal(serializable)
	if err != nil {
		return "", err
	}

	return string(jsonBytes), nil
}

func deserializeOktaResponseV5(serialized string) (*oktav5.APIResponse, error) {
	var serializable SerializableOktaResponseV5
	err := json.Unmarshal([]byte(serialized), &serializable)
	if err != nil {
		return nil, err
	}

	parsedUrl, err := url.Parse(serializable.Url)
	if err != nil {
		return nil, err
	}

	return &oktav5.APIResponse{
		Response: &http.Response{
			Request: &http.Request{
				URL: parsedUrl,
			},
			Header: http.Header{
				"Link": serializable.Link,
			},
		},
	}, nil
}
