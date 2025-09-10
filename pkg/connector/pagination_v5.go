package connector

import (
	"encoding/json"
	"net/http"
	"net/url"

	oktav5 "github.com/conductorone/okta-sdk-golang/v5/okta"
)

type SerializableOktaResponseV5 struct {
	Link []string
	Url  string
}

func serializeOktaResponseV5(resp *oktav5.APIResponse) (string, error) {
	if resp == nil {
		return "", nil
	}

	if !resp.HasNextPage() {
		return "", nil
	}

	// looks like the Request is nil in some cases when doesn't have next page
	if resp.Request == nil {
		return "", nil
	}

	serializable := &SerializableOktaResponseV5{
		Link: resp.Header["Link"],
		Url:  resp.Request.URL.String(),
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
