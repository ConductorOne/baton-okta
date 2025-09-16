package connector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"

	oktav5 "github.com/conductorone/okta-sdk-golang/v5/okta"
)

type SerializableOktaResponseV5 struct {
	Link []string
	Url  string
}

func deserializeOktaResponseAfterV5(serialized string) (string, error) {
	if serialized == "" {
		return "", nil
	}

	r, err := deserializeOktaResponseV5(serialized) //nolint:bodyclose // just a dummy response
	if err != nil {
		return "", err
	}

	next := ""

	links := r.Header["Link"]
	if len(links) > 0 {
		for _, link := range links {
			splitLinkHeader := strings.Split(link, ";")
			if len(splitLinkHeader) < 2 {
				continue
			}
			rawLink := strings.TrimRight(strings.TrimLeft(splitLinkHeader[0], "<"), ">")
			rawURL, _ := url.Parse(rawLink)
			rawURL.Scheme = ""
			rawURL.Host = ""
			if r.Request != nil {
				q := r.Request.URL.Query()
				for k, v := range rawURL.Query() {
					q.Set(k, v[0])
				}
				rawURL.RawQuery = q.Encode()
			}
			if strings.Contains(link, `rel="next"`) {
				next = rawURL.Query().Get("after")
			}
		}
	}

	return next, nil
}

func serializeOktaResponseV5(resp *oktav5.APIResponse) (string, error) {
	if resp == nil {
		return "", nil
	}

	if !resp.HasNextPage() {
		return "", nil
	}

	// looks like the Request is nil in some cases when doesn't have next Page
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

func deserializeOktaResponseV5(serialized string) (*http.Response, error) {
	var serializable SerializableOktaResponseV5
	err := json.Unmarshal([]byte(serialized), &serializable)
	if err != nil {
		return nil, err
	}

	parsedUrl, err := url.Parse(serializable.Url)
	if err != nil {
		return nil, err
	}

	return &http.Response{
		Request: &http.Request{
			URL: parsedUrl,
		},
		Header: http.Header{
			"Link": serializable.Link,
		},
	}, nil
}

func paginateV5[T any](
	ctx context.Context,
	clientV5 *oktav5.APIClient,
	page string,
	act func(ctx2 context.Context) (T, *oktav5.APIResponse, error),
) (T, string, annotations.Annotations, error) {
	var response T
	var empty T
	var resp *oktav5.APIResponse
	var err error

	l := ctxzap.Extract(ctx)

	if page == "" {
		l.Debug("paginationV5: first Page")

		response, resp, err = act(ctx)
		if err != nil {
			annon, err := wrapErrorV5(resp, err)
			return empty, "", annon, err
		}
	} else {
		l.Debug("paginationV5: paginate", zap.String("Page", page))

		prevResp, err := deserializeOktaResponseV5(page) //nolint:bodyclose // just a dummy response
		if err != nil {
			return empty, "", nil, err
		}

		previous := oktav5.NewAPIResponse(prevResp, clientV5, nil)
		if previous.HasNextPage() {
			resp, err = previous.Next(&response)
			if err != nil {
				annon, err := wrapErrorV5(resp, err)
				return empty, "", annon, err
			}
		}
	}

	nextPage, annos, err := parseRespV5(resp)
	if err != nil {
		return empty, "", nil, err
	}

	return response, nextPage, annos, nil
}
