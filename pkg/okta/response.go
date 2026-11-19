package okta

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Response is an API response. The body has already been read and stays
// readable through Body.
type Response struct {
	*http.Response
	// NextPage is the rel="next" link, reduced to a path plus query. The
	// request's own query parameters are carried into it, overridden by those
	// in the link, as the connector has always done.
	NextPage string
}

// HasNextPage reports whether the response advertised a next page.
func (r *Response) HasNextPage() bool { return r != nil && r.NextPage != "" }

func newResponse(r *http.Response) *Response {
	resp := &Response{Response: r}
	for _, link := range r.Header.Values("Link") {
		parts := strings.Split(link, ";")
		if len(parts) < 2 {
			continue
		}
		raw := strings.TrimRight(strings.TrimLeft(parts[0], "<"), ">")
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		u.Scheme = ""
		u.Host = ""
		if r.Request != nil {
			q := r.Request.URL.Query()
			for k, v := range u.Query() {
				q.Set(k, v[0])
			}
			u.RawQuery = q.Encode()
		}
		if strings.Contains(link, `rel="next"`) {
			resp.NextPage = u.String()
		}
	}
	return resp
}

func (r *Response) bodyBytes() ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(b))
	return b, nil
}

// NextPageFromLinks computes Response.NextPage for a response to requestURL
// that carried the given Link header values. It lets a caller that stored
// those two values in a page token resume pagination later.
func NextPageFromLinks(requestURL *url.URL, links []string) string {
	r := &http.Response{Header: http.Header{}, Request: &http.Request{URL: requestURL}}
	for _, l := range links {
		r.Header.Add("Link", l)
	}
	return newResponse(r).NextPage
}
