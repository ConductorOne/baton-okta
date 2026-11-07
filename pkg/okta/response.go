package okta

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Response is an API response. The body has already been read and stays
// readable through Body.
type Response struct {
	*http.Response
	// Self and NextPage are the rel="self" and rel="next" links, reduced to a
	// path plus query. The request's own query parameters are carried into
	// them, overridden by those in the link, as Okta's SDKs always have.
	Self     string
	NextPage string
}

// HasNextPage reports whether the response advertised a next page.
func (r *Response) HasNextPage() bool { return r != nil && r.NextPage != "" }

// NextAfter returns the "after" cursor of the next page, or "".
func (r *Response) NextAfter() string {
	if r == nil || r.NextPage == "" {
		return ""
	}
	u, err := url.Parse(r.NextPage)
	if err != nil {
		return ""
	}
	return u.Query().Get("after")
}

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
		if strings.Contains(link, `rel="self"`) {
			resp.Self = u.String()
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

// responseCache holds successful GET responses keyed by full URL.
type responseCache struct {
	ttl time.Duration
	now func() time.Time

	mu      sync.Mutex
	entries map[string]cachedResponse
}

type cachedResponse struct {
	status     string
	statusCode int
	header     http.Header
	body       []byte
	expires    time.Time // zero: never
}

func newResponseCache(ttl time.Duration) *responseCache {
	return &responseCache{ttl: ttl, now: time.Now, entries: map[string]cachedResponse{}}
}

func (c *responseCache) get(key string) (cachedResponse, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return cachedResponse{}, false
	}
	if !e.expires.IsZero() && !c.now().Before(e.expires) {
		delete(c.entries, key)
		return cachedResponse{}, false
	}
	return e, true
}

func (c *responseCache) set(key string, resp *http.Response, body []byte) {
	e := cachedResponse{
		status:     resp.Status,
		statusCode: resp.StatusCode,
		header:     resp.Header.Clone(),
		body:       append([]byte(nil), body...),
	}
	if c.ttl > 0 {
		e.expires = c.now().Add(c.ttl)
	}
	c.mu.Lock()
	c.entries[key] = e
	c.mu.Unlock()
}

func (c *responseCache) delete(key string) {
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
}

func (e cachedResponse) toHTTP(req *http.Request) *http.Response {
	return &http.Response{
		Status:     e.status,
		StatusCode: e.statusCode,
		Header:     e.header.Clone(),
		Body:       io.NopCloser(bytes.NewReader(e.body)),
		Request:    req,
	}
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
