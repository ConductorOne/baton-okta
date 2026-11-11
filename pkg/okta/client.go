// Package okta is a small client for the parts of the Okta Management API the
// connector uses. It speaks to the API directly over the baton-sdk uhttp
// transport and keeps request and response types to the fields the connector
// reads.
package okta

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	contentTypeJSON = "application/json"

	// OmitCredentialsContentType asks Okta to leave credentials, credential
	// links and transitioningToStatus out of user payloads.
	// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/User/#tag/User/operation/listUsers!in=header&path=Content-Type&t=request
	OmitCredentialsContentType = `application/json; okta-response="omitCredentials,omitCredentialsLinks,omitTransitioningToStatus"`

	defaultMaxRetries = 2
	defaultMaxBackoff = 30 * time.Second
)

// Config configures a Client.
type Config struct {
	// OrgURL is the org's base URL, e.g. https://acme.okta.com.
	OrgURL *url.URL
	// HTTPClient sends every request. It is expected to be a uhttp client, or
	// the oktaauth DPoP client wrapping one.
	HTTPClient *http.Client
	// APIToken, when set, is sent as "Authorization: SSWS <token>". When empty
	// the transport is responsible for authorization (OAuth/DPoP mode).
	APIToken string
}

// Client calls the Okta Management API.
type Client struct {
	orgURL     *url.URL
	httpClient *http.Client
	apiToken   string

	maxRetries int
	maxBackoff time.Duration
	sleep      func(ctx context.Context, d time.Duration) error

	// limitMu guards limit, the last rate-limit window observed by a request
	// sent with rateLimitPrevention.
	limitMu sync.Mutex
	limit   *rateLimitWindow
}

// NewClient returns a Client for cfg.
func NewClient(cfg Config) (*Client, error) {
	if cfg.OrgURL == nil || cfg.OrgURL.Host == "" {
		return nil, errors.New("okta: org URL is required")
	}
	if cfg.HTTPClient == nil {
		return nil, errors.New("okta: HTTP client is required")
	}
	c := &Client{
		orgURL:     &url.URL{Scheme: cfg.OrgURL.Scheme, Host: cfg.OrgURL.Host},
		httpClient: cfg.HTTPClient,
		apiToken:   cfg.APIToken,
		maxRetries: defaultMaxRetries,
		maxBackoff: defaultMaxBackoff,
		sleep:      sleepContext,
	}
	return c, nil
}

// request describes one API call.
type request struct {
	method string
	// path is the request path, optionally followed by "?query". It may also
	// be a path previously returned in Response.NextPage.
	path        string
	query       url.Values
	body        any
	contentType string
	// rateLimitPrevention waits out an exhausted rate-limit window observed by
	// an earlier request that also set it, before sending.
	rateLimitPrevention bool
	// errorStyle selects how a non-2xx response becomes an error.
	errorStyle errorStyle
	// no429Retry makes the first 429 final.
	no429Retry bool
	// followUpPage marks a status-line request for a page after the first,
	// whose success body is decoded by decodeFollowUpPage.
	followUpPage bool
}

// do sends req, decoding a successful JSON body into v when v is non-nil. On a
// non-2xx response it returns the response together with an error built per
// req.errorStyle. When the request never produced a usable response (transport
// failure, or 429 retries exhausted) the returned *Response is nil.
func (c *Client) do(ctx context.Context, req request, v any) (*Response, error) {
	httpReq, err := c.newHTTPRequest(ctx, req)
	if err != nil {
		return nil, err
	}

	if req.rateLimitPrevention {
		if err := c.waitForRateLimitWindow(ctx); err != nil {
			return nil, err
		}
	}

	max429Retries := c.maxRetries
	if req.no429Retry {
		max429Retries = 0
	}
	httpResp, _, err := c.doWithRetries(ctx, httpReq, max429Retries) //nolint:bodyclose // doWithRetries reads and closes the network body
	if err != nil {
		if req.errorStyle == errorStyleGeneric {
			return nil, &GenericError{Message: err.Error(), cause: err}
		}
		return nil, err
	}

	if httpResp.StatusCode >= 200 && httpResp.StatusCode <= 299 && req.method == http.MethodGet {
		if req.rateLimitPrevention {
			c.recordRateLimitWindow(httpResp)
		}
	}

	return c.buildResponse(httpResp, req, v)
}

func (c *Client) newHTTPRequest(ctx context.Context, req request) (*http.Request, error) {
	u, err := c.resolve(req.path, req.query)
	if err != nil {
		return nil, err
	}

	var body io.Reader
	if req.body != nil {
		buf := new(bytes.Buffer)
		enc := json.NewEncoder(buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(req.body); err != nil {
			return nil, err
		}
		body = buf
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if c.apiToken != "" {
		httpReq.Header.Set("Authorization", "SSWS "+c.apiToken)
	}
	httpReq.Header.Set("Accept", contentTypeJSON)
	switch {
	case req.contentType != "":
		httpReq.Header.Set("Content-Type", req.contentType)
	case req.body != nil:
		httpReq.Header.Set("Content-Type", contentTypeJSON)
	}
	return httpReq, nil
}

// resolve joins path (which may carry its own query) onto the org URL and
// merges extra query parameters into it.
func (c *Client) resolve(path string, extra url.Values) (*url.URL, error) {
	rel, err := url.Parse(path)
	if err != nil {
		return nil, err
	}
	u := *c.orgURL
	u.Path = rel.Path
	u.RawPath = rel.RawPath
	q := rel.Query()
	for k, vs := range extra {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	if len(q) > 0 {
		u.RawQuery = q.Encode()
	} else {
		u.RawQuery = rel.RawQuery
	}
	return &u, nil
}

// doWithRetries sends httpReq, retrying up to max429Retries 429 responses
// after the window Okta advertises, and up to c.maxRetries connections dropped
// mid-response (io.EOF). It returns the final response with its body fully read.
func (c *Client) doWithRetries(ctx context.Context, httpReq *http.Request, max429Retries int) (*http.Response, []byte, error) {
	var reqBody []byte
	if httpReq.Body != nil {
		b, err := io.ReadAll(httpReq.Body)
		if err != nil {
			return nil, nil, err
		}
		_ = httpReq.Body.Close()
		reqBody = b
	}

	eofRetries := 0
	for attempt := 0; ; attempt++ {
		if reqBody != nil {
			httpReq.Body = io.NopCloser(bytes.NewReader(reqBody))
		}
		resp, err := c.httpClient.Do(httpReq)
		if err != nil {
			// A connection dropped mid-response is retried; anything else from
			// the transport is final.
			if errors.Is(err, io.EOF) {
				if eofRetries < c.maxRetries {
					eofRetries++
					attempt--
					continue
				}
				return nil, nil, &TransportError{err: err}
			}
			return nil, nil, err
		}

		if resp.StatusCode != http.StatusTooManyRequests {
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				return nil, nil, err
			}
			resp.Body = io.NopCloser(bytes.NewReader(body))
			return resp, body, nil
		}

		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()

		backoff, err := backoffFor429(resp)
		if err != nil {
			return nil, nil, err
		}
		if attempt >= max429Retries {
			return nil, nil, errTooManyRequests
		}
		if backoff > c.maxBackoff {
			backoff = c.maxBackoff
		}
		if err := c.sleep(ctx, backoff); err != nil {
			return nil, nil, err
		}
		httpReq.Header.Add("X-Okta-Retry-For", resp.Header.Get("X-Okta-Request-Id"))
		httpReq.Header.Add("X-Okta-Retry-Count", strconv.Itoa(attempt+1))
	}
}

var errTooManyRequests = errors.New("too many requests")

// TransportError is a request that got no response because the connection
// kept dropping mid-response (io.EOF) after every retry. It reports
// codes.Unavailable, so callers treat it as transient and retry later.
type TransportError struct {
	err error
}

func (e *TransportError) Error() string { return "network error: " + e.err.Error() }

func (e *TransportError) Unwrap() error { return e.err }

// GRPCStatus lets status.Code and status.FromError classify the error.
func (e *TransportError) GRPCStatus() *status.Status {
	return status.New(codes.Unavailable, e.Error())
}

// backoffFor429 is how long Okta asks a client to wait after a 429: until the
// X-Rate-Limit-Reset epoch, measured against the response's Date, plus a second.
func backoffFor429(resp *http.Response) (time.Duration, error) {
	requestDate, err := time.Parse("Mon, 02 Jan 2006 15:04:05 GMT", resp.Header.Get("Date"))
	if err != nil {
		return 0, fmt.Errorf("date header is missing or invalid: %w", err)
	}
	reset, err := strconv.Atoi(resp.Header.Get("X-Rate-Limit-Reset"))
	if err != nil {
		return 0, fmt.Errorf("X-Rate-Limit-Reset header is missing or invalid: %w", err)
	}
	return time.Duration(int64(reset)-requestDate.Unix()+1) * time.Second, nil
}

func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// rateLimitWindow is the X-Rate-Limit state of the most recent successful
// GET sent with rateLimitPrevention.
type rateLimitWindow struct {
	remaining int
	reset     time.Duration
}

func (c *Client) recordRateLimitWindow(resp *http.Response) {
	if _, err := strconv.Atoi(resp.Header.Get("X-Rate-Limit-Limit")); err != nil {
		return
	}
	remaining, err := strconv.Atoi(resp.Header.Get("X-Rate-Limit-Remaining"))
	if err != nil {
		return
	}
	reset, err := backoffFor429(resp)
	if err != nil {
		return
	}
	c.limitMu.Lock()
	c.limit = &rateLimitWindow{remaining: remaining, reset: reset}
	c.limitMu.Unlock()
}

func (c *Client) waitForRateLimitWindow(ctx context.Context) error {
	c.limitMu.Lock()
	limit := c.limit
	c.limitMu.Unlock()
	if limit == nil || limit.remaining > 0 {
		return nil
	}
	return c.sleep(ctx, limit.reset)
}

// buildResponse wraps httpResp, turning a non-2xx status into an error and
// decoding a 2xx JSON body into v.
func (c *Client) buildResponse(httpResp *http.Response, req request, v any) (*Response, error) {
	resp := newResponse(httpResp)
	body, err := resp.bodyBytes()
	if err != nil {
		return nil, err
	}

	if err := responseError(req.errorStyle, httpResp, body); err != nil {
		return resp, err
	}

	if len(body) == 0 {
		return resp, nil
	}
	if req.errorStyle == errorStyleGeneric && req.followUpPage {
		if err := decodeFollowUpPage(httpResp.Header.Get("Content-Type"), body, v); err != nil {
			if errors.Is(err, errUnknownContentType) {
				return nil, err
			}
			return resp, err
		}
		return resp, nil
	}
	if v == nil {
		// Decoded and discarded, so a non-JSON success body is still an error.
		var discard any
		v = &discard
	}
	ct := httpResp.Header.Get("Content-Type")
	isJSON := strings.Contains(ct, contentTypeJSON)
	if req.errorStyle == errorStyleGeneric {
		isJSON = jsonContentType.MatchString(ct)
	}
	switch {
	case isJSON:
		if err := json.Unmarshal(body, v); err != nil {
			if req.errorStyle == errorStyleGeneric {
				return resp, &GenericError{Message: err.Error(), Body: body}
			}
			return nil, err
		}
	default:
		if req.errorStyle == errorStyleGeneric {
			return resp, &GenericError{Message: "undefined response type", Body: body}
		}
		return nil, errors.New("could not build a response for type: " + ct)
	}
	return resp, nil
}

var errUnknownContentType = errors.New("could not build a response for type")

// decodeFollowUpPage decodes the success body of a device or API-token page
// fetched from a rel="next" link. These pages have always been decoded with
// different rules from first pages: the Content-Type must contain
// application/json (or application/xml), application/octet-stream bodies are
// not decoded, decode errors are returned bare, and any other type fails with
// "could not build a response for type: <type>".
func decodeFollowUpPage(ct string, body []byte, v any) error {
	var err error
	switch {
	case strings.Contains(ct, "application/xml"):
		err = xml.NewDecoder(bytes.NewReader(body)).Decode(v)
	case strings.Contains(ct, contentTypeJSON):
		err = json.NewDecoder(bytes.NewReader(body)).Decode(v)
	case strings.Contains(ct, "application/octet-stream"):
		return nil
	default:
		return fmt.Errorf("%w: %s", errUnknownContentType, ct)
	}
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}
