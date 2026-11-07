package okta

import (
	"net/url"
	"strconv"
)

// QueryParams are the query parameters the connector sends. Zero values are
// omitted.
type QueryParams struct {
	After     string
	Limit     int64
	Filter    string
	Expand    string
	Activate  *bool
	SendEmail *bool
	Search    string
	Since     string
	SortOrder string
	Provider  *bool
	NextLogin string
}

// Values encodes the parameters.
func (p *QueryParams) Values() url.Values {
	qs := url.Values{}
	if p == nil {
		return qs
	}
	if p.After != "" {
		qs.Add("after", p.After)
	}
	if p.Limit != 0 {
		qs.Add("limit", strconv.FormatInt(p.Limit, 10))
	}
	if p.Filter != "" {
		qs.Add("filter", p.Filter)
	}
	if p.Expand != "" {
		qs.Add("expand", p.Expand)
	}
	if p.Activate != nil {
		qs.Add("activate", strconv.FormatBool(*p.Activate))
	}
	if p.SendEmail != nil {
		qs.Add("sendEmail", strconv.FormatBool(*p.SendEmail))
	}
	if p.Search != "" {
		qs.Add("search", p.Search)
	}
	if p.Since != "" {
		qs.Add("since", p.Since)
	}
	if p.SortOrder != "" {
		qs.Add("sortOrder", p.SortOrder)
	}
	if p.Provider != nil {
		qs.Add("provider", strconv.FormatBool(*p.Provider))
	}
	if p.NextLogin != "" {
		qs.Add("nextLogin", p.NextLogin)
	}
	return qs
}

// String returns "?<encoded>" or "" when no parameter is set.
func (p *QueryParams) String() string {
	qs := p.Values()
	if len(qs) == 0 {
		return ""
	}
	return "?" + qs.Encode()
}

// Bool returns a pointer to b.
func Bool(b bool) *bool { return &b }
