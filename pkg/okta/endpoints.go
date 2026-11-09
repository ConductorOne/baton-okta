package okta

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// RequestOption adjusts a single request.
type RequestOption func(*request)

// WithContentType overrides the request Content-Type (sent even without a body).
func WithContentType(ct string) RequestOption {
	return func(r *request) { r.contentType = ct }
}

// WithFreshRead is retained for compatibility; all reads are fresh.
func WithFreshRead() RequestOption {
	return func(*request) {}
}

// The device, API token and resource-set lookups have always differed from the
// rest of the API in three ways, each set by one option. statusLineEndpoint
// applies all three.
func statusLineEndpoint(extra ...RequestOption) []RequestOption {
	return append([]RequestOption{withStatusLineErrors(), withRateLimitWait(), withNo429Retry()}, extra...)
}

// withStatusLineErrors makes non-2xx responses surface as *GenericError
// carrying the HTTP status line.
func withStatusLineErrors() RequestOption {
	return func(r *request) { r.errorStyle = errorStyleGeneric }
}

// withRateLimitWait waits out an exhausted rate-limit window, observed by an
// earlier request that also set it, before sending.
func withRateLimitWait() RequestOption {
	return func(r *request) { r.rateLimitPrevention = true }
}

// withNo429Retry makes the first 429 final. Dropped connections are still
// retried.
func withNo429Retry() RequestOption {
	return func(r *request) { r.no429Retry = true }
}

// withFollowUpPage marks a status-line list request as fetching a page after
// the first one.
func withFollowUpPage(followUp bool) RequestOption {
	return func(r *request) { r.followUpPage = followUp }
}

// Do sends method to path (which may include a query string), JSON-encoding
// body when non-nil and decoding a successful JSON response into v when
// non-nil. A non-2xx response is returned alongside an *Error.
func (c *Client) Do(ctx context.Context, method, path string, body, v any, opts ...RequestOption) (*Response, error) {
	req := request{method: method, path: path, body: body}
	for _, o := range opts {
		o(&req)
	}
	return c.do(ctx, req, v)
}

func (c *Client) get(ctx context.Context, path string, qp *QueryParams, v any, opts ...RequestOption) (*Response, error) {
	return c.Do(ctx, http.MethodGet, path+qp.String(), nil, v, opts...)
}

// ---- Org

// GetOrgSettings reads GET /api/v1/org.
func (c *Client) GetOrgSettings(ctx context.Context) (*OrgSetting, *Response, error) {
	var out *OrgSetting
	resp, err := c.get(ctx, "/api/v1/org", nil, &out)
	if err != nil {
		return nil, resp, err
	}
	return out, resp, nil
}

// ---- Users

// GetUser reads GET /api/v1/users/{idOrLogin}.
func (c *Client) GetUser(ctx context.Context, userID string, opts ...RequestOption) (*User, *Response, error) {
	var out *User
	resp, err := c.get(ctx, fmt.Sprintf("/api/v1/users/%v", PathEscape(userID)), nil, &out, opts...)
	if err != nil {
		return nil, resp, err
	}
	return out, resp, nil
}

// CreateUser sends POST /api/v1/users.
func (c *Client) CreateUser(ctx context.Context, body CreateUserRequest, qp *QueryParams) (*User, *Response, error) {
	var out *User
	resp, err := c.Do(ctx, http.MethodPost, "/api/v1/users"+qp.String(), body, &out)
	if err != nil {
		return nil, resp, err
	}
	return out, resp, nil
}

// PartialUpdateUser sends POST /api/v1/users/{id}, merging the given profile.
func (c *Client) PartialUpdateUser(ctx context.Context, userID string, body User) (*User, *Response, error) {
	var out *User
	resp, err := c.Do(ctx, http.MethodPost, fmt.Sprintf("/api/v1/users/%v", PathEscape(userID)), body, &out)
	if err != nil {
		return nil, resp, err
	}
	return out, resp, nil
}

// lifecycle sends POST /api/v1/users/{id}/lifecycle/{op}.
func (c *Client) lifecycle(ctx context.Context, userID, op string, qp *QueryParams) (*Response, error) {
	var out map[string]any
	return c.Do(ctx, http.MethodPost, fmt.Sprintf("/api/v1/users/%v/lifecycle/%s", PathEscape(userID), op)+qp.String(), nil, &out)
}

// ActivateUser activates a STAGED or DEPROVISIONED user.
func (c *Client) ActivateUser(ctx context.Context, userID string, qp *QueryParams) (*Response, error) {
	return c.lifecycle(ctx, userID, "activate", qp)
}

// DeactivateUser deprovisions a user.
func (c *Client) DeactivateUser(ctx context.Context, userID string, qp *QueryParams) (*Response, error) {
	return c.lifecycle(ctx, userID, "deactivate", qp)
}

// SuspendUser suspends an ACTIVE user.
func (c *Client) SuspendUser(ctx context.Context, userID string) (*Response, error) {
	return c.Do(ctx, http.MethodPost, fmt.Sprintf("/api/v1/users/%v/lifecycle/suspend", PathEscape(userID)), nil, nil)
}

// UnsuspendUser returns a SUSPENDED user to ACTIVE.
func (c *Client) UnsuspendUser(ctx context.Context, userID string) (*Response, error) {
	return c.Do(ctx, http.MethodPost, fmt.Sprintf("/api/v1/users/%v/lifecycle/unsuspend", PathEscape(userID)), nil, nil)
}

// DeleteUser sends DELETE /api/v1/users/{id}: it deactivates an active user
// and permanently deletes a DEPROVISIONED one.
func (c *Client) DeleteUser(ctx context.Context, userID string) (*Response, error) {
	return c.Do(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/users/%v", PathEscape(userID)), nil, nil)
}

// ListUserRoles reads GET /api/v1/users/{id}/roles.
func (c *Client) ListUserRoles(ctx context.Context, userID string) ([]*Role, *Response, error) {
	var out []*Role
	resp, err := c.get(ctx, fmt.Sprintf("/api/v1/users/%v/roles", PathEscape(userID)), nil, &out)
	if err != nil {
		return nil, resp, err
	}
	return out, resp, nil
}

// AssignRoleToUser sends POST /api/v1/users/{id}/roles.
func (c *Client) AssignRoleToUser(ctx context.Context, userID string, body AssignRoleRequest) (*Role, *Response, error) {
	var out *Role
	resp, err := c.Do(ctx, http.MethodPost, fmt.Sprintf("/api/v1/users/%v/roles", PathEscape(userID)), body, &out)
	if err != nil {
		return nil, resp, err
	}
	return out, resp, nil
}

// RemoveRoleFromUser sends DELETE /api/v1/users/{id}/roles/{roleAssignmentId}.
func (c *Client) RemoveRoleFromUser(ctx context.Context, userID, roleID string) (*Response, error) {
	return c.Do(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/users/%v/roles/%v", PathEscape(userID), PathEscape(roleID)), nil, nil)
}

// ---- Groups

// ListGroups reads GET /api/v1/groups.
func (c *Client) ListGroups(ctx context.Context, qp *QueryParams) ([]*Group, *Response, error) {
	var out []*Group
	resp, err := c.get(ctx, "/api/v1/groups", qp, &out)
	if err != nil {
		return nil, resp, err
	}
	return out, resp, nil
}

// GetGroup reads GET /api/v1/groups/{id}.
func (c *Client) GetGroup(ctx context.Context, groupID string, qp *QueryParams) (*Group, *Response, error) {
	var out *Group
	resp, err := c.get(ctx, fmt.Sprintf("/api/v1/groups/%v", PathEscape(groupID)), qp, &out)
	if err != nil {
		return nil, resp, err
	}
	return out, resp, nil
}

// CreateGroup sends POST /api/v1/groups.
func (c *Client) CreateGroup(ctx context.Context, body Group) (*Group, *Response, error) {
	var out *Group
	resp, err := c.Do(ctx, http.MethodPost, "/api/v1/groups", body, &out)
	if err != nil {
		return nil, resp, err
	}
	return out, resp, nil
}

// UpdateGroup sends PUT /api/v1/groups/{id}.
func (c *Client) UpdateGroup(ctx context.Context, groupID string, body Group) (*Group, *Response, error) {
	var out *Group
	resp, err := c.Do(ctx, http.MethodPut, fmt.Sprintf("/api/v1/groups/%v", PathEscape(groupID)), body, &out)
	if err != nil {
		return nil, resp, err
	}
	return out, resp, nil
}

// DeleteGroup sends DELETE /api/v1/groups/{id}.
func (c *Client) DeleteGroup(ctx context.Context, groupID string) (*Response, error) {
	return c.Do(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/groups/%v", PathEscape(groupID)), nil, nil)
}

// ListGroupUsers reads GET /api/v1/groups/{id}/users.
func (c *Client) ListGroupUsers(ctx context.Context, groupID string, qp *QueryParams) ([]*User, *Response, error) {
	var out []*User
	resp, err := c.get(ctx, fmt.Sprintf("/api/v1/groups/%v/users", PathEscape(groupID)), qp, &out)
	if err != nil {
		return nil, resp, err
	}
	return out, resp, nil
}

// AddUserToGroup sends PUT /api/v1/groups/{groupId}/users/{userId}.
func (c *Client) AddUserToGroup(ctx context.Context, groupID, userID string) (*Response, error) {
	return c.Do(ctx, http.MethodPut, fmt.Sprintf("/api/v1/groups/%v/users/%v", PathEscape(groupID), PathEscape(userID)), nil, nil)
}

// RemoveUserFromGroup sends DELETE /api/v1/groups/{groupId}/users/{userId}.
func (c *Client) RemoveUserFromGroup(ctx context.Context, groupID, userID string) (*Response, error) {
	return c.Do(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/groups/%v/users/%v", PathEscape(groupID), PathEscape(userID)), nil, nil)
}

// ListGroupRoles reads GET /api/v1/groups/{id}/roles.
func (c *Client) ListGroupRoles(ctx context.Context, groupID string, opts ...RequestOption) ([]*Role, *Response, error) {
	var out []*Role
	resp, err := c.get(ctx, fmt.Sprintf("/api/v1/groups/%v/roles", PathEscape(groupID)), nil, &out, opts...)
	if err != nil {
		return nil, resp, err
	}
	return out, resp, nil
}

// AssignRoleToGroup sends POST /api/v1/groups/{id}/roles.
func (c *Client) AssignRoleToGroup(ctx context.Context, groupID string, body AssignRoleRequest) (*Role, *Response, error) {
	var out *Role
	resp, err := c.Do(ctx, http.MethodPost, fmt.Sprintf("/api/v1/groups/%v/roles", PathEscape(groupID)), body, &out)
	if err != nil {
		return nil, resp, err
	}
	return out, resp, nil
}

// RemoveRoleFromGroup sends DELETE /api/v1/groups/{id}/roles/{roleAssignmentId}.
func (c *Client) RemoveRoleFromGroup(ctx context.Context, groupID, roleID string) (*Response, error) {
	return c.Do(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/groups/%v/roles/%v", PathEscape(groupID), PathEscape(roleID)), nil, nil)
}

// ---- Apps

// ListApplications reads GET /api/v1/apps.
func (c *Client) ListApplications(ctx context.Context, qp *QueryParams) ([]*Application, *Response, error) {
	var out []*Application
	resp, err := c.get(ctx, "/api/v1/apps", qp, &out)
	if err != nil {
		return nil, resp, err
	}
	return out, resp, nil
}

// GetApplication reads GET /api/v1/apps/{id}.
func (c *Client) GetApplication(ctx context.Context, appID string) (*Application, *Response, error) {
	var out *Application
	resp, err := c.get(ctx, fmt.Sprintf("/api/v1/apps/%v", PathEscape(appID)), nil, &out)
	if err != nil {
		return nil, resp, err
	}
	return out, resp, nil
}

// ListApplicationUsers reads GET /api/v1/apps/{id}/users.
func (c *Client) ListApplicationUsers(ctx context.Context, appID string, qp *QueryParams) ([]*AppUser, *Response, error) {
	var out []*AppUser
	resp, err := c.get(ctx, fmt.Sprintf("/api/v1/apps/%v/users", PathEscape(appID)), qp, &out)
	if err != nil {
		return nil, resp, err
	}
	return out, resp, nil
}

// GetApplicationUser reads GET /api/v1/apps/{id}/users/{userId}.
func (c *Client) GetApplicationUser(ctx context.Context, appID, userID string) (*AppUser, *Response, error) {
	var out *AppUser
	resp, err := c.get(ctx, fmt.Sprintf("/api/v1/apps/%v/users/%v", PathEscape(appID), PathEscape(userID)), nil, &out)
	if err != nil {
		return nil, resp, err
	}
	return out, resp, nil
}

// AssignUserToApplication sends POST /api/v1/apps/{id}/users.
func (c *Client) AssignUserToApplication(ctx context.Context, appID string, body AppUser) (*AppUser, *Response, error) {
	var out *AppUser
	resp, err := c.Do(ctx, http.MethodPost, fmt.Sprintf("/api/v1/apps/%v/users", PathEscape(appID)), body, &out)
	if err != nil {
		return nil, resp, err
	}
	return out, resp, nil
}

// DeleteApplicationUser sends DELETE /api/v1/apps/{id}/users/{userId}.
func (c *Client) DeleteApplicationUser(ctx context.Context, appID, userID string) (*Response, error) {
	return c.Do(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/apps/%v/users/%v", PathEscape(appID), PathEscape(userID)), nil, nil)
}

// ListApplicationGroupAssignments reads GET /api/v1/apps/{id}/groups.
func (c *Client) ListApplicationGroupAssignments(ctx context.Context, appID string, qp *QueryParams) ([]*ApplicationGroupAssignment, *Response, error) {
	var out []*ApplicationGroupAssignment
	resp, err := c.get(ctx, fmt.Sprintf("/api/v1/apps/%v/groups", PathEscape(appID)), qp, &out)
	if err != nil {
		return nil, resp, err
	}
	return out, resp, nil
}

// GetApplicationGroupAssignment reads GET /api/v1/apps/{id}/groups/{groupId}.
func (c *Client) GetApplicationGroupAssignment(ctx context.Context, appID, groupID string) (*ApplicationGroupAssignment, *Response, error) {
	var out *ApplicationGroupAssignment
	resp, err := c.get(ctx, fmt.Sprintf("/api/v1/apps/%v/groups/%v", PathEscape(appID), PathEscape(groupID)), nil, &out)
	if err != nil {
		return nil, resp, err
	}
	return out, resp, nil
}

// CreateApplicationGroupAssignment sends PUT /api/v1/apps/{id}/groups/{groupId}.
func (c *Client) CreateApplicationGroupAssignment(ctx context.Context, appID, groupID string, body ApplicationGroupAssignment) (*ApplicationGroupAssignment, *Response, error) {
	var out *ApplicationGroupAssignment
	resp, err := c.Do(ctx, http.MethodPut, fmt.Sprintf("/api/v1/apps/%v/groups/%v", PathEscape(appID), PathEscape(groupID)), body, &out)
	if err != nil {
		return nil, resp, err
	}
	return out, resp, nil
}

// DeleteApplicationGroupAssignment sends DELETE /api/v1/apps/{id}/groups/{groupId}.
func (c *Client) DeleteApplicationGroupAssignment(ctx context.Context, appID, groupID string) (*Response, error) {
	return c.Do(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/apps/%v/groups/%v", PathEscape(appID), PathEscape(groupID)), nil, nil)
}

// ---- System Log

// ListLogEvents reads GET /api/v1/logs.
func (c *Client) ListLogEvents(ctx context.Context, qp *QueryParams) ([]*LogEvent, *Response, error) {
	var out []*LogEvent
	resp, err := c.get(ctx, "/api/v1/logs", qp, &out)
	if err != nil {
		return nil, resp, err
	}
	return out, resp, nil
}

// ---- Devices, API tokens and resource-set lookups (status-line errors)

// ListDevices reads GET /api/v1/devices, or the next page when nextPage is set.
func (c *Client) ListDevices(ctx context.Context, limit int32, nextPage string) ([]Device, *Response, error) {
	path := nextPage
	if path == "" {
		path = fmt.Sprintf("/api/v1/devices?limit=%d", limit)
	}
	var out []Device
	resp, err := c.Do(ctx, http.MethodGet, path, nil, &out, statusLineEndpoint(withFollowUpPage(nextPage != ""))...)
	return out, resp, err
}

// ListAPITokens reads GET /api/v1/api-tokens, or the next page when nextPage is set.
func (c *Client) ListAPITokens(ctx context.Context, nextPage string) ([]APIToken, *Response, error) {
	path := nextPage
	if path == "" {
		path = "/api/v1/api-tokens"
	}
	var out []APIToken
	resp, err := c.Do(ctx, http.MethodGet, path, nil, &out, statusLineEndpoint(withFollowUpPage(nextPage != ""))...)
	return out, resp, err
}

// GetAPIToken reads GET /api/v1/api-tokens/{id}.
func (c *Client) GetAPIToken(ctx context.Context, tokenID string) (*APIToken, *Response, error) {
	var out *APIToken
	resp, err := c.Do(ctx, http.MethodGet, "/api/v1/api-tokens/"+PathEscape(tokenID), nil, &out, statusLineEndpoint()...)
	if err != nil {
		return nil, resp, err
	}
	return out, resp, nil
}

// GetResourceSet reads GET /api/v1/iam/resource-sets/{id}.
func (c *Client) GetResourceSet(ctx context.Context, resourceSetID string) (*ResourceSet, *Response, error) {
	var out *ResourceSet
	resp, err := c.Do(ctx, http.MethodGet, "/api/v1/iam/resource-sets/"+PathEscape(resourceSetID), nil, &out, statusLineEndpoint()...)
	if err != nil {
		return nil, resp, err
	}
	return out, resp, nil
}

// GetResourceSetBinding reads GET /api/v1/iam/resource-sets/{id}/bindings/{roleId}.
func (c *Client) GetResourceSetBinding(ctx context.Context, resourceSetID, roleID string) (*ResourceSetBinding, *Response, error) {
	var out *ResourceSetBinding
	resp, err := c.Do(ctx, http.MethodGet,
		"/api/v1/iam/resource-sets/"+PathEscape(resourceSetID)+"/bindings/"+PathEscape(roleID), nil, &out, statusLineEndpoint()...)
	if err != nil {
		return nil, resp, err
	}
	return out, resp, nil
}

// PathEscape escapes s as a single URL path segment, including the dot segments.
func PathEscape(s string) string {
	switch s {
	case ".":
		return "%2E"
	case "..":
		return "%2E%2E"
	default:
		return url.PathEscape(s)
	}
}
