package okta

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// Error is the error body the Okta Management API returns
// (https://developer.okta.com/docs/reference/error-codes/), plus the OAuth
// error fields the authorization server uses.
type Error struct {
	ErrorMessage     string           `json:"error"`
	ErrorDescription string           `json:"error_description"`
	ErrorCode        string           `json:"errorCode,omitempty"`
	ErrorSummary     string           `json:"errorSummary,omitempty"`
	ErrorLink        string           `json:"errorLink,omitempty"`
	ErrorId          string           `json:"errorId,omitempty"`
	ErrorCauses      []map[string]any `json:"errorCauses,omitempty"`
}

func (e *Error) Error() string {
	formattedErr := "the API returned an unknown error"
	if e.ErrorDescription != "" {
		formattedErr = fmt.Sprintf("the API returned an error: %s", e.ErrorDescription)
	} else if e.ErrorSummary != "" {
		formattedErr = fmt.Sprintf("the API returned an error: %s", e.ErrorSummary)
	}
	if len(e.ErrorCauses) > 0 {
		var causes []string
		for _, cause := range e.ErrorCauses {
			for key, val := range cause {
				causes = append(causes, fmt.Sprintf("%s: %v", key, val))
			}
		}
		formattedErr = fmt.Sprintf("%s. Causes: %s", formattedErr, strings.Join(causes, ", "))
	}
	return formattedErr
}

// GenericError is returned by the endpoints whose callers only surface the
// HTTP status line (devices, API tokens, resource-set lookups). Message is the
// status line, or the reason the error body could not be decoded.
type GenericError struct {
	Message string
	Body    []byte
	Model   *Error
}

func (e *GenericError) Error() string { return e.Message }

type errorStyle int

const (
	// errorStyleOkta returns *Error for any status >= 400.
	errorStyleOkta errorStyle = iota
	// errorStyleGeneric returns *GenericError for any status >= 300.
	errorStyleGeneric
)

func responseError(style errorStyle, resp *http.Response, body []byte) error {
	switch style {
	case errorStyleGeneric:
		return genericResponseError(resp, body)
	case errorStyleOkta:
		return checkResponse(resp, body)
	default:
		return checkResponse(resp, body)
	}
}

// CheckResponseForError returns the *Error for a non-2xx/3xx response, or nil.
// The body stays readable afterwards.
func CheckResponseForError(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return checkResponse(resp, body)
}

func checkResponse(resp *http.Response, body []byte) error {
	statusCode := resp.StatusCode
	if statusCode >= http.StatusOK && statusCode < http.StatusBadRequest {
		return nil
	}
	e := Error{}
	if (statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden) &&
		strings.Contains(resp.Header.Get("Www-Authenticate"), "Bearer") {
		for _, v := range strings.Split(resp.Header.Get("Www-Authenticate"), ", ") {
			if strings.Contains(v, "error_description") {
				desc, ok := parseAuthParam(v, "error_description")
				if !ok {
					e.ErrorSummary = "unauthorized"
				} else {
					e.ErrorSummary = desc
				}
				return &e
			}
		}
	}
	_ = json.Unmarshal(body, &e)
	if statusCode == http.StatusInternalServerError {
		e.ErrorSummary += fmt.Sprintf(", x-okta-request-id=%s", resp.Header.Get("x-okta-request-id"))
	}
	return &e
}

// parseAuthParam reads a single `name="value"` WWW-Authenticate parameter.
// The whole fragment must be that one parameter.
func parseAuthParam(fragment, name string) (string, bool) {
	k, v, ok := strings.Cut(strings.TrimSpace(fragment), "=")
	if !ok || strings.TrimSpace(k) != name {
		return "", false
	}
	v = strings.TrimSpace(v)
	if !strings.HasPrefix(v, `"`) {
		return "", false
	}
	unq, err := strconv.Unquote(v)
	if err != nil {
		return "", false
	}
	return unq, true
}

var jsonContentType = regexp.MustCompile(`(?i:(?:application|text)/(?:vnd\.[^;]+\+)?json)`)

func genericResponseError(resp *http.Response, body []byte) error {
	if resp.StatusCode < http.StatusMultipleChoices {
		return nil
	}
	gerr := &GenericError{Message: resp.Status, Body: body}
	switch resp.StatusCode {
	case http.StatusForbidden, http.StatusNotFound, http.StatusTooManyRequests:
		if len(body) == 0 {
			gerr.Model = &Error{}
			return gerr
		}
		if !jsonContentType.MatchString(resp.Header.Get("Content-Type")) {
			gerr.Message = "undefined response type"
			return gerr
		}
		var model Error
		if err := json.Unmarshal(body, &model); err != nil {
			gerr.Message = err.Error()
			return gerr
		}
		gerr.Model = &model
	}
	return gerr
}
