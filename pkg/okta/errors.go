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
	"unicode/utf8"
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
	// cause is the transport error when the request got no response.
	cause error
}

func (e *GenericError) Error() string { return e.Message }

func (e *GenericError) Unwrap() error { return e.cause }

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
// The body stays readable afterwards. The connector decodes responses through
// Client; this is exported for pkg/oktaauth's tests, which check how a
// rewritten DPoP rejection renders.
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

// parseAuthParam reads one comma-separated WWW-Authenticate fragment the way
// Okta's error decoding always has: as a single TOML `key = "value"` line. It
// returns the value when the key is name, "" when the line holds a different
// string-valued key, and ok=false when the fragment is not such a line. So a
// fragment carrying several space-separated pairs, or the scheme name ("Bearer
// error_description=..."), is rejected, while single-quoted, triple-quoted and
// escaped values and a trailing "# comment" are accepted.
func parseAuthParam(fragment, name string) (string, bool) {
	rest := strings.TrimLeft(fragment, " \t")
	key, rest, ok := tomlKey(rest)
	if !ok {
		return "", false
	}
	rest = strings.TrimLeft(rest, " \t")
	if !strings.HasPrefix(rest, "=") {
		return "", false
	}
	val, rest, ok := tomlString(strings.TrimLeft(rest[1:], " \t"))
	if !ok {
		return "", false
	}
	rest = strings.TrimLeft(rest, " \t")
	if rest != "" && !strings.HasPrefix(rest, "#") {
		return "", false
	}
	if key != name {
		return "", true
	}
	return val, true
}

// tomlKey reads a bare or quoted TOML key from the start of s.
func tomlKey(s string) (string, string, bool) {
	if strings.HasPrefix(s, `"`) || strings.HasPrefix(s, "'") {
		return tomlString(s)
	}
	i := 0
	for i < len(s) && (s[i] == '_' || s[i] == '-' ||
		(s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= '0' && s[i] <= '9')) {
		i++
	}
	if i == 0 {
		return "", "", false
	}
	return s[:i], s[i:], true
}

// tomlString reads a TOML string (basic, literal, or either multi-line form)
// from the start of s and returns its value and the remaining input.
func tomlString(s string) (string, string, bool) {
	switch {
	case strings.HasPrefix(s, `"""`):
		return tomlBasic(s[3:], `"""`)
	case strings.HasPrefix(s, `'''`):
		end := strings.Index(s[3:], `'''`)
		if end < 0 {
			return "", "", false
		}
		return s[3 : 3+end], s[3+end+3:], true
	case strings.HasPrefix(s, `"`):
		return tomlBasic(s[1:], `"`)
	case strings.HasPrefix(s, `'`):
		end := strings.IndexByte(s[1:], '\'')
		if end < 0 {
			return "", "", false
		}
		return s[1 : 1+end], s[1+end+1:], true
	}
	return "", "", false
}

// tomlBasic decodes a basic string body up to the closing delimiter, applying
// TOML's escapes.
func tomlBasic(s, closing string) (string, string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); {
		if strings.HasPrefix(s[i:], closing) {
			return b.String(), s[i+len(closing):], true
		}
		c := s[i]
		switch {
		case c == '\\':
			if i+1 >= len(s) {
				return "", "", false
			}
			n := 2
			switch s[i+1] {
			case 'b':
				b.WriteByte('\b')
			case 't':
				b.WriteByte('\t')
			case 'n':
				b.WriteByte('\n')
			case 'f':
				b.WriteByte('\f')
			case 'r':
				b.WriteByte('\r')
			case '"':
				b.WriteByte('"')
			case '\\':
				b.WriteByte('\\')
			case 'u', 'U':
				digits := 4
				if s[i+1] == 'U' {
					digits = 8
				}
				if i+2+digits > len(s) {
					return "", "", false
				}
				r, err := strconv.ParseUint(s[i+2:i+2+digits], 16, 32)
				if err != nil || !utf8.ValidRune(rune(r)) {
					return "", "", false
				}
				b.WriteRune(rune(r))
				n += digits
			default:
				return "", "", false
			}
			i += n
		case (c < 0x20 && c != '\t') || c == 0x7f:
			return "", "", false
		default:
			b.WriteByte(c)
			i++
		}
	}
	return "", "", false
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
			return gerr
		}
		if !jsonContentType.MatchString(resp.Header.Get("Content-Type")) {
			gerr.Message = "undefined response type"
			return gerr
		}
		// The error model is decoded only to surface a malformed body.
		var model Error
		if err := json.Unmarshal(body, &model); err != nil {
			gerr.Message = err.Error()
		}
	}
	return gerr
}
