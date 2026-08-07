package connector

import (
	"strings"
	"testing"
)

func TestParseOktaOrgURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr string
	}{
		{name: "bare host", raw: "acmeco.okta.com", want: "https://acmeco.okta.com"},
		{name: "https scheme", raw: "https://acmeco.okta.com", want: "https://acmeco.okta.com"},
		{name: "https with trailing slash", raw: "https://acmeco.okta.com/", want: "https://acmeco.okta.com"},
		{name: "bare host with trailing slash", raw: "acmeco.okta.com/", want: "https://acmeco.okta.com"},
		{name: "whitespace", raw: "  acmeco.okta.com  ", want: "https://acmeco.okta.com"},
		{name: "empty", raw: "", wantErr: "domain is required"},
		{name: "whitespace only", raw: "   ", wantErr: "domain is required"},
		{name: "scheme only", raw: "https://", wantErr: "domain must be an HTTPS hostname"},
		{name: "http scheme", raw: "http://acmeco.okta.com", wantErr: "domain must be an HTTPS hostname"},
		{name: "path", raw: "https://acmeco.okta.com/admin", wantErr: "domain must be an HTTPS hostname"},
		{name: "bare path", raw: "acmeco.okta.com/admin", wantErr: "domain must be an HTTPS hostname"},
		{name: "query", raw: "https://acmeco.okta.com?redirect=evil.example", wantErr: "domain must be an HTTPS hostname"},
		{name: "fragment", raw: "https://acmeco.okta.com#fragment", wantErr: "domain must be an HTTPS hostname"},
		{name: "userinfo", raw: "https://user@acmeco.okta.com", wantErr: "domain must be an HTTPS hostname"},
		{name: "port", raw: "https://acmeco.okta.com:8443", wantErr: "domain must be an HTTPS hostname"},
		{name: "double scheme", raw: "https://https://acmeco.okta.com", wantErr: "domain must be an HTTPS hostname"},
		{name: "garbage", raw: "://", wantErr: "domain must be an HTTPS hostname"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseOktaOrgURL(tt.raw)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("parseOktaOrgURL(%q) = %q, want error containing %q", tt.raw, got, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				if !strings.Contains(err.Error(), "domain") {
					t.Fatalf("error must name the domain field, got %q", err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("parseOktaOrgURL(%q): %v", tt.raw, err)
			}
			if got.String() != tt.want {
				t.Fatalf("parseOktaOrgURL(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}
