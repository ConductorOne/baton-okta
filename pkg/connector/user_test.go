package connector

import "testing"

func Test_shouldIncludeUserByEmails(t *testing.T) {
	type args struct {
		userEmails         []string
		emailDomainFilters []string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "should include user by email",
			args: args{
				userEmails:         []string{"alice@foo.com"},
				emailDomainFilters: []string{"foo.com"},
			},
			want: true,
		},
		{
			name: "no match",
			args: args{
				userEmails:         []string{"alice@foo.com"},
				emailDomainFilters: []string{"example.com"},
			},
			want: false,
		},
		{
			name: "multiple filters",
			args: args{
				userEmails:         []string{"alice@foo.com"},
				emailDomainFilters: []string{"example.com", "foo.com"},
			},
			want: true,
		},
		{
			name: "no filters",
			args: args{
				userEmails:         []string{"alice@foo.com"},
				emailDomainFilters: []string{},
			},
			want: false,
		},
		{
			name: "no filters (nil list)",
			args: args{
				userEmails:         []string{"alice@foo.com"},
				emailDomainFilters: nil,
			},
			want: false,
		},
		{
			name: "empty filters (has capacity)",
			args: args{
				userEmails:         []string{"alice@foo.com"},
				emailDomainFilters: make([]string, 0, 100),
			},
			want: false,
		},
		{
			name: "multiple emails, no match",
			args: args{
				userEmails:         []string{"alice@foo.com", "bob@example.com"},
				emailDomainFilters: []string{"test.com"},
			},
			want: false,
		},
		{
			name: "multiple emails, multiple matches",
			args: args{
				userEmails:         []string{"alice@foo.com", "bob@example.com"},
				emailDomainFilters: []string{"foo.com", "example.com"},
			},
			want: true,
		},
		{
			name: "multiple emails, single match",
			args: args{
				userEmails:         []string{"alice@foo.com", "bob@example.com", "carlos@test.com"},
				emailDomainFilters: []string{"test.com"},
			},
			want: true,
		},
		{
			name: "mixed case match",
			args: args{
				userEmails:         []string{"alice@fOo.cOm"},
				emailDomainFilters: []string{"foo.com"},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldIncludeUserByEmails(tt.args.userEmails, tt.args.emailDomainFilters); got != tt.want {
				t.Errorf("shouldIncludeUserByEmails() = %v, want %v", got, tt.want)
			}
		})
	}
}
