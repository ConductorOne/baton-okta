package connector

import (
	"testing"

	"github.com/conductorone/baton-sdk/pkg/cli"
)

func TestShouldFetchApiTokens(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		syncSecrets bool
		opts        *cli.ConnectorOpts
		want        bool
	}{
		{
			name:        "deprecated flag still fetches",
			syncSecrets: true,
			opts:        &cli.ConnectorOpts{},
			want:        true,
		},
		{
			name:        "unfiltered sync does not fetch",
			syncSecrets: false,
			opts:        &cli.ConnectorOpts{},
			want:        false,
		},
		{
			name:        "explicit opt-in fetches",
			syncSecrets: false,
			opts:        &cli.ConnectorOpts{SyncResourceTypeIDs: []string{resourceTypeApiToken.Id}},
			want:        true,
		},
		{
			name:        "explicit filter without api-token does not fetch",
			syncSecrets: false,
			opts:        &cli.ConnectorOpts{SyncResourceTypeIDs: []string{resourceTypeUser.Id}},
			want:        false,
		},
		{
			name:        "flag wins over filter that omits api-token",
			syncSecrets: true,
			opts:        &cli.ConnectorOpts{SyncResourceTypeIDs: []string{resourceTypeUser.Id}},
			want:        true,
		},
		{
			name:        "nil opts (capabilities) reports fetch",
			syncSecrets: false,
			opts:        nil,
			want:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			o := &Okta{SyncSecrets: tt.syncSecrets, opts: tt.opts}
			if got := o.shouldFetchApiTokens(); got != tt.want {
				t.Fatalf("shouldFetchApiTokens() = %v, want %v", got, tt.want)
			}
		})
	}
}
