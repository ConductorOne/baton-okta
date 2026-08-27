package connector

import (
	"slices"
	"testing"

	cfg "github.com/conductorone/baton-okta/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/cli"
)

const logsReadScope = "okta.logs.read"

// Okta issues a token carrying only the requested scopes the app has also granted,
// so dropping okta.logs.read from this list makes the event feed fail on every run
// no matter what the customer grants in Okta. Verified against a live tenant: with
// the scope granted but not requested, GET /api/v1/logs returns 403.
func TestPrivateKeyScopes_AlwaysRequestsSystemLogRead(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		cc   *cfg.Okta
		opts *cli.ConnectorOpts
	}{
		{name: "defaults", cc: &cfg.Okta{}, opts: nil},
		{name: "secrets sync on", cc: &cfg.Okta{SyncSecrets: true}, opts: nil},
		{
			name: "explicit sync filter excluding devices",
			cc:   &cfg.Okta{},
			opts: &cli.ConnectorOpts{SyncResourceTypeIDs: []string{resourceTypeUser.Id}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := privateKeyScopes(tc.cc, tc.opts); !slices.Contains(got, logsReadScope) {
				t.Errorf("scopes = %v, want %q present", got, logsReadScope)
			}
		})
	}
}

func TestPrivateKeyScopes_ConditionalScopes(t *testing.T) {
	t.Parallel()

	base := privateKeyScopes(&cfg.Okta{}, nil)
	if slices.Contains(base, apiTokensReadScope) {
		t.Errorf("%q requested without --sync-secrets", apiTokensReadScope)
	}
	if !slices.Contains(base, devicesReadScope) {
		t.Errorf("%q missing when no sync filter narrows it out", devicesReadScope)
	}

	withSecrets := privateKeyScopes(&cfg.Okta{SyncSecrets: true}, nil)
	if !slices.Contains(withSecrets, apiTokensReadScope) {
		t.Errorf("%q missing with --sync-secrets", apiTokensReadScope)
	}

	// A filter that names only users must not pull in the device scope.
	narrowed := privateKeyScopes(&cfg.Okta{}, &cli.ConnectorOpts{
		SyncResourceTypeIDs: []string{resourceTypeUser.Id},
	})
	if slices.Contains(narrowed, devicesReadScope) {
		t.Errorf("%q requested although device sync is filtered out", devicesReadScope)
	}
}

// Every read and manage scope the sync itself depends on has to stay listed.
func TestPrivateKeyScopes_CoversReadAndManage(t *testing.T) {
	t.Parallel()

	got := privateKeyScopes(&cfg.Okta{}, nil)
	for _, want := range slices.Concat(defaultScopes, provisioningScopes, eventFeedScopes) {
		if !slices.Contains(got, want) {
			t.Errorf("scopes = %v, want %q present", got, want)
		}
	}
	// Okta rejects nothing for a duplicate, but a repeat means the assembly is
	// appending the same source twice.
	seen := map[string]bool{}
	for _, s := range got {
		if seen[s] {
			t.Errorf("scope %q requested twice: %v", s, got)
		}
		seen[s] = true
	}
}

// The assembly used to start from `scopes = defaultScopes` and append, which only
// avoided mutating the package-level slice because its capacity happened to be
// exhausted. Pin that the sources are untouched.
func TestPrivateKeyScopes_DoesNotMutatePackageSlices(t *testing.T) {
	t.Parallel()

	defaultsBefore := slices.Clone(defaultScopes)
	provisioningBefore := slices.Clone(provisioningScopes)
	eventFeedBefore := slices.Clone(eventFeedScopes)

	_ = privateKeyScopes(&cfg.Okta{SyncSecrets: true}, nil)
	_ = privateKeyScopes(&cfg.Okta{}, nil)

	if !slices.Equal(defaultScopes, defaultsBefore) {
		t.Errorf("defaultScopes mutated: %v, want %v", defaultScopes, defaultsBefore)
	}
	if !slices.Equal(provisioningScopes, provisioningBefore) {
		t.Errorf("provisioningScopes mutated: %v, want %v", provisioningScopes, provisioningBefore)
	}
	if !slices.Equal(eventFeedScopes, eventFeedBefore) {
		t.Errorf("eventFeedScopes mutated: %v, want %v", eventFeedScopes, eventFeedBefore)
	}
}
