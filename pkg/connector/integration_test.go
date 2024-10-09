package connector

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/stretchr/testify/require"
)

var (
	batonApiToken           = os.Getenv("BATON_API_TOKEN")
	batonDomain             = os.Getenv("BATON_DOMAIN")
	batonSyncCustomRoles, _ = strconv.ParseBool(os.Getenv("BATON_SYNC_CUSTOM_ROLES"))
	ctxTest                 = context.Background()
)

func TestSyncRoles(t *testing.T) {
	if batonApiToken == "" && batonDomain == "" {
		t.Skip()
	}

	cliTest, err := getClietForTesting(ctxTest, &Config{
		Domain:   batonDomain,
		ApiToken: batonApiToken,
	})
	require.Nil(t, err)

	r := &roleResourceType{
		resourceType:    resourceTypeRole,
		client:          cliTest.client,
		syncCustomRoles: batonSyncCustomRoles,
	}

	var token = "{}"
	for token != "" {
		res, tk, _, err := r.List(ctxTest, &v2.ResourceId{}, &pagination.Token{
			Token: token,
		})
		require.Nil(t, err)
		require.NotNil(t, res)
		token = tk
	}
}

func getClietForTesting(ctx context.Context, cfg *Config) (*Okta, error) {
	var oktaClient *okta.Client
	client, err := uhttp.NewClient(ctx, uhttp.WithLogger(true, nil))
	if err != nil {
		return nil, err
	}

	if cfg.ApiToken != "" && cfg.Domain != "" {
		_, oktaClient, err = okta.NewClient(ctx,
			okta.WithOrgUrl(fmt.Sprintf("https://%s", cfg.Domain)),
			okta.WithToken(cfg.ApiToken),
			okta.WithHttpClientPtr(client),
			okta.WithCache(cfg.Cache),
			okta.WithCacheTti(cfg.CacheTTI),
			okta.WithCacheTtl(cfg.CacheTTL),
		)
		if err != nil {
			return nil, err
		}
	}

	return &Okta{
		client:           oktaClient,
		domain:           cfg.Domain,
		apiToken:         cfg.ApiToken,
		syncInactiveApps: cfg.SyncInactiveApps,
		ciamConfig: &ciamConfig{
			Enabled:      cfg.Ciam,
			EmailDomains: cfg.CiamEmailDomains,
		},
	}, nil
}
