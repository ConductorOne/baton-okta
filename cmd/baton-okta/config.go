package main

import (
	"context"
	"fmt"

	"github.com/conductorone/baton-sdk/pkg/cli"
	"github.com/spf13/cobra"
)

// config defines the external configuration required for the connector to run.
type config struct {
	cli.BaseConfig `mapstructure:",squash"` // Puts the base config options in the same place as the connector options

	Domain           string `mapstructure:"domain"`
	ApiToken         string `mapstructure:"api-token"`
	OktaClientId     string `mapstructure:"okta-client-id"`
	OktaPrivateKey   string `mapstructure:"okta-private-key"`
	OktaPrivateKeyId string `mapstructure:"okta-private-key-id"`
	SyncInactiveApps bool   `mapstructure:"sync-inactive-apps"`
	OktaProvisioning bool   `mapstructure:"provisioning"`
}

// validateConfig is run after the configuration is loaded, and should return an error if it isn't valid.
func validateConfig(ctx context.Context, cfg *config) error {
	if cfg.Domain == "" {
		return fmt.Errorf("domain is missing")
	}

	if cfg.OktaClientId == "" && cfg.ApiToken == "" {
		return fmt.Errorf("api token is missing")
	}

	return nil
}

// cmdFlags sets the cmdFlags required for the connector.
func cmdFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().String("domain", "", "The URL for the Okta organization. ($BATON_DOMAIN)")
	cmd.PersistentFlags().String("okta-client-id", "", "The Okta Client ID. ($BATON_OKTA_CLIENT_ID)")
	cmd.PersistentFlags().String("okta-private-key", "", "The Okta Private Key. ($BATON_OKTA_PRIVATE_KEY)")
	cmd.PersistentFlags().String("okta-private-key-id", "", "The Okta Private Key ID. ($BATON_OKTA_PRIVATE_KEY_ID)")
	cmd.PersistentFlags().String("api-token", "", "The API token for the service account.  ($BATON_API_TOKEN)")
	cmd.PersistentFlags().Bool("sync-inactive-apps", true, "Whether to sync inactive apps or not.  ($BATON_SYNC_INACTIVE_APPS)")
}
