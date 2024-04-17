package main

import (
	"context"
	"fmt"

	"github.com/conductorone/baton-okta/pkg/connector"
	"github.com/spf13/cobra"
)

// validateConfig is run after the configuration is loaded, and should return an error if it isn't valid.
func validateConfig(ctx context.Context, cfg *connector.Config) error {
	if cfg.Domain == "" {
		return fmt.Errorf("domain is missing")
	}

	if cfg.ApiToken == "" {
		if cfg.OktaClientId == "" {
			return fmt.Errorf("either api token or client id is required")
		} else if cfg.OktaClientId != "" && cfg.OktaPrivateKey == "" || cfg.OktaPrivateKeyId == "" {
			return fmt.Errorf("private key and private key id required")
		}

		if cfg.OktaClientId == "" && cfg.OktaPrivateKey == "" && cfg.OktaPrivateKeyId == "" {
			return fmt.Errorf("client id, private key and private key id required")
		}
	}

	if cfg.ApiToken != "" && cfg.OktaClientId != "" {
		return fmt.Errorf("api token and client id cannot be provided simultaneously")
	}

	return nil
}

// cmdFlags sets the cmdFlags required for the connector.
func cmdFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().String("domain", "", "The URL for the Okta organization. ($BATON_DOMAIN)")
	cmd.PersistentFlags().String("okta-client-id", "", "The Okta Client ID. ($BATON_OKTA_CLIENT_ID)")
	cmd.PersistentFlags().String("okta-private-key", "", "The Okta Private Key. This can be the whole private key or the path to the private key. ($BATON_OKTA_PRIVATE_KEY)")
	cmd.PersistentFlags().String("okta-private-key-id", "", "The Okta Private Key ID. ($BATON_OKTA_PRIVATE_KEY_ID)")
	cmd.PersistentFlags().String("api-token", "", "The API token for the service account.  ($BATON_API_TOKEN)")
	cmd.PersistentFlags().Bool("sync-inactive-apps", true, "Whether to sync inactive apps or not.  ($BATON_SYNC_INACTIVE_APPS)")
}
