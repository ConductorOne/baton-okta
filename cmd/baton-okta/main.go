package main

import (
	"context"
	"fmt"
	"os"

	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/types"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/conductorone/baton-okta/pkg/connector"
	configschema "github.com/conductorone/baton-sdk/pkg/config"
)

var version = "dev"

func main() {
	ctx := context.Background()
	_, cmd, err := configschema.DefineConfiguration(ctx, "baton-okta", getConnector, configuration)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	cmd.Version = version
	err = cmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func getConnector(ctx context.Context, v *viper.Viper) (types.ConnectorServer, error) {
	l := ctxzap.Extract(ctx)
	ccfg := &connector.Config{
		Domain:           v.GetString("domain"),
		ApiToken:         v.GetString("api-token"),
		OktaClientId:     v.GetString("okta-client-id"),
		OktaPrivateKey:   v.GetString("okta-private-key"),
		OktaPrivateKeyId: v.GetString("okta-private-key-id"),
		SyncInactiveApps: v.GetBool("sync-inactive-apps"),
		OktaProvisioning: v.GetBool("okta-provisioning"),
		Ciam:             v.GetBool("ciam"),
		CiamEmailDomains: v.GetStringSlice("ciam-email-domains"),
		Cache:            v.GetBool("cache"),
		CacheTTI:         v.GetInt32("cache-tti"),
		CacheTTL:         v.GetInt32("cache-ttl"),
		SyncCustomRoles:  v.GetBool("sync-custom-roles"),
		AWSMode:          v.GetBool("aws-identity-center-mode"),
		AWSOktaAppId:     v.GetString("aws-okta-app-id"),
	}

	cb, err := connector.New(ctx, ccfg)
	if err != nil {
		l.Error("error creating connector", zap.Error(err))
		return nil, err
	}

	connector, err := connectorbuilder.NewConnector(ctx, cb)
	if err != nil {
		l.Error("error creating connector", zap.Error(err))
		return nil, err
	}

	return connector, nil
}
