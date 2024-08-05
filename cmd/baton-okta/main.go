package main

import (
	"context"
	"fmt"
	"os"

	"github.com/conductorone/baton-sdk/pkg/cli"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/types"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"

	"github.com/conductorone/baton-okta/pkg/connector"
)

var version = "dev"

func main() {
	ctx := context.Background()

	cfg := &Config{}
	cmd, err := cli.NewCmd(ctx, "baton-okta", cfg, validateConfig, getConnector)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	cmd.Version = version

	cmdFlags(cmd)

	err = cmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func getConnector(ctx context.Context, cfg *Config) (types.ConnectorServer, error) {
	l := ctxzap.Extract(ctx)

	ccfg := &connector.Config{
		Domain:           cfg.Domain,
		ApiToken:         cfg.ApiToken,
		OktaClientId:     cfg.OktaClientId,
		OktaPrivateKey:   cfg.OktaPrivateKey,
		OktaPrivateKeyId: cfg.OktaPrivateKeyId,
		SyncInactiveApps: cfg.SyncInactiveApps,
		OktaProvisioning: cfg.OktaProvisioning,
		Ciam:             cfg.Ciam,
		CiamEmailDomains: cfg.CiamEmailDomains,
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
