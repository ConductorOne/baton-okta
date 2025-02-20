//go:build build_lambda_target

package config

import (
	"context"
	"strings"

	"github.com/conductorone/baton-sdk/pkg/cli"
	"github.com/conductorone/baton-sdk/pkg/connectorrunner"
	"github.com/conductorone/baton-sdk/pkg/field"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func DefineConfiguration[T any](
	ctx context.Context,
	connectorName string,
	connector cli.GetConnectorFunc[T],
	connectorConfSchema field.Configuration,
	options ...connectorrunner.Option,
) (*viper.Viper, *cobra.Command, error) {
	v := viper.New()
	v.SetEnvPrefix("BATON")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()

	lambdaConfSchema := field.NewConfiguration(field.LambdaServerFields(), field.LambdaServerRelationships...)

	// setup CLI with cobra
	mainCMD := &cobra.Command{
		Use:           connectorName,
		Short:         connectorName,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE:          cli.MakeLambdaServerCommand[T](ctx, connectorName, v, connector, lambdaConfSchema, connectorConfSchema),
	}

	// set persistent flags only on the main subcommand
	err := setFlagsAndConstraints(mainCMD, lambdaConfSchema)
	if err != nil {
		return nil, nil, err
	}

	// main subcommand
	mainCMD.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		if v.IsSet(f.Name) {
			_ = mainCMD.PersistentFlags().Set(f.Name, v.GetString(f.Name))
		}
	})

	mainCMD.Flags().VisitAll(func(f *pflag.Flag) {
		if v.IsSet(f.Name) {
			_ = mainCMD.Flags().Set(f.Name, v.GetString(f.Name))
		}
	})

	return v, mainCMD, nil
}
