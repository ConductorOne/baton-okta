//go:build !build_lambda_target

package config

import (
	"context"
	"errors"
	"fmt"
	"os"
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
	schema field.Configuration,
	options ...connectorrunner.Option,
) (*viper.Viper, *cobra.Command, error) {
	if err := verifyStructFields[T](schema); err != nil {
		return nil, nil, fmt.Errorf("VerifyStructFields failed: %w", err)
	}

	v := viper.New()
	v.SetConfigType("yaml")

	path, name, err := cleanOrGetConfigPath(os.Getenv("BATON_CONFIG_PATH"))
	if err != nil {
		return nil, nil, err
	}

	v.SetConfigName(name)
	v.AddConfigPath(path)
	if err := v.ReadInConfig(); err != nil {
		if errors.Is(err, viper.ConfigFileNotFoundError{}) {
			return nil, nil, err
		}
	}
	v.SetEnvPrefix("baton")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()

	confschema := schema
	confschema.Fields = append(field.DefaultFields, confschema.Fields...)
	// Ensure unique fields
	uniqueFields := make(map[string]field.SchemaField)
	for _, f := range confschema.Fields {
		uniqueFields[f.FieldName] = f
	}
	confschema.Fields = make([]field.SchemaField, 0, len(uniqueFields))
	for _, f := range uniqueFields {
		confschema.Fields = append(confschema.Fields, f)
	}
	// setup CLI with cobra
	mainCMD := &cobra.Command{
		Use:           connectorName,
		Short:         connectorName,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE:          cli.MakeMainCommand(ctx, connectorName, v, confschema, connector, options...),
	}
	// set persistent flags only on the main subcommand
	err = setFlagsAndConstraints(mainCMD, field.NewConfiguration(field.DefaultFields, field.DefaultRelationships...))
	if err != nil {
		return nil, nil, err
	}

	// set the rest of flags
	err = setFlagsAndConstraints(mainCMD, schema)
	if err != nil {
		return nil, nil, err
	}

	grpcServerCmd := &cobra.Command{
		Use:    "_connector-service",
		Short:  "Start the connector service",
		Hidden: true,
		RunE:   cli.MakeGRPCServerCommand(ctx, connectorName, v, confschema, connector),
	}
	err = setFlagsAndConstraints(grpcServerCmd, schema)
	if err != nil {
		return nil, nil, err
	}
	mainCMD.AddCommand(grpcServerCmd)

	capabilitiesCmd := &cobra.Command{
		Use:   "capabilities",
		Short: "Get connector capabilities",
		RunE:  cli.MakeCapabilitiesCommand(ctx, connectorName, v, confschema, connector),
	}
	err = setFlagsAndConstraints(capabilitiesCmd, schema)
	if err != nil {
		return nil, nil, err
	}
	mainCMD.AddCommand(capabilitiesCmd)

	mainCMD.AddCommand(cli.AdditionalCommands(connectorName, schema.Fields)...)

	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Get the connector config schema",
		RunE:  cli.MakeConfigSchemaCommand(ctx, connectorName, v, confschema, connector),
	}
	mainCMD.AddCommand(configCmd)

	// NOTE(shackra): Set all values from Viper to the flags so
	// that Cobra won't complain that a flag is missing in case we
	// pass values through environment variables

	// main subcommand
	mainCMD.Flags().VisitAll(func(f *pflag.Flag) {
		if v.IsSet(f.Name) {
			_ = mainCMD.Flags().Set(f.Name, v.GetString(f.Name))
		}
	})

	// children process subcommand
	grpcServerCmd.Flags().VisitAll(func(f *pflag.Flag) {
		if v.IsSet(f.Name) {
			_ = grpcServerCmd.Flags().Set(f.Name, v.GetString(f.Name))
		}
	})

	// capabilities subcommand
	capabilitiesCmd.Flags().VisitAll(func(f *pflag.Flag) {
		if v.IsSet(f.Name) {
			_ = capabilitiesCmd.Flags().Set(f.Name, v.GetString(f.Name))
		}
	})

	return v, mainCMD, nil
}
