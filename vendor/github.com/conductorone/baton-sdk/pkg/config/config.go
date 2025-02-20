package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/conductorone/baton-sdk/pkg/field"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func verifyStructFields[T any](schema field.Configuration) error {
	// Verify that every field in the confschema has a corresponding struct tag in the struct defined in getconnector of type T
	//  or that it obeys the old interface, a *viper.Viper
	var config T // Create a zero-value instance of T
	tType := reflect.TypeOf(config)
	// Viper doesn't do struct fields
	if tType == reflect.TypeOf(viper.Viper{}) {
		return nil
	}
	configType := reflect.TypeOf(config)
	if configType.Kind() == reflect.Ptr {
		configType = configType.Elem()
	}
	if configType.Kind() != reflect.Struct {
		return fmt.Errorf("T must be a struct type, got %v", configType.Kind())
	}
	for _, field := range schema.Fields {
		fieldFound := false
		for i := 0; i < configType.NumField(); i++ {
			structField := configType.Field(i)
			if structField.Tag.Get("mapstructure") == field.FieldName {
				fieldFound = true
				break
			}
		}
		if !fieldFound {
			// This means a connector may not set an export target of none.
			return fmt.Errorf("field %s in confschema does not have a corresponding struct tag in the configuration struct", field.FieldName)
		}
	}
	return nil
}

func listFieldConstrainsAsStrings(constrains field.SchemaFieldRelationship) []string {
	var fields []string
	for _, v := range constrains.Fields {
		fields = append(fields, v.FieldName)
	}

	return fields
}

func cleanOrGetConfigPath(customPath string) (string, string, error) {
	if customPath != "" {
		cfgDir, cfgFile := filepath.Split(filepath.Clean(customPath))
		if cfgDir == "" {
			cfgDir = "."
		}

		ext := filepath.Ext(cfgFile)
		if ext == "" || (ext != ".yaml" && ext != ".yml") {
			return "", "", errors.New("expected config file to have .yaml or .yml extension")
		}

		return strings.TrimSuffix(
				cfgDir,
				string(filepath.Separator),
			), strings.TrimSuffix(
				cfgFile,
				ext,
			), nil
	}

	return ".", ".baton", nil
}

func setFlagsAndConstraints(command *cobra.Command, schema field.Configuration) error {
	// add options
	for _, f := range schema.Fields {
		switch f.Variant {
		case field.BoolVariant:
			value, err := field.GetDefaultValue[bool](f)
			if err != nil {
				return fmt.Errorf(
					"field %s, %s: %w",
					f.FieldName,
					f.Variant,
					err,
				)
			}
			if f.IsPersistent() {
				command.PersistentFlags().
					BoolP(f.FieldName, f.GetCLIShortHand(), *value, f.GetDescription())
			} else {
				command.Flags().
					BoolP(f.FieldName, f.GetCLIShortHand(), *value, f.GetDescription())
			}
		case field.IntVariant:
			value, err := field.GetDefaultValue[int](f)
			if err != nil {
				return fmt.Errorf(
					"field %s, %s: %w",
					f.FieldName,
					f.Variant,
					err,
				)
			}
			if f.IsPersistent() {
				command.PersistentFlags().
					IntP(f.FieldName, f.GetCLIShortHand(), *value, f.GetDescription())
			} else {
				command.Flags().
					IntP(f.FieldName, f.GetCLIShortHand(), *value, f.GetDescription())
			}
		case field.StringVariant:
			value, err := field.GetDefaultValue[string](f)
			if err != nil {
				return fmt.Errorf(
					"field %s, %s: %w",
					f.FieldName,
					f.Variant,
					err,
				)
			}
			if f.IsPersistent() {
				command.PersistentFlags().
					StringP(f.FieldName, f.GetCLIShortHand(), *value, f.GetDescription())
			} else {
				command.Flags().
					StringP(f.FieldName, f.GetCLIShortHand(), *value, f.GetDescription())
			}

		case field.StringSliceVariant:
			value, err := field.GetDefaultValue[[]string](f)
			if err != nil {
				return fmt.Errorf(
					"field %s, %s: %w",
					f.FieldName,
					f.Variant,
					err,
				)
			}
			if f.IsPersistent() {
				command.PersistentFlags().
					StringSliceP(f.FieldName, f.GetCLIShortHand(), *value, f.GetDescription())
			} else {
				command.Flags().
					StringSliceP(f.FieldName, f.GetCLIShortHand(), *value, f.GetDescription())
			}
		default:
			return fmt.Errorf(
				"field %s, %s is not yet supported",
				f.FieldName,
				f.Variant,
			)
		}

		// mark hidden
		if f.IsHidden() {
			if f.IsPersistent() {
				err := command.PersistentFlags().MarkHidden(f.FieldName)
				if err != nil {
					return fmt.Errorf(
						"cannot hide persistent field %s, %s: %w",
						f.FieldName,
						f.Variant,
						err,
					)
				}
			} else {
				err := command.Flags().MarkHidden(f.FieldName)
				if err != nil {
					return fmt.Errorf(
						"cannot hide field %s, %s: %w",
						f.FieldName,
						f.Variant,
						err,
					)
				}
			}
		}

		// mark required
		if f.Required {
			if f.Variant == field.BoolVariant {
				return fmt.Errorf("requiring %s of type %s does not make sense", f.FieldName, f.Variant)
			}

			if f.IsPersistent() {
				err := command.MarkPersistentFlagRequired(f.FieldName)
				if err != nil {
					return fmt.Errorf(
						"cannot require persistent field %s, %s: %w",
						f.FieldName,
						f.Variant,
						err,
					)
				}
			} else {
				err := command.MarkFlagRequired(f.FieldName)
				if err != nil {
					return fmt.Errorf(
						"cannot require field %s, %s: %w",
						f.FieldName,
						f.Variant,
						err,
					)
				}
			}
		}
	}

	// apply constrains
	for _, constrain := range schema.Constraints {
		switch constrain.Kind {
		case field.MutuallyExclusive:
			command.MarkFlagsMutuallyExclusive(listFieldConstrainsAsStrings(constrain)...)
		case field.RequiredTogether:
			command.MarkFlagsRequiredTogether(listFieldConstrainsAsStrings(constrain)...)
		case field.AtLeastOne:
			command.MarkFlagsOneRequired(listFieldConstrainsAsStrings(constrain)...)
		case field.Dependents:
			// do nothing
		default:
			return fmt.Errorf("invalid config")
		}
	}

	return nil
}
