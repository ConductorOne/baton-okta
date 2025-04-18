//go:build windows

package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
	"gopkg.in/yaml.v2"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/spf13/cobra"

	"github.com/conductorone/baton-sdk/pkg/field"
	"github.com/conductorone/baton-sdk/pkg/logging"
)

const (
	defaultConfigFile = "config.yaml"
)

func isService() bool {
	ok, _ := svc.IsWindowsService()
	return ok
}

func setupService(name string) error {
	if !isService() {
		return nil
	}

	err := os.Setenv("BATON_CONFIG_PATH", filepath.Join(getConfigDir(name), defaultConfigFile))
	if err != nil {
		return err
	}

	return nil
}

func getConfigDir(name string) string {
	return filepath.Join(os.Getenv("PROGRAMDATA"), "ConductorOne", name)
}

var skipServiceSetupFields = map[string]struct{}{
	"LogLevel":           {},
	"LogFormat":          {},
	"BaseConfig":         {},
	"C1zPath":            {},
	"GrantEntitlementID": {},
	"GrantPrincipalID":   {},
	"GrantPrincipalType": {},
	"RevokeGrantID":      {},
}

func getExePath() (string, error) {
	p, err := filepath.Abs(os.Args[0])
	if err != nil {
		return "", err
	}

	fInfo, err := os.Stat(p)
	if err != nil {
		return "", err
	}
	if fInfo.Mode().IsDir() {
		return "", fmt.Errorf("path is a directory")
	}

	if filepath.Ext(p) == "" {
		p += ".exe"
		fi, err := os.Stat(p)
		if err != nil {
			return "", err
		}
		if fi.Mode().IsDir() {
			return "", fmt.Errorf("path is a directory")
		}
	}

	return p, err
}

func initLogger(ctx context.Context, name string, loggingOpts ...logging.Option) (context.Context, error) {
	if isService() {
		defaultLoggingOpts := []logging.Option{
			logging.WithLogFormat(logging.LogFormatJSON),
			logging.WithLogLevel("info"),
			logging.WithOutputPaths([]string{filepath.Join(getConfigDir(name), "baton.log")}),
		}
		loggingOpts = append(defaultLoggingOpts, loggingOpts...)
	}

	return logging.Init(ctx, loggingOpts...)
}

func startCmd(name string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: fmt.Sprintf("Start the %s service", name),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, err := initLogger(
				context.Background(),
				name,
				logging.WithLogFormat(logging.LogFormatConsole),
				logging.WithLogLevel("info"),
			)

			l := ctxzap.Extract(ctx).With(zap.String("service_name", name))
			l.Info("Starting service.")

			s, closeSvc, err := getWindowsService(ctx, name)
			if err != nil {
				l.Error("Failed to get service.", zap.Error(err))
				return err
			}
			defer closeSvc()

			err = s.Start()
			if err != nil {
				l.Error("Failed to start service.", zap.Error(err))
				return err
			}

			return nil
		},
	}
	return cmd
}

func stopCmd(name string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stop",
		Short: fmt.Sprintf("Stop the %s service", name),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, err := initLogger(
				context.Background(),
				name,
				logging.WithLogFormat(logging.LogFormatConsole),
				logging.WithLogLevel("info"),
			)

			l := ctxzap.Extract(ctx).With(zap.String("service_name", name))
			l.Info("Stopping service.")

			s, closeSvc, err := getWindowsService(ctx, name)
			if err != nil {
				l.Error("Failed to get service.", zap.Error(err))
				return err
			}
			defer closeSvc()

			status, err := s.Control(svc.Stop)
			if err != nil {
				l.Error("Failed to stop service.", zap.Error(err))
				return err
			}

			changeCtx, cancel := context.WithDeadline(ctx, time.Now().Add(10*time.Second))
			defer cancel()
			for {
				select {
				case <-changeCtx.Done():
					l.Error("Failed to stop service within 10 seconds.", zap.Error(err))
					return changeCtx.Err()

				case <-time.After(1 * time.Second):
					status, err = s.Query()
					if err != nil {
						l.Error("Failed to query service status.", zap.Error(err))
						return err
					}

					if status.State == svc.Stopped {
						return nil
					}
				}
			}
		},
	}
	return cmd
}

func statusCmd(name string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: fmt.Sprintf("Check the status of the %s service", name),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, err := initLogger(
				context.Background(),
				name,
				logging.WithLogFormat(logging.LogFormatConsole),
				logging.WithLogLevel("info"),
			)

			l := ctxzap.Extract(ctx)

			s, closeSvc, err := getWindowsService(ctx, name)
			if err != nil {
				l.Error("Failed to get service.", zap.Error(err))
				return err
			}
			defer closeSvc()

			results, err := s.Query()
			if err != nil {
				l.Error("Failed to query service status.", zap.Error(err))
				return err
			}

			var status string
			switch results.State {
			case svc.Stopped:
				status = "Stopped"
			case svc.StartPending:
				status = "StartPending"
			case svc.StopPending:
				status = "StopPending"
			case svc.Running:
				status = "Running"
			case svc.ContinuePending:
				status = "ContinuePending"
			case svc.PausePending:
				status = "PausePending"
			case svc.Paused:
				status = "Paused"
			default:
				status = "Unknown"
			}

			l.Info("Queried server status", zap.String("status", status))

			return nil
		},
	}
	return cmd
}

func getWindowsService(ctx context.Context, name string) (*mgr.Service, func(), error) {
	l := ctxzap.Extract(ctx).With(zap.String("service_name", name))

	m, err := mgr.Connect()
	if err != nil {
		l.Error("Failed to connect to service manager.", zap.Error(err))
		return nil, func() {}, err
	}
	l.Debug("Connected to service manager.")

	s, err := m.OpenService(name)
	if err != nil {
		m.Disconnect()
		l.Error("Failed to open service.", zap.Error(err))
		return nil, func() {}, err
	}
	l.Debug("Opened service.", zap.String("service_name", name))

	return s, func() {
		s.Close()
		m.Disconnect()
	}, nil
}

func interactiveSetup(ctx context.Context, outputFilePath string, fields []field.SchemaField) error {
	l := ctxzap.Extract(ctx)

	config := make(map[string]interface{})
	for _, vfield := range fields {
		if vfield.GetName() == "" {
			return fmt.Errorf("field has no name")
		}

		// ignore any fields from the default set, except client id and client secret
		if field.IsFieldAmongDefaultList(vfield) && vfield.GetName() != "client-id" && vfield.GetName() != "client-secret" {
			continue
		}

		var input string
		fmt.Printf("Enter %s: ", vfield.GetName())
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			input = scanner.Text()
			break
		}

		if input == "" {
			if vfield.Required {
				return fmt.Errorf("required field '%s' cannot be empty", vfield.GetName())
			}
			continue
		}

		switch vfield.Variant {
		case field.BoolVariant:
			b, err := strconv.ParseBool(input)
			if err != nil {
				return err
			}
			config[vfield.GetName()] = b

		case field.StringVariant:
			config[vfield.GetName()] = input

		case field.IntVariant:
			i, err := strconv.Atoi(input)
			if err != nil {
				return err
			}

			config[vfield.GetName()] = i

			// TODO (shackra): add support for []string in SDK
		default:
			l.Error("Unsupported type for interactive config.", zap.String("type", string(vfield.Variant)))
			return errors.New("unsupported type for interactive config")
		}
	}

	// Check to see if the config file already exists before overwriting it.
	fInfo, err := os.Stat(outputFilePath)
	if err == nil {
		if fInfo.Mode().IsRegular() {
			return fmt.Errorf("config file already exists at %s", outputFilePath)
		}
		return fmt.Errorf("config file path is not a regular file: %s", outputFilePath)
	}

	err = os.MkdirAll(filepath.Dir(outputFilePath), 0755)
	if err != nil {
		l.Error("Failed to create config directory.", zap.Error(err), zap.String("path", filepath.Dir(outputFilePath)))
		return err
	}
	f, err := os.Create(outputFilePath)
	if err != nil {
		l.Error("Failed to create config file.", zap.Error(err))
		return err
	}
	defer f.Close()

	err = yaml.NewEncoder(f).Encode(config)
	if err != nil {
		return err
	}

	l.Info("Config file created.", zap.String("path", outputFilePath))

	return nil
}

func installCmd(name string, fields []field.SchemaField) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "setup",
		Short: fmt.Sprintf("Setup and configure the %s service", name),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, err := initLogger(context.Background(), name, logging.WithLogFormat(logging.LogFormatConsole), logging.WithLogLevel("info"))
			l := ctxzap.Extract(ctx)
			svcMgr, err := mgr.Connect()
			if err != nil {
				l.Error("Failed to connect to service manager.", zap.Error(err))
				return err
			}
			defer svcMgr.Disconnect()
			s, err := svcMgr.OpenService(name)
			if err == nil {
				s.Close()
				return fmt.Errorf("%s is already installed as a service. Please run '%s remove' to remove it first.", name, os.Args[0])
			}
			err = interactiveSetup(ctx, filepath.Join(getConfigDir(name), defaultConfigFile), fields)
			if err != nil {
				l.Error("Failed to setup service.", zap.Error(err))
				return err
			}
			exePath, err := getExePath()
			if err != nil {
				l.Error("Failed to get executable path.", zap.Error(err))
				return err
			}
			mgrCfg := mgr.Config{
				DisplayName:    name,
				Description:    fmt.Sprintf("ConductorOne %s service", name),
				BinaryPathName: exePath,
			}
			s, err = svcMgr.CreateService(name, exePath, mgrCfg)
			if err != nil {
				l.Error("Failed to create service.", zap.Error(err), zap.String("service_name", name))
				return err
			}
			defer s.Close()
			err = eventlog.InstallAsEventCreate(name, eventlog.Error|eventlog.Warning|eventlog.Info)
			if err != nil {
				l.Error("Failed to install event log source.", zap.Error(err))
				delErr := s.Delete()
				if delErr != nil {
					l.Error("Failed to remove service.", zap.Error(delErr))
					err = errors.Join(err, delErr)
				}
				return err
			}
			l.Info("Successfully installed service.", zap.String("service_name", name))
			return nil
		},
	}
	return cmd
}

func uninstallCmd(name string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove",
		Short: fmt.Sprintf("Remove the %s service", name),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, err := initLogger(
				context.Background(),
				name,
				logging.WithLogFormat(logging.LogFormatConsole),
				logging.WithLogLevel("info"),
			)

			l := ctxzap.Extract(ctx)

			s, closeSvc, err := getWindowsService(ctx, name)
			if err != nil {
				l.Error("Failed to get service.", zap.Error(err))
				return err
			}
			defer closeSvc()

			err = s.Delete()
			if err != nil {
				l.Error("Failed to remove service.", zap.Error(err))
				return err
			}

			err = eventlog.Remove(name)
			if err != nil {
				l.Error("Failed to remove event log source.", zap.Error(err))
				return err
			}

			err = os.Remove(filepath.Join(getConfigDir(name), defaultConfigFile))
			if err != nil {
				l.Error("Failed to remove config file.", zap.Error(err))
				return err
			}

			l.Info("Successfully removed service.", zap.String("service_name", name))
			return nil
		},
	}
	return cmd
}

type batonService struct {
	name string
	ctx  context.Context
	elog debug.Log
}

func (s *batonService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	ctx, err := initLogger(s.ctx, s.name, logging.WithLogFormat(logging.LogFormatConsole), logging.WithLogLevel("info"))
	if err != nil {
		s.elog.Error(1, fmt.Sprintf("Failed to initialize logger. %v", err))
		return false, 1
	}
	l := ctxzap.Extract(ctx)
	l.Info("Executing service.")
	changes <- svc.Status{State: svc.StartPending}
	s.elog.Info(1, fmt.Sprintf("Starting %s service.", s.name))

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	s.elog.Info(1, fmt.Sprintf("Started %s service.", s.name))
outer:
	for {
		select {
		case <-s.ctx.Done():
			l.Info("Service context done. Shutting down")
			s.elog.Info(1, fmt.Sprintf("%s service context done. Shutting down.", s.name))
			break outer
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				l.Info("Received stop/shutdown request. Stopping service.")
				s.elog.Info(1, fmt.Sprintf("Received stop/shutdown request. Stopping %s service.", s.name))
				break outer
			default:
				s.elog.Error(1, fmt.Sprintf("Unexpected control request #%d", c))
			}
		}
	}

	l.Info("Service stopped.")
	changes <- svc.Status{State: svc.StopPending}
	s.elog.Info(1, fmt.Sprintf("%s service stopped.", s.name))
	return false, 0
}

func runService(ctx context.Context, name string) (context.Context, error) {
	l := ctxzap.Extract(ctx)
	l.Info("Running service.")

	ctx, cancel := context.WithCancelCause(ctx)
	var elog debug.Log
	go func() {
		defer cancel(nil)

		var err error
		elog, err = eventlog.Open(name)
		if err != nil {
			l.Error("Failed to open event log.", zap.Error(err))
		}
		defer elog.Close()

		err = svc.Run(name, &batonService{
			name: name,
			ctx:  ctx,
			elog: elog,
		})
		if err != nil {
			elog.Error(1, fmt.Sprintf("Running %v service failed. %v", name, err))
		} else {
			elog.Info(1, fmt.Sprintf("%v service is running.", name))
		}
	}()

	return ctx, nil
}

func AdditionalCommands(connectorName string, fields []field.SchemaField) []*cobra.Command {
	return []*cobra.Command{
		startCmd(connectorName),
		stopCmd(connectorName),
		statusCmd(connectorName),
		installCmd(connectorName, fields),
		uninstallCmd(connectorName),
	}
}
