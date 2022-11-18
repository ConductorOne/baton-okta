# baton-okta

## Usage
```
baton-okta

Usage:
  baton-okta [flags]
  baton-okta [command]

Available Commands:
  completion         Generate the autocompletion script for the specified shell
  help               Help about any command

Flags:
      --api-token string     The API token for the service account
      --domain string        The URL for the Okta organization
  -f, --file string          The path to the c1z file to sync with ($C1_FILE) (default "sync.c1z")
  -h, --help                 help for baton-okta
      --log-format string    The output format for logs: json, console ($C1_LOG_FORMAT) (default "json")
      --log-level string     The log level: debug, info, warn, error ($C1_LOG_LEVEL) (default "info")
      --sync-inactive-apps   Whether to sync inactive apps or not
  -v, --version              version for baton-okta

Use "baton-okta [command] --help" for more information about a command.
```