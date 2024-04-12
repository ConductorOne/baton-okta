![Baton Logo](./docs/images/baton-logo.png)

# `baton-okta` [![Go Reference](https://pkg.go.dev/badge/github.com/conductorone/baton-okta.svg)](https://pkg.go.dev/github.com/conductorone/baton-okta) ![main ci](https://github.com/conductorone/baton-okta/actions/workflows/main.yaml/badge.svg)

`baton-okta` is a connector for Okta built using the [Baton SDK](https://github.com/conductorone/baton-sdk). It communicates with the Okta API to sync data about which groups and users have access to applications, groups, and roles within an Okta domain.

Check out [Baton](https://github.com/conductorone/baton) to learn more about the project in general.

# Getting Started

## brew

```
brew install conductorone/baton/baton conductorone/baton/baton-okta

BATON_API_TOKEN=oktaAPIToken BATON_DOMAIN=domain-1234.okta.com baton-okta
baton resources
```

Or auth using a public/private keypair

```
BATON_OKTA_CLIENT_ID=appClientID \
BATON_OKTA_PRIVATE_KEY='auth.key' \
BATON_OKTA_PRIVATE_KEY_ID=appKID \
BATON_DOMAIN=domain-1234.okta.com baton-okta
baton resources
```

## docker

```
docker run --rm -v $(pwd):/out -e BATON_API_TOKEN=oktaAPIToken -e BATON_DOMAIN=domain-1234.okta.com ghcr.io/conductorone/baton-okta:latest -f "/out/sync.c1z"
docker run --rm -v $(pwd):/out ghcr.io/conductorone/baton:latest -f "/out/sync.c1z" resources
```

## source

```
go install github.com/conductorone/baton/cmd/baton@main
go install github.com/conductorone/baton-okta/cmd/baton-okta@main

BATON_API_TOKEN=oktaAPIToken BATON_DOMAIN=domain-1234.okta.com baton-okta
baton resources
```

# Data Model

`baton-okta` will pull down information about the following Okta resources:

- Applications
- Groups
- Roles
- Users

By default, `baton-okta` will sync information for inactive applications. You can exclude inactive applications setting the `--sync-inactive-apps` flag to `false`.

# Contributing, Support and Issues

We started Baton because we were tired of taking screenshots and manually building spreadsheets. We welcome contributions, and ideas, no matter how small -- our goal is to make identity and permissions sprawl less painful for everyone. If you have questions, problems, or ideas: Please open a Github Issue!

See [CONTRIBUTING.md](https://github.com/ConductorOne/baton/blob/main/CONTRIBUTING.md) for more details.

# `baton-okta` Command Line Usage

```
baton-okta

Usage:
  baton-okta [flags]
  baton-okta [command]

Available Commands:
  capabilities       Get connector capabilities
  completion         Generate the autocompletion script for the specified shell
  help               Help about any command

Flags:
      --api-token string             The API token for the service account.  ($BATON_API_TOKEN)
      --client-id string             The client ID used to authenticate with ConductorOne ($BATON_CLIENT_ID)
      --client-secret string         The client secret used to authenticate with ConductorOne ($BATON_CLIENT_SECRET)
      --domain string                The URL for the Okta organization. ($BATON_DOMAIN)
  -f, --file string                  The path to the c1z file to sync with ($BATON_FILE) (default "sync.c1z")
  -h, --help                         help for baton-okta
      --log-format string            The output format for logs: json, console ($BATON_LOG_FORMAT) (default "json")
      --log-level string             The log level: debug, info, warn, error ($BATON_LOG_LEVEL) (default "info")
      --okta-client-id string        The Okta Client ID. ($BATON_OKTA_CLIENT_ID)
      --okta-private-key string      The Okta Private Key. This can be the whole private key or the path to the private key, ($BATON_OKTA_PRIVATE_KEY)
      --okta-private-key-id string   The Okta Private Key ID. ($BATON_OKTA_PRIVATE_KEY_ID)
  -p, --provisioning                 This must be set in order for provisioning actions to be enabled. ($BATON_PROVISIONING)
      --sync-inactive-apps           Whether to sync inactive apps or not.  ($BATON_SYNC_INACTIVE_APPS) (default true)
  -v, --version                      version for baton-okta

Use "baton-okta [command] --help" for more information about a command.
```
