![Baton Logo](./docs/images/baton-logo.png)

# `baton-okta` [![Go Reference](https://pkg.go.dev/badge/github.com/conductorone/baton-okta.svg)](https://pkg.go.dev/github.com/conductorone/baton-okta) ![ci](https://github.com/conductorone/baton-okta/actions/workflows/ci.yaml/badge.svg) ![verify](https://github.com/conductorone/baton-okta/actions/workflows/verify.yaml/badge.svg)

`baton-okta` is a connector for Okta built using the [Baton SDK](https://github.com/conductorone/baton-sdk). It communicates with the Okta API to sync data about which groups and users have access to applications, groups, and roles within an Okta domain.

Check out [Baton](https://github.com/conductorone/baton) to learn more about the project in general.

# Prerequisites

- An Okta org (domain such as `acmeco.okta.com`)
- An **API token** from an admin with the permissions you need, **or** an OAuth 2.0 API Services app (private key JWT)
- For account provisioning / grant-revoke: write-level admin (`okta.users.manage`, etc.) — see [docs/connector.mdx](docs/connector.mdx)

# Getting Started

## brew

```
brew install conductorone/baton/baton conductorone/baton/baton-okta

BATON_API_TOKEN=oktaAPIToken BATON_DOMAIN=domain-1234.okta.com baton-okta
baton resources
```

Or auth using a public/private keypair (OAuth 2.0 client credentials with `private_key_jwt`):

```
BATON_AUTH_METHOD=private-key-group \
BATON_OKTA_CLIENT_ID=appClientID \
BATON_OKTA_PRIVATE_KEY='auth.key' \
BATON_OKTA_PRIVATE_KEY_ID=appKID \
BATON_DOMAIN=domain-1234.okta.com baton-okta
baton resources
```

Notes for OAuth setup:

- `BATON_AUTH_METHOD=private-key-group` is required when authenticating via OAuth — without it the CLI defaults to the API Token field group and refuses to start with `field api-token of type string is marked as required but it has a zero-value`.
- The private key must be a PEM-encoded **RSA** key. Both **PKCS#1** (`-----BEGIN RSA PRIVATE KEY-----`) and **PKCS#8** (`-----BEGIN PRIVATE KEY-----`, what `openssl genrsa` produces by default) are accepted, so no conversion step is needed. Elliptic-curve keys are rejected — Okta's DPoP implementation requires RSA.
- **DPoP is supported** and needs no Okta-side change: leave the app's **Proof of Possession** setting at Okta's default. Earlier revisions of this file and of `docs/connector.mdx` told you to disable DPoP; that instruction described the pre-DPoP connector and was removed in CXH-2198.
- The API Services app **must be assigned an admin role** on its **Admin Roles** tab. Granting OAuth scopes is not sufficient. Without a role, most endpoints return `403`, but `GET /api/v1/users` returns `200` with an empty list — so the sync succeeds and finds zero accounts.
- See [`docs/connector.mdx`](docs/connector.mdx) for the complete Okta-side setup and [`docs/docs-info.md`](docs/docs-info.md) for the internal detail on key handling, DPoP, and scopes.

## docker

```
docker run --rm -v $(pwd):/out -e BATON_API_TOKEN=oktaAPIToken -e BATON_DOMAIN=domain-1234.okta.com public.ecr.aws/conductorone/baton-okta:latest -f "/out/sync.c1z"
docker run --rm -v $(pwd):/out ghcr.io/conductorone/baton:latest -f "/out/sync.c1z" resources
```

The two images come from different registries, deliberately. Connector images are published
to **ECR Public** (`public.ecr.aws/conductorone/baton-okta`), which is also what the
Kubernetes manifests in [`docs/connector.mdx`](docs/connector.mdx) use. The `baton` CLI image
is published only to **GHCR** (`ghcr.io/conductorone/baton`) — there is no
`public.ecr.aws/conductorone/baton` repository, so do not "tidy" that second line to match
the first.

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
- Custom-Roles
- Resource-Sets
- Resourceset-Bindings
- Devices

By default, `baton-okta` will sync information for inactive applications. You can exclude inactive applications setting the `--sync-inactive-apps` flag to `false`.

For syncing custom roles `--sync-custom-roles` must be provided. Its default value is `false`.

Devices are an opt-in resource type: enable the **Device** resource type in the connector's sync configuration to include it. Device sync is read-only; the connector does not manage device-to-user assignments.

We have also introduced resourceset-bindings (resourcesetID and custom roles ID) for provisioning custom roles and members.

# Provisioning

With `--provisioning` enabled, the connector supports:

- **Account creation** — create Okta users via C1 account provisioning / `--create-account-profile`
- **Group / app / role grant and revoke**
- **Group create, modify, and delete** (group delete via `--delete-resource`)
- **enable_user / disable_user** lifecycle actions — `enable_user` unsuspends a `SUSPENDED` account and activates a `STAGED` one (no activation email); `disable_user` suspends an enabled account

### Account creation profile fields

Optional keys in the account creation profile (see [docs/connector.mdx](docs/connector.mdx) for field semantics and [docs/docs-info.md](docs/docs-info.md) for wire-level detail):

| Key | Values | Notes |
| --- | --- | --- |
| `provider_type` | `OKTA` / `FEDERATION` | `FEDERATION` creates a federated user (no Okta password). Use with the **no-password** credential option. |
| `send_activation_email` | `true` / `false` | Default `true`. When `false`, activates without sending Okta's activation email. |
| `create_inactive` | `true` / `false` | Create as staged; skips activation. |
| `password_change_on_login_required` | `true` / `false` | Only applied with random password. Conflicts with `send_activation_email=false` on that path only. |
| `additionalAttributes` | object | Extra Okta profile attributes. |

Precedence notes:

- `create_inactive=true` wins over `send_activation_email` — the user stays staged; no activation follow-up runs.
- `password_change_on_login_required` is inert on the no-password credential path (same as before this feature).
- A key present with the wrong type fails the request instead of being ignored, so a mapping mistake surfaces rather than creating an account that is missing what was asked for. Only an absent or null key falls back to its default.

Example (federated user, no activation email):

```
BATON_API_TOKEN='…' BATON_DOMAIN='domain-1234.okta.com' baton-okta --provisioning \
  --create-account-profile '{"first_name":"Ada","last_name":"Lovelace","email":"ada@example.com","login":"ada@example.com","provider_type":"FEDERATION","send_activation_email":false}' \
  --create-account-resource-type user
```

Note: the CLI's default credential path uses a random password. `provider_type=FEDERATION` requires a **no-password** credential option (as C1 uses for that flow). Validate FEDERATION creates via the C1 UI or a caller that passes no-password credentials.

### Resourceset-bindings, custom roles and members (Users or Groups)

Example IDs:

```
Resource Set `iamkuwy3gqcfNexfQ697`
Custom Role `cr0kuwv5507zJCtSy697`
Member `00ujp51vjgWd6ylZ6697`
```

Granting a custom role to a user:

```
BATON_API_TOKEN='oktaAPIToken' BATON_DOMAIN='domain-1234.okta.com' baton-okta \
--grant-entitlement 'resourceset-binding:iamkuwy3gqcfNexfQ697:cr0kuwv5507zJCtSy697:member' --grant-principal-type 'user' --grant-principal '00ujp51vjgWd6ylZ6697'
```

Revoking a custom role grant (unassigns a member):

```
BATON_API_TOKEN='oktaAPIToken' BATON_DOMAIN='domain-1234.okta.com' baton-okta \
--revoke-grant 'resourceset-binding:iamkuwy3gqcfNexfQ697:cr0kuwv5507zJCtSy697:member:user:00ujp51vjgWd6ylZ6697'
```

Revoking everything associated to a custom role (deletes the role's binding):

```
BATON_API_TOKEN='oktaAPIToken' BATON_DOMAIN='domain-1234.okta.com' baton-okta \
--revoke-grant 'resource-set:iamkuwy3gqcfNexfQ697:bindings:custom-role:cr0kuwv5507zJCtSy697'
```

# Documentation

- [docs/connector.mdx](docs/connector.mdx) — customer-facing C1 setup guide
- [docs/docs-info.md](docs/docs-info.md) — internal setup guide, account-creation wire format, API links

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
  config             Get the connector config schema
  health-check       Check the health of a running connector
  help               Help about any command

Flags:
      --api-token string                                 required: The API token for the service account ($BATON_API_TOKEN)
      --auth-method string                               ($BATON_AUTH_METHOD)
      --cache                                            Enable response cache ($BATON_CACHE) (default true)
      --cache-tti int                                    Response cache cleanup interval in seconds ($BATON_CACHE_TTI) (default 60)
      --cache-ttl int                                    Response cache time to live in seconds ($BATON_CACHE_TTL) (default 300)
      --client-id string                                 The client ID used to authenticate with ConductorOne ($BATON_CLIENT_ID)
      --client-secret string                             The client secret used to authenticate with ConductorOne ($BATON_CLIENT_SECRET)
      --domain string                                    required: The URL for the Okta organization ($BATON_DOMAIN)
      --external-resource-c1z string                     The path to the c1z file to sync external baton resources with ($BATON_EXTERNAL_RESOURCE_C1Z)
      --external-resource-entitlement-id-filter string   The entitlement that external users, groups must have access to sync external baton resources ($BATON_EXTERNAL_RESOURCE_ENTITLEMENT_ID_FILTER)
  -f, --file string                                      The path to the c1z file to sync with ($BATON_FILE) (default "sync.c1z")
      --filter-email-domains strings                     Press Enter to add multiple items. ($BATON_FILTER_EMAIL_DOMAINS)
      --health-check                                     Enable the HTTP health check endpoint ($BATON_HEALTH_CHECK)
      --health-check-port int                            Port for the HTTP health check endpoint ($BATON_HEALTH_CHECK_PORT) (default 8081)
  -h, --help                                             help for baton-okta
      --http-timeout-seconds int                         HTTP client timeout in seconds (max 1800) ($BATON_HTTP_TIMEOUT_SECONDS) (default 300)
      --keep-previous-sync-c1z                           Keep the previously synced c1z on disk to enable ETag replay across service-mode syncs (requires a connector that supports ETag replay; costs one c1z of local disk) ($BATON_KEEP_PREVIOUS_SYNC_C1Z)
      --log-format string                                The output format for logs: json, console ($BATON_LOG_FORMAT) (default "json")
      --log-level string                                 The log level: debug, info, warn, error ($BATON_LOG_LEVEL) (default "info")
      --log-level-debug-expires-at string                The timestamp indicating when debug-level logging should expire ($BATON_LOG_LEVEL_DEBUG_EXPIRES_AT)
      --log-path strings                                 The file path to write logs to ($BATON_LOG_PATH)
      --okta-client-id string                            required: The Okta Client ID ($BATON_OKTA_CLIENT_ID)
      --okta-private-key string                          required: The Okta Private Key (PEM-encoded) ($BATON_OKTA_PRIVATE_KEY)
      --okta-private-key-id string                       required: The Okta Private Key ID ($BATON_OKTA_PRIVATE_KEY_ID)
      --otel-collector-endpoint string                   The endpoint of the OpenTelemetry collector to send observability data to (used for both tracing and logging if specific endpoints are not provided) ($BATON_OTEL_COLLECTOR_ENDPOINT)
      --parallel-sync                                    Deprecated: use --workers instead. ($BATON_PARALLEL_SYNC)
  -p, --provisioning                                     This must be set in order for provisioning actions to be enabled ($BATON_PROVISIONING)
      --skip-app-groups                                  Whether to skip syncing APP_GROUP type groups (Okta push groups created by SCIM-integrated apps) or not ($BATON_SKIP_APP_GROUPS)
      --skip-entitlements-and-grants                     This must be set to skip syncing of entitlements and grants ($BATON_SKIP_ENTITLEMENTS_AND_GRANTS)
      --skip-full-sync                                   This must be set to skip a full sync ($BATON_SKIP_FULL_SYNC)
      --skip-secondary-emails                            Whether to skip syncing secondary emails or not ($BATON_SKIP_SECONDARY_EMAILS)
      --storage-engine string                            The storage engine to use when opening the sync c1z file: sqlite or pebble. Leave unset to use the baton-sdk default. ($BATON_STORAGE_ENGINE)
      --sync-custom-roles                                Whether to enable syncing custom roles or not ($BATON_SYNC_CUSTOM_ROLES)
      --sync-inactive-apps                               Whether to sync inactive apps or not ($BATON_SYNC_INACTIVE_APPS) (default true)
      --sync-resource-types strings                      The resource type IDs to sync ($BATON_SYNC_RESOURCE_TYPES)
      --sync-resources strings                           The resource IDs to sync ($BATON_SYNC_RESOURCES)
      --sync-secrets                                     Whether to sync secrets or not ($BATON_SYNC_SECRETS)
      --task-concurrency int                             The number of Baton tasks to run concurrently in service mode. Tasks may include sync, grant, revoke, and more. Minimum value is 1, maximum value is 100. ($BATON_TASK_CONCURRENCY) (default 3)
      --ticketing                                        This must be set to enable ticketing support ($BATON_TICKETING)
  -v, --version                                          version for baton-okta
      --workers int                                      The number of sync workers to use. -1 for auto-detect, 0 for sequential, >0 for parallel ($BATON_WORKERS)

Use "baton-okta [command] --help" for more information about a command.
```
