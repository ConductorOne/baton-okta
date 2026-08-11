# Okta Connector Setup Guide

Internal technical notes for maintainers. Customer-facing setup lives in [`docs/connector.mdx`](connector.mdx). This connector is a hand-written Go client on the Okta Management API (okta-sdk-golang v2), not declarative baton-http.

---

## Connector capabilities

1. What resources does the connector sync?
   - **Users** — Okta users (including deactivated); profile, status, emails
   - **Groups** — Okta groups (`OKTA_GROUP`, `APP_GROUP`, `BUILT_IN`); optional skip of `APP_GROUP` via `--skip-app-groups`
   - **Applications** — Okta apps; optional inactive apps via `--sync-inactive-apps`
   - **Roles** — Standard admin roles
   - **Custom roles / resource sets / bindings** — When `--sync-custom-roles` is enabled
   - **Secrets (API tokens)** — When `--sync-secrets` is enabled
   - **Devices** — Okta-managed devices; **opt-in** resource type, off unless explicitly selected (see [Devices](#devices))

2. Can the connector provision any resources? If so, which ones?
   - **User account creation** — `POST /api/v1/users` (+ optional `POST /api/v1/users/{id}/lifecycle/activate`)
   - **Group membership** — Grant/Revoke via group users API
   - **App assignment** — Grant/Revoke via app users API
   - **Role assignment** — Grant/Revoke for assignable roles
   - **Custom-role bindings** — Grant/Revoke on resource-set bindings when custom roles are enabled
   - **Group create / modify / delete** — Resource actions + `ResourceDeleter` for groups
   - **enable_user / disable_user** — Lifecycle actions (unsuspend / suspend)

   **Note:** Account **deprovisioning** (hard delete of users) is not implemented. Soft disable is via `disable_user`.

3. Does the connector support grant expansion?
   - Yes for group-as-principal paths where `GrantExpandable` points at the group's `member` entitlement (app/role grants through groups).

---

## Connector credentials

1. What credentials are needed?
   - **Domain** (`--domain` / `$BATON_DOMAIN`) — Okta org host, e.g. `acmeco.okta.com` or `integrator-123.okta.com`. A value that includes `https://` (or a trailing slash) is normalised before the client is built; an explicit port is preserved (e.g. local mocks). Path, query, fragment, and userinfo are rejected.
   - **API Token** (`--api-token` / `$BATON_API_TOKEN`) — SSWS token, **or**
   - **OAuth private key** — `--auth-method=private-key-group` plus `--okta-client-id`, `--okta-private-key-id`, `--okta-private-key` (PEM-encoded RSA key; PKCS#1 or PKCS#8, see [OAuth private key handling](#oauth-private-key-handling))

2. For each item:

   * **How does a user create or look up the credential?**
     - API token: Okta Admin → **Security** → **API** → **Tokens** → **Create Token**. See [`connector.mdx`](connector.mdx) Gather credentials.
     - OAuth: Okta OIDC API Services app with private_key_jwt. DPoP is supported and needs no Okta-side change — leave the app's **Proof of Possession** setting at Okta's default. The app also needs an admin role on its **Admin Roles** tab; scopes alone are not enough. See [`connector.mdx`](connector.mdx) and [OAuth private key handling](#oauth-private-key-handling).

   * **Does it need specific scopes/permissions?**
     - Sync (read): `okta.users.read`, `okta.groups.read`, `okta.apps.read`, `okta.roles.read` (roles need elevated admin)
     - Provision (write): `okta.users.manage`, `okta.groups.manage`, `okta.apps.manage`, `okta.roles.manage` as needed
     - API tokens inherit the admin role of the creating user (Super Admin / custom role / Read-only+App+Group admin combinations — see the permissions chart in `connector.mdx`)

   * **Different scopes to sync vs provision?**
     - Yes — read scopes/roles for sync-only; manage scopes/roles for account creation, grant/revoke, and lifecycle actions.

   * **What access is needed to CREATE the credential?**
     - Admin console access with permission to create API tokens or OIDC API Services apps (typically Super Admin or equivalent).

---

## OAuth private key handling

The `private-key-group` auth path lives in `pkg/oktaauth` and is wired up by the `cfg.PrivateKeyGroup` branch of `pkg/connector/connector.go`.

**DPoP is supported.** Added in CXH-1522 (PR #172, 2026-06-26). `oktaauth.NewDPoPHTTPClient` builds a DPoP proofer from the RSA key and returns an `*http.Client` whose round tripper handles the `DPoP-Nonce` challenge/retry exchange, with separate nonce stores for the token endpoint and resource endpoints. Both SDK clients (v2 and v5) are then constructed in `Bearer` authorization mode with a sentinel token, so the `oktaauth` transport owns authentication end to end rather than the SDK's native private-key path.

Consequences for setup docs:

- **No Okta-side DPoP change is needed.** The app works with **Require Demonstrating Proof of Possession (DPoP) header in token requests** either checked (Okta's default for new API Services apps) or unchecked. Documentation that instructs readers to disable DPoP is stale — it described the pre-CXH-1522 connector and was corrected in CXH-2198.
- Verified live 2026-08-05 against `integrator-9077615.okta.com`: an API Services app with `dpop_bound_access_tokens: true` synced successfully both via the CLI binary and via the C1-hosted connector.

**Key formats.** `parseRSAPrivateKey` accepts both PKCS#1 (`RSA PRIVATE KEY`) and PKCS#8 (`PRIVATE KEY`) PEM blocks, so no `openssl` conversion step is needed — earlier docs requiring PKCS#1 were stale. Literal `\n` sequences are normalized to real newlines before decoding, which is what lets an escaped single-line PEM survive being pasted through a config form (CXH-1910). The key must be RSA: a PKCS#8 block holding an EC key is rejected with `unsupported key type ...: Okta DPoP requires RSA`. Covered by `TestParseRSAPrivateKey` in `pkg/oktaauth/oktaauth_test.go`.

**An admin role is required, and its absence is partly silent.** Scopes and admin role are evaluated independently: the requested scopes can all be present in the minted token while Okta still refuses the request because the API Services app has no role on its **Admin Roles** tab. Observed 2026-08-05 with `okta.devices.read` granted and present in the token, on an app with no admin role:

| Call | Result |
| :--- | :--- |
| `GET /api/v1/devices` | `403` `E0000006` "You do not have permission to perform the requested action" |
| `GET /api/v1/users` | `200` with an **empty list** |

The users case is the dangerous one: the sync exits 0 and writes a bundle containing zero users, so a missing admin role presents as a successful empty sync rather than an error. Assigning Super Administrator makes both return data.

**Requested scopes.** On this path the connector requests the four default read scopes plus all four `*.manage` provisioning scopes unconditionally, then adds `okta.apiTokens.read` when `--sync-secrets` is set and `okta.devices.read` when device sync is enabled. Per the note in `connector.go`, a scope the app has not been granted drops from the issued token and only surfaces as a 403 on first use, so a read-only app still authenticates.

**Console caveat for whoever writes customer docs.** During CXH-2092 / CXH-2124 validation, the Okta Admin Console's **Okta API Scopes** tab twice failed to persist scope grants with no error shown — the grants did not appear in `GET /api/v1/apps/{id}/grants`. `POST /api/v1/apps/{id}/grants` worked reliably. The customer-facing walkthrough directs readers to that tab, so it carries a note telling them to refresh and visually confirm the granted scopes.

---

## Account creation

Account creation is driven by `AccountCreationSchema` in `pkg/connector/connector.go` and `CreateAccount` in `pkg/connector/user.go`.

### Profile fields (schema keys)

| Schema key | Required | Default | Behavior |
| :--- | :---: | :--- | :--- |
| `first_name` | yes | — | Okta `profile.firstName` |
| `last_name` | yes | — | Okta `profile.lastName` |
| `email` | yes | — | Okta `profile.email`; also login fallback |
| `login` | no | email | Okta `profile.login` |
| `password_change_on_login_required` | no | false | Schema `StringField` (True/False placeholder). Sets `nextLogin=changePassword` when using random password |
| `create_inactive` | no | false | Schema `StringField` (True/False placeholder). `activate=false`; skips activation follow-up |
| `send_activation_email` | no | true | Schema `StringField` (True/False placeholder; same shape as the two siblings above). Accepts a bool or its string form at runtime. When `false`: create staged, then `ActivateUser` with `sendEmail=false`, then re-fetch user |
| `provider_type` | no | empty (Okta default local provider) | `OKTA` or `FEDERATION` (case-insensitive). `FEDERATION` sets `credentials.provider` + query `provider=true` |
| `additionalAttributes` | no | — | Map merged into Okta profile; cannot override protected keys. A value of any other type is rejected, not dropped |

### Wire format / Okta calls

Doc root: [Okta Users API](https://developer.okta.com/docs/reference/api/users/).

| Operation | Method + path | Notes |
| :--- | :--- | :--- |
| Create user | `POST /api/v1/users` | Query: `activate`, `provider`, optional `nextLogin` |
| Activate user | `POST /api/v1/users/{id}/lifecycle/activate` | Query: `sendEmail=false` when suppressing activation email |
| Get user | `GET /api/v1/users/{idOrLogin}` | Re-fetch after activate to pick up the post-activation status; best-effort, a failure keeps the created user. Also used to resolve an existing login on retry |

### Conflict / validation rules

- `provider_type=FEDERATION` + random password credential option → error (Okta rejects password on FEDERATION users).
- `send_activation_email=false` + `password_change_on_login_required=true` + **random password** → error (staged+activate path cannot also set `nextLogin=changePassword`). On the no-password path, `password_change_on_login_required` is inert and does not conflict (pre-existing behavior).
- `create_inactive=true` wins over `send_activation_email` / `password_change_on_login_required`: evaluated first, user stays staged, no activate call, and the conflict check above is skipped.
- Without query `provider=true`, Okta **ignores** a `credentials.provider` block and creates a normal OKTA user (verified live).
- A profile field present with the wrong type is always an error, never a silent fallback: booleans
  (`create_inactive`, `send_activation_email`, `password_change_on_login_required`) must be a bool or
  its string form, and `additionalAttributes` must be an object. Only an absent or null key falls back
  to the default, because creating the account without what the caller asked for would report success
  for a different outcome. The C1 mapping screen does not validate the mapped expression's type, so a
  CEL expression returning the wrong type is caught here.

### Retry semantics

The suppressed-email flow spans three calls, so a failure can leave the user created but not
activated. On retry, Okta rejects the create with `E0000001` and an `errorCauses` entry naming
`login`. Any duplicate login returns `AlreadyExistsResult` — with the existing Okta user when
the follow-up fetch succeeds, or without a Resource when the lookup fails — so the caller
converges on that account (or the next sync correlates it) instead of failing forever. The
existing user's status does not matter.

The existing user's lifecycle is never changed — activation runs only for a user this same call
created. `STAGED` does not identify a stranded attempt: `create_inactive=true` and an admin-staged
account look identical, so activating on a duplicate would override an explicit "keep this account
inactive" decision. The trade-off is that a retry after a failed activation reports
`AlreadyExistsResult` with the user still `STAGED`, and finishing activation has to happen in Okta.
The `enable_user` action does not cover this case: it only unsuspends a `SUSPENDED` user. On any other
status (including `STAGED`) Okta returns "Cannot unsuspend a user that is not suspended", and the
action swallows that into a success response (`Account … was already enabled`) without changing the
user — so the account stays `STAGED`.

### Org2Org / hub-spoke

Spoke users are often created as `FEDERATION` (hub owns credentials) with `send_activation_email=false` (no Okta activation email). Prefer the connector's **no-password** credential option with `FEDERATION`.

### Status notes (Okta semantics)

- FEDERATION user after staged create + activate(`sendEmail=false`) → typically **ACTIVE**.
- OKTA user with **no password** after the same flow → typically **PROVISIONED** (same as default create without password).
- OKTA user **with** password after activate(`sendEmail=false`) → typically **ACTIVE**.

---

## Resource reference (API doc links)

Doc roots:

- [Users](https://developer.okta.com/docs/reference/api/users/)
- [Groups](https://developer.okta.com/docs/reference/api/groups/)
- [Apps](https://developer.okta.com/docs/reference/api/apps/)
- [Roles](https://developer.okta.com/docs/reference/api/roles/)
- [Devices](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Device/)
- [Authorization Servers / OAuth for Okta](https://developer.okta.com/docs/guides/implement-oauth-for-okta/)

### Users

| Operation | Method + path | Doc |
| :--- | :--- | :--- |
| List users | `GET /api/v1/users` | [List Users](https://developer.okta.com/docs/reference/api/users/#list-users) |
| Get user | `GET /api/v1/users/{id}` | [Get User](https://developer.okta.com/docs/reference/api/users/#get-user) |
| Create user | `POST /api/v1/users` | [Create User](https://developer.okta.com/docs/reference/api/users/#create-user) |
| Activate | `POST /api/v1/users/{id}/lifecycle/activate` | [Activate User](https://developer.okta.com/docs/reference/api/users/#activate-user) |
| Suspend / unsuspend | lifecycle suspend / unsuspend | [Lifecycle operations](https://developer.okta.com/docs/reference/api/users/#lifecycle-operations) |

### Groups

| Operation | Method + path | Doc |
| :--- | :--- | :--- |
| List groups | `GET /api/v1/groups` | [List Groups](https://developer.okta.com/docs/reference/api/groups/#list-groups) |
| List group users | `GET /api/v1/groups/{id}/users` | [List Group Members](https://developer.okta.com/docs/reference/api/groups/#list-group-members) |
| Add / remove member | `PUT` / `DELETE .../users/{userId}` | [Add User to Group](https://developer.okta.com/docs/reference/api/groups/#add-user-to-group) |
| Create / update / delete group | `POST` / `PUT` / `DELETE /api/v1/groups` | [Groups API](https://developer.okta.com/docs/reference/api/groups/) |

### Applications

| Operation | Method + path | Doc |
| :--- | :--- | :--- |
| List apps | `GET /api/v1/apps` | [List Applications](https://developer.okta.com/docs/reference/api/apps/#list-applications) |
| Assign / unassign user | app users assign/unassign | [Assign User](https://developer.okta.com/docs/reference/api/apps/#assign-user-to-application-for-sso) |

### Devices

Added in v0.5.19 (PR #186, CXH-2092). Implemented in `pkg/connector/device.go`; resource type declared in `pkg/connector/connector.go`.

**Opt-in.** The resource type carries an `&v2.OptInRequired{}` annotation, so it is off unless the sync filter explicitly selects `device` — `shouldSyncResourceType` requires an explicit filter that names the type. It is registered unconditionally (not behind a config flag), so it always appears in the capabilities/metadata output and reaches the C1 platform for a user to enable.

**Read-only.** `Entitlements` and `Grants` both return `nil` — devices are synced as inventory only. Device-to-user assignments are **not** modelled, so there is nothing to review or provision against a device.

| Property | Value |
| :--- | :--- |
| Resource type ID | `device` |
| Display name | `Device` |
| Trait | `TRAIT_MANAGED_DEVICE` (built with `resource.NewManagedDeviceResource`) |
| Required scope | `okta.devices.read` |
| Provisioning | None (no entitlements, no grants) |

| Operation | Method + path | Doc |
| :--- | :--- | :--- |
| List devices | `GET /api/v1/devices` | [List Devices](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Device/#tag/Device/operation/listDevices) |

Called through okta-sdk-golang **v5** (`DeviceAPI.ListDevices`), unlike most of the connector, which is on v2.

**Pagination.** `limit` is clamped to `deviceListLimit = 200`, Okta's enforced maximum for this endpoint; a larger requested page size is silently reduced to 200. Paging follows Okta's Link-header cursor: the first call issues `ListDevices`, and each subsequent page is fetched by deserializing the previous `APIResponse` out of the page-token bag and calling `.Next()`.

**Field mapping.** All attributes come from the device's `profile` object. When `profile` is absent, no trait options are set and the resource name falls back to the device ID.

| Okta field | Baton managed-device field |
| :--- | :--- |
| `id` (top level) | Resource ID |
| `profile.displayName` | Resource display name (falls back to `id` when empty) |
| `profile.serialNumber` | Serial |
| `profile.udid` | UDID |
| `profile.model` | Model |
| `profile.manufacturer` | Vendor |
| `profile.platform` | OS name, plus the mapped OS type below |
| `profile.osVersion` | OS version |

**Platform mapping.** `WINDOWS`, `MACOS`, `IOS`, `ANDROID`, and `CHROMEOS` map to their `DeviceOS_OsType` equivalents. Any other value maps to `OS_TYPE_UNSPECIFIED` — deliberately left unset rather than guessed — while `profile.platform` is still carried through verbatim as the OS name, so a new Okta platform value surfaces as an unspecified type with a readable name.

**Failure mode.** On the OAuth path, `okta.devices.read` is only appended to the requested token scopes when device sync is enabled. Granting the scope is not sufficient by itself: with the scope present in the token but no admin role on the API Services app, `GET /api/v1/devices` returns `403 E0000006` (verified live 2026-08-05). See [OAuth private key handling](#oauth-private-key-handling).

---

## Additional notes

- Error prefix at the connector layer: `okta-connectorv2:`.
- Pagination: Okta Link-header cursors via the SDK.
- Rate limits: handled by Okta SDK / HTTP client retries; respect `X-Rate-Limit-*` / `Retry-After`.
- Group profile `type` is synced for `OKTA_GROUP` / `APP_GROUP` / `BUILT_IN` (see note in `connector.mdx`).
