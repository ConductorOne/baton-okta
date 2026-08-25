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
   - **enable_user / disable_user** — Reversible lifecycle actions (activate / unsuspend / suspend, see [Lifecycle and deprovisioning actions](#lifecycle-and-deprovisioning-actions))
   - **deactivate_user / delete_user** — Explicit destructive workflow actions
   - **Account deprovisioning** — `ResourceDeleterV2Limited` deactivates and permanently deletes users
   - **update_profile** — Partial update of an existing user's profile via `POST /api/v1/users/{id}` (Okta's partial-update semantics; only the fields provided are changed). Manual/UX invocation with individual typed fields.
   - **update_user** — Same underlying `POST /api/v1/users/{id}` call, but takes a `user_profile` JSON object instead of typed fields and accepts any Okta profile attribute (no curated allowlist). This is the global-action shape C1's automated profile-push pipeline requires — a resource-scoped-only action does not satisfy that lookup.

   **Note:** Two wire-level caveats operators hit in practice: (1) sending an empty string `""` for a profile attribute leaves it present-but-empty in Okta, while sending `null` removes the attribute entirely — these are NOT equivalent ways to clear a field. (2) An unrecognized profile attribute key fails the entire `PartialUpdateUser` call; there is no per-field skip/partial-success behavior, so a single bad key in a large `user_profile` payload rejects the whole update.

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
`login`. A duplicate login returns `AlreadyExistsResult` for every status except `DEPROVISIONED`
— with the existing Okta user when the follow-up fetch succeeds, or without a Resource when the
lookup fails — so the caller converges on that account (or the next sync correlates it) instead
of failing forever. A `DEPROVISIONED` collision is the exception: it fails with
`FailedPrecondition`, because the connector has no reactivation path and reporting success would
hand back a login that can never be provisioned.

The existing user's lifecycle is never changed — activation runs only for a user this same call
created. `STAGED` does not identify a stranded attempt: `create_inactive=true` and an admin-staged
account look identical, so activating on a duplicate would override an explicit "keep this account
inactive" decision. The trade-off is that a retry after a failed activation reports
`AlreadyExistsResult` with the user still `STAGED`.

Finishing that activation is an explicit operation: run the `enable_user` action against the
account, which activates a `STAGED` user with `sendEmail=false` (see
[Lifecycle actions](#lifecycle-actions)). A repeated create will not do it, by design — only an
operator asking to enable that specific account can, because a create cannot tell a stranded
attempt from a deliberately inactive account.

### Org2Org / hub-spoke

Spoke users are often created as `FEDERATION` (hub owns credentials) with `send_activation_email=false` (no Okta activation email). Prefer the connector's **no-password** credential option with `FEDERATION`.

### Status notes (Okta semantics)

- FEDERATION user after staged create + activate(`sendEmail=false`) → typically **ACTIVE**.
- OKTA user with **no password** after the same flow → typically **PROVISIONED** (same as default create without password).
- OKTA user **with** password after activate(`sendEmail=false`) → typically **ACTIVE**.

---

## Lifecycle and deprovisioning actions

Okta distinguishes suspension, deactivation, and deletion. The connector keeps those contracts separate:

- `disable_user` suspends an account. Suspension blocks sign-in but retains group and application assignments and can be reversed by `enable_user`.
- `deactivate_user` deprovisions an account from assigned applications and leaves its Okta record in `DEPROVISIONED`.
- `delete_user` ensures deactivation and then permanently deletes the Okta record.
- C1 resource deletion uses the same permanent-delete operation as `delete_user`.

The two new destructive operations are user-scoped Baton resource actions with a required `user_id` `ResourceIdField` restricted to the Okta `user` resource type, so C1 workflows bind them to a synced account. `deactivate_user` uses `RESOURCE_DISABLE` action typing and `delete_user` uses `RESOURCE_DELETE`. The global `disable_user` action remains the only `ACCOUNT_DISABLE` action, preserving the standard account-lifecycle integration and its reversible suspend semantics.

| Okta status | `enable_user` | `disable_user` | `deactivate_user` | `delete_user` / resource delete |
|---|---|---|---|---|
| `ACTIVE`, `PROVISIONED`, `RECOVERY`, `PASSWORD_EXPIRED`, `LOCKED_OUT` | already enabled, no call | `POST /lifecycle/suspend` | `POST /lifecycle/deactivate?sendEmail=false` | deactivate, then `DELETE /api/v1/users/{id}` |
| `SUSPENDED` | `POST /lifecycle/unsuspend` | already disabled, no call | `POST /lifecycle/deactivate?sendEmail=false` | deactivate, then delete |
| `STAGED` | `POST /lifecycle/activate?sendEmail=false` | already disabled, no call | `POST /lifecycle/deactivate?sendEmail=false` | deactivate, then delete |
| `DEPROVISIONED` | error — reactivation is a separate decision | already disabled, no call | already deactivated, no call | delete |
| Missing | `NotFound` | `NotFound` | `NotFound` | already deleted, no call |

Okta's DELETE endpoint only permanently deletes a `DEPROVISIONED` user. Calling it on another status merely deactivates the user and requires a second call, and Okta documents `204 No Content` for both outcomes. The status code therefore cannot prove deletion. The shared connector operation bypasses the SDK GET cache, confirms `DEPROVISIONED` immediately before DELETE, and performs a fresh GET afterward. `NotFound` proves success; a surviving `DEPROVISIONED` record gets one second DELETE and another verification; any remaining record returns a retryable error instead of a false success.

Lifecycle races are reconciled using structured state, not vendor error text. After a successful deactivate, the connector performs up to four fresh status reads 500 ms apart so an ordinary asynchronous transition can reach `DEPROVISIONED` in the same invocation; a longer transition returns a retryable error. If deactivation itself is rejected while another actor is changing the same user, one fresh status read converts the error to success only when Okta now reports `DEPROVISIONED`. Absence is success only for a delete operation, and other outcomes preserve the original mutation error. A missing user is idempotent success for delete operations; the deactivate-only action keeps missing as `NotFound` because its requested result is a surviving `DEPROVISIONED` user.

`enable_user` and `disable_user` also read the current status first because `unsuspend` only applies to `SUSPENDED` and `activate` only to `STAGED`. They plan from a single status GET, then trust a successful lifecycle call rather than adding a confirm GET. C1 runs each action in a fresh lambda, so a vendor-SDK cache bypass solely for confirmation is unnecessary.

**Sync status for `STAGED` (Okta sign-in, not C1).** Sync maps `STAGED` to `RESOURCE_STATUS_DISABLED` alongside `SUSPENDED` and `DEPROVISIONED`. In Okta, staged means the account was created but not activated — nobody can sign in to Okta until `activate`. This is an Okta lifecycle state, not a statement about signing in to ConductorOne.

Default Create Account does not leave users staged: the connector activates them or sends Okta's activation email. Users remain staged only when `create_inactive=true`, when an Okta admin created the user without activating it, or when an incomplete create left it there. The raw Okta status remains on the resource details, so staged stays distinguishable from suspended and deprovisioned.

Credential-problem statuses (`RECOVERY`, `PASSWORD_EXPIRED`, and `LOCKED_OUT`) remain enabled. `enable_user` reports them as already enabled rather than unlocking the account or resetting credentials. Activating a staged user sends no email, matching the `send_activation_email=false` creation path. An `OKTA` account without a password typically lands in `PROVISIONED`, while a `FEDERATION` account can land in `ACTIVE`.

Deactivation and deletion require `okta.users.manage`. Deactivation is destructive because Okta deprovisions the user from assigned apps, potentially destroying downstream email or files. Permanent deletion cannot be recovered. Workflow authors should put approval gates around these actions when policy requires them.

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
