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
   - **Domain** (`--domain` / `$BATON_DOMAIN`) — Okta org host, e.g. `acmeco.okta.com` or `integrator-123.okta.com`
   - **API Token** (`--api-token` / `$BATON_API_TOKEN`) — SSWS token, **or**
   - **OAuth private key** — `--auth-method=private-key-group` plus `--okta-client-id`, `--okta-private-key-id`, `--okta-private-key` (PKCS#1 PEM)

2. For each item:

   * **How does a user create or look up the credential?**
     - API token: Okta Admin → **Security** → **API** → **Tokens** → **Create Token**. See [`connector.mdx`](connector.mdx) Gather credentials.
     - OAuth: Okta OIDC API Services app with private_key_jwt; DPoP must be disabled for the connector's JWT path unless DPoP support is configured. See [`connector.mdx`](connector.mdx).

   * **Does it need specific scopes/permissions?**
     - Sync (read): `okta.users.read`, `okta.groups.read`, `okta.apps.read`, `okta.roles.read` (roles need elevated admin)
     - Provision (write): `okta.users.manage`, `okta.groups.manage`, `okta.apps.manage`, `okta.roles.manage` as needed
     - API tokens inherit the admin role of the creating user (Super Admin / custom role / Read-only+App+Group admin combinations — see the permissions chart in `connector.mdx`)

   * **Different scopes to sync vs provision?**
     - Yes — read scopes/roles for sync-only; manage scopes/roles for account creation, grant/revoke, and lifecycle actions.

   * **What access is needed to CREATE the credential?**
     - Admin console access with permission to create API tokens or OIDC API Services apps (typically Super Admin or equivalent).

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
| `password_change_on_login_required` | no | false | Sets `nextLogin=changePassword` when using random password |
| `create_inactive` | no | false | `activate=false`; skips activation follow-up |
| `send_activation_email` | no | true | When `false`: create staged, then `ActivateUser` with `sendEmail=false`, then re-fetch user |
| `provider_type` | no | empty (Okta default local provider) | `OKTA` or `FEDERATION` (case-insensitive). `FEDERATION` sets `credentials.provider` + query `provider=true` |
| `additionalAttributes` | no | — | Map merged into Okta profile; cannot override protected keys |

### Wire format / Okta calls

Doc root: [Okta Users API](https://developer.okta.com/docs/reference/api/users/).

| Operation | Method + path | Notes |
| :--- | :--- | :--- |
| Create user | `POST /api/v1/users` | Query: `activate`, `provider`, optional `nextLogin` |
| Activate user | `POST /api/v1/users/{id}/lifecycle/activate` | Query: `sendEmail=false` when suppressing activation email |
| Get user | `GET /api/v1/users/{idOrLogin}` | Re-fetch after activate to pick up the post-activation status; best-effort, a failure keeps the created user. Also used to adopt an existing login on retry |

### Conflict / validation rules

- `provider_type=FEDERATION` + random password credential option → error (Okta rejects password on FEDERATION users).
- `send_activation_email=false` + `password_change_on_login_required=true` + **random password** → error (staged+activate path cannot also set `nextLogin=changePassword`). On the no-password path, `password_change_on_login_required` is inert and does not conflict (pre-existing behavior).
- `create_inactive=true` wins over `send_activation_email` / `password_change_on_login_required`: evaluated first, user stays staged, no activate call, and the conflict check above is skipped.
- Without query `provider=true`, Okta **ignores** a `credentials.provider` block and creates a normal OKTA user (verified live).

### Retry semantics

The suppressed-email flow spans three calls, so a failure can leave the user created but not
activated. On retry, Okta rejects the create with `E0000001` and an `errorCauses` entry naming
`login`. The connector adopts that user **only when** `send_activation_email=false` was requested
**and** the existing user is still `STAGED` (the stranded partial-create case), then activates and
returns `AlreadyExistsResult`. A duplicate login against an already-ACTIVE (or otherwise non-STAGED)
account is returned as the original create error — it is a genuine collision, not a retry.

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

---

## Additional notes

- Error prefix at the connector layer: `okta-connectorv2:`.
- Pagination: Okta Link-header cursors via the SDK.
- Rate limits: handled by Okta SDK / HTTP client retries; respect `X-Rate-Limit-*` / `Retry-After`.
- Group profile `type` is synced for `OKTA_GROUP` / `APP_GROUP` / `BUILT_IN` (see note in `connector.mdx`).
