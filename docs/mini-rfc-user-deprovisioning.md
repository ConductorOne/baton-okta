# Mini RFC: Okta user deactivation and deletion

**Status:** Accepted for implementation in PR #180  
**Issues:** CXH-1999, CXH-2267 (formerly CXP-925)

## Context

Okta has three materially different account-offboarding operations:

| Operation | Okta endpoint | Result | Reversible | Assignments |
|---|---|---|---|---|
| Suspend | `POST /api/v1/users/{id}/lifecycle/suspend` | `SUSPENDED` | Yes, with unsuspend | Retained |
| Deactivate | `POST /api/v1/users/{id}/lifecycle/deactivate` | `DEPROVISIONED` | Account may be reactivated, but downstream deprovisioning can destroy data | Removed/deprovisioned |
| Delete | `DELETE /api/v1/users/{id}` | User permanently removed | No | User already must be deprovisioned |

The connector already exposes `disable_user`, which deliberately means **suspend**, and `enable_user`, which activates or unsuspends. Reusing `disable_user` for deactivation would silently turn a reversible workflow step into a destructive one. This RFC therefore preserves that contract and adds explicit deactivation and deletion surfaces.

Okta's delete endpoint is stateful: when called on a user that is not `DEPROVISIONED`, the first call deactivates rather than deletes and a second call is required. A connector operation named delete must guarantee the final state, not merely issue one ambiguous DELETE request.

## Goals

1. Support C1's standard account deprovisioning path through Baton's `ResourceDeleterV2Limited` interface.
2. Expose explicit `deactivate_user` and `delete_user` Baton actions for direct use in C1 workflows.
3. Preserve the existing `disable_user` suspend semantics.
4. Make resource deletion and explicit deletion retry-safe.
5. Share lifecycle orchestration so the resource and action paths cannot drift.

## Non-goals

- Changing `enable_user` or `disable_user` arguments or behavior.
- Automatically reactivating a `DEPROVISIONED` user.
- Sending Okta deactivation emails.
- Waiting on `Prefer: respond-async`; the connector uses Okta's synchronous default.
- Adding a confirmation protocol not represented by `BatonActionSchema`; workflow authors remain responsible for approval gates around destructive actions.

## API surfaces

### Standard resource deletion

`userResourceType.Delete(ctx, resourceID, parentResourceID)` implements `connectorbuilder.ResourceDeleterV2Limited`. It validates that the resource is a non-empty Okta `user` ID, then invokes the shared permanent-delete operation. The SDK discovers the interface and publishes `CAPABILITY_RESOURCE_DELETE` for the user resource type.

### Global Baton actions

The actions are global because C1's **Perform connector action** workflow step enumerates global connector actions. The Active Directory and other connector implementations use this pattern for workflow-callable account operations.

| Action | Argument | Action type | Contract |
|---|---|---|---|
| `disable_user` (existing) | `user_id` string | `ACCOUNT`, `ACCOUNT_DISABLE` | Suspend; reversible; retained unchanged |
| `deactivate_user` (new) | `user_id` resource ID restricted to `user` | `ACCOUNT` | Ensure the user is `DEPROVISIONED`, but do not delete |
| `delete_user` (new) | `user_id` resource ID restricted to `user` | `ACCOUNT` | Ensure deactivation, then permanently delete |

The new actions use `ResourceIdField` so a C1 workflow can bind a synced Okta user directly instead of extracting and passing a raw vendor ID. They use generic `ACCOUNT`, not `ACCOUNT_DISABLE`: `disable_user` remains the single standardized account-disable action consumed by lifecycle automation. They also avoid `RESOURCE_DELETE` action typing because the standard resource-deletion interface is the platform-owned deletion path; `delete_user` is an explicitly selected workflow action.

Both new actions return:

- `success` (`bool`)
- `message` (`string`) describing whether the operation changed state or was already satisfied

## Lifecycle orchestration

### Deactivate-only operation

1. Validate the user ID.
2. Read the current user status while bypassing the Okta SDK GET cache.
3. If the user is missing, return `NotFound`.
4. If status is already `DEPROVISIONED`, succeed without a mutation.
5. Otherwise call `DeactivateUser` with `sendEmail=false`.
6. If the mutation loses a race, re-read the user: a confirmed `DEPROVISIONED` state is success, while a missing user remains `NotFound` for this action. Preserve the original mutation error if the re-read shows any other state or itself fails for a non-not-found reason.

### Permanent-delete operation

1. Validate the user ID.
2. Read the current user status while bypassing the Okta SDK GET cache.
3. If the user is missing, succeed as already deleted.
4. If status is not `DEPROVISIONED`, call `DeactivateUser` with `sendEmail=false`.
5. If deactivation loses a race, re-read the user. Continue when the user is now `DEPROVISIONED`; succeed when it is now missing; otherwise preserve the original mutation error.
6. Call `DeactivateOrDeleteUser` once the user is deprovisioned.
7. Only `204 No Content` confirms permanent deletion. If Okta returns another successful status such as `202 Accepted`, perform one fresh status read and issue the required second DELETE only after Okta reports `DEPROVISIONED`.
8. If deactivation is still incomplete, or a second DELETE still does not return 204, return a retryable error rather than claiming the user is gone.
9. Treat a not-found delete response as success because another actor completed the requested terminal state.

The Okta SDK treats every 2xx response as transport success. The connector adds the operation-specific 204 check because DELETE on a non-deprovisioned user can mean “deactivation accepted,” not “user permanently removed.”

### State matrix

| Initial state | `deactivate_user` | `delete_user` / resource delete |
|---|---|---|
| `ACTIVE`, `PROVISIONED`, `RECOVERY`, `PASSWORD_EXPIRED`, `LOCKED_OUT`, `STAGED`, `SUSPENDED` | Deactivate | Deactivate, then delete |
| `DEPROVISIONED` | No-op success | Delete |
| Missing | `NotFound` | No-op success |
| Unknown future status returned by Okta | Attempt deactivation and let Okta enforce its lifecycle rules | Attempt deactivation, then delete on success |

## Errors and observability

- Missing/empty/wrong-type resource arguments return `InvalidArgument` before any Okta call.
- Okta not-found errors are classified from structured Okta error codes through the connector's existing gRPC error mapping, never from error-message strings.
- Delete retries treat `NotFound` as success; deactivate-only calls do not because their requested observable state is a surviving `DEPROVISIONED` user.
- A lifecycle mutation rejected during a concurrent transition is reconciled with one fresh status re-read. The connector only converts the error to success when Okta now proves the requested state; it never matches vendor error text.
- Permission failures, invalid lifecycle transitions, rate limits, timeouts, and server errors remain errors.
- Helpers return wrapped errors; the SDK owns terminal error logging to avoid duplicate error logs.
- Success logs include the Okta user ID and final operation without sensitive profile data.
- Destructive lifecycle decisions bypass the SDK GET cache. A stale `DEPROVISIONED` value could otherwise make Okta's first DELETE call merely deactivate a reactivated user while the connector incorrectly reports permanent deletion.

## Implementation shape

- Keep low-level wrappers for Okta deactivate and delete calls.
- Add a shared state-aware service function used by both `userResourceType.Delete` and `delete_user`.
- Add a shared deactivate-only function used by `deactivate_user` and the permanent-delete service.
- Register the new schemas in `Okta.GlobalActions` with contextual registration errors.
- Add compile-time interface assertions for the user resource deleter and global action provider.

## Verification

Tests use the real vendored Okta v2 client against an `httptest.Server`, asserting HTTP method, path, query, and call order.

Required cases:

1. Active user resource deletion performs GET → deactivate (`sendEmail=false`) → DELETE.
2. Deprovisioned user deletion skips deactivate.
3. Missing user deletion is idempotent and performs no mutation.
4. A deletion race that returns not-found during deactivate or delete succeeds.
5. A non-204 DELETE is completed with a fresh status read and second DELETE, or returns a retryable error without claiming success.
6. Reconciliation preserves the original mutation error when the fresh status does not prove success or the status read fails.
7. Deactivate action changes an active user and no-ops a deprovisioned user.
8. Deactivate action returns `NotFound` for a missing user.
9. Action schemas are globally registered with resource-ID arguments, return fields, and the intended action types.
10. Invalid resource IDs fail before network access.
11. Generated capabilities match `baton_capabilities.json`.
12. Connector tests, build, lint, and metadata validation pass.

## Documentation and rollout

- Update `README.md`, `docs/connector.mdx`, and `docs/docs-info.md` to distinguish suspend, deactivate, and delete.
- Document destructive behavior, retry semantics, required `okta.users.manage` scope, and workflow action arguments.
- Regenerate `baton_capabilities.json` from the built connector rather than editing it by hand.
- Call out the behavioral rollout explicitly: before this change, C1's standard Okta account-deprovisioning path was unsupported; after this change, invoking that path permanently deletes the Okta user after deactivation. This is the requested CXH-1999 contract, so it is not hidden behind a connector-specific flag.
- Existing `enable_user` / `disable_user` workflows retain their schemas and reversible semantics. The explicit `deactivate_user` and `delete_user` actions are additive.
