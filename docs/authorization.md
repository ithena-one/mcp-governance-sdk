# Authorization (RBAC)

The `@ithena/mcp-governance` SDK provides a flexible Role-Based Access Control (RBAC) system integrated into its processing pipeline.

## Enabling RBAC

To enable authorization checks, set the `enableRbac` option to `true` in the `GovernedServerOptions`.

```typescript
const options: GovernedServerOptions = {
    // ... other options
    enableRbac: true,
    identityResolver: myIdentityResolver, // REQUIRED for RBAC
    roleStore: myRoleStore,             // REQUIRED for RBAC
    permissionStore: myPermissionStore,   // REQUIRED for RBAC
    // derivePermission: myPermissionDeriver, // Optional: Defaults work often
};

const governedServer = new GovernedServer(baseServer, options);
```

When `enableRbac` is `true`, you **must** provide implementations for `identityResolver`, `roleStore`, and `permissionStore`.

## RBAC Pipeline Steps

When RBAC is enabled, the following steps occur during the request pipeline (after Identity Resolution):

1.  **Check Identity:** If the `IdentityResolver` did not return a `UserIdentity` (i.e., returned `null`), an `AuthorizationError` with `reason: 'identity'` is thrown, and the request is denied. Anonymous access is generally not permitted when RBAC is enabled unless specific permissions bypass checks (see step 3).
2.  **Derive Permission:** The `derivePermission` function (either the default or your custom one) is called with the incoming MCP `Request` and `TransportContext`. It should return a string representing the permission required for this specific operation (e.g., `tool:call:my_tool`, `resource:read:confidential/*`) or `null` if no permission check is needed for this request (e.g., for `ping`).
3.  **Check Necessity:** If `derivePermission` returns `null`, the RBAC check is skipped for this request, and the pipeline proceeds to the next step (Post-Authorization Hook or Credential Resolution).
4.  **Get Roles:** If a permission string *is* returned, the `RoleStore.getRoles(identity, opCtx)` method is called to fetch the list of roles associated with the resolved `UserIdentity`.
5.  **Check Permissions:** For each role returned by the `RoleStore`, the `PermissionStore.hasPermission(role, permission, opCtx)` method is called.
6.  **Grant/Deny:** If *any* of the user's roles grant the required permission (i.e., `hasPermission` returns `true` for at least one role), access is granted, and the pipeline proceeds. If *none* of the roles grant the permission, an `AuthorizationError` with `reason: 'permission'` is thrown, and the request is denied.

*(See **[Core Concepts](./core-concepts.md)** for the full pipeline diagram)*

## Components

*   **`IdentityResolver`:** (See **[Interfaces](./interfaces.md#identityresolver)**) Must successfully resolve a non-null `UserIdentity` for RBAC checks to proceed.
*   **`RoleStore`:** (See **[Interfaces](./interfaces.md#rolestore)**) Maps a `UserIdentity` to a list of role strings (`string[]`).
*   **`PermissionStore`:** (See **[Interfaces](./interfaces.md#permissionstore)**) Determines if a specific `role` string grants a specific `permission` string.

## Permission Strings

Permissions are simple strings used to represent the action being performed. The `derivePermission` function is responsible for generating these strings.

*   **Default Logic (`defaultDerivePermission`):** The default implementation generates permissions based on the MCP method and some key parameters. Examples:
    *   `tools/call` with `name: 'cleanup'` -> `"tool:call:cleanup"`
    *   `resources/read` with `uri: 'db://orders/123'` -> `"resource:read:db://orders/123"`
    *   `resources/list` -> `"resource:list"`
    *   `prompts/get` with `name: 'summary'` -> `"prompt:get:summary"`
    *   `completion/complete` with prompt ref -> `"completion:prompt:<prompt_name>:<arg_name>"`
    *   `initialize`, `ping` -> `null` (no check needed)
*   **Custom Logic:** You can provide your own `derivePermission` function in `GovernedServerOptions` if the default logic doesn't fit your needs or if you require more granularity based on request parameters or transport context.

```typescript
// Example Custom derivePermission
function myDerivePermission(request: Request, transportCtx: TransportContext): string | null {
    if (request.method === 'tools/call') {
        const toolName = request.params?.name;
        // Add extra check based on IP for a specific tool
        if (toolName === 'internal_admin_tool' && transportCtx.remoteAddress !== '192.168.1.10') {
             // Let PermissionStore handle the actual grant/deny based on role,
             // but derive a specific permission for internal access.
             return `internal:tool:call:${toolName}`;
        }
        // Fallback to default-like logic for other tools
        return toolName ? `tool:call:${toolName}` : null;
    }
    // Use default for other methods (or add more custom logic)
    return defaultDerivePermission(request, transportCtx);
}

const options: GovernedServerOptions = {
    // ...
    enableRbac: true,
    derivePermission: myDerivePermission,
    // ... other RBAC stores
};
```

## Error Handling

*   **`AuthenticationError`:** Thrown by `IdentityResolver` on failed authentication. Results in a `4xx` range error response (often mapped to MCP `InvalidRequest` or a custom code).
*   **`AuthorizationError`:** Thrown by the pipeline if identity is missing (`reason: 'identity'`) or if no role grants the required permission (`reason: 'permission'`). Results in a `4xx` range error response (often mapped to a custom `-32001` code or similar).

## Denied Request Auditing

By default (`auditDeniedRequests: true`), even requests denied by RBAC are logged by the `AuditLogStore`. The `AuditRecord.outcome.status` will be `'denied'`, and `AuditRecord.outcome.error` and `AuditRecord.authorization` will contain details about the denial. Set `auditDeniedRequests: false` to suppress these audit logs. 