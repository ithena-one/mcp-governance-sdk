# Default Implementations

**Navigation:**
* [← Back to Auditing & Logging](./auditing-logging.md)
* [Next: Security Considerations →](./security.md)

The `@ithena-one/mcp-governance` SDK provides several default implementations for its core interfaces. These are primarily intended for **rapid development, testing, and demonstration purposes.**

**⚠️ IMPORTANT: Most default implementations are NOT suitable for production environments and should be replaced with robust, secure alternatives integrated with your infrastructure.**

## Default Logger (`ConsoleLogger`)

*   **Interface:** `Logger`
*   **File:** `src/defaults/logger.ts`
*   **Behavior:** Logs structured JSON messages to the `console`. Supports basic log levels (`debug`, `info`, `warn`, `error`) and creating child loggers with bound context.
*   **Production Readiness:** **NO.** Suitable for development and debugging only. Replace with an adapter for your production logging library (e.g., Pino, Winston) that sends logs to a proper aggregation system.

## Default Audit Stores (`NoOpAuditLogStore`, `ConsoleAuditLogStore`)

*   **Interface:** `AuditLogStore`
*   **File:** `src/defaults/audit.ts`
*   **Behavior:**
    *   `NoOpAuditLogStore` (Default if `auditStore` option is omitted): Does absolutely nothing. Auditing is effectively disabled.
    *   `ConsoleAuditLogStore`: Logs the complete, sanitized `AuditRecord` as JSON to the `console`.
*   **Production Readiness:** **NO.** `NoOpAuditLogStore` provides no auditing. `ConsoleAuditLogStore` is only suitable for basic debugging. Replace with an implementation that sends audit records to your SIEM, log aggregation platform (e.g., ELK, Splunk, Datadog), or a dedicated audit database.

## Default RBAC Stores (`InMemoryRoleStore`, `InMemoryPermissionStore`)

*   **Interface:** `RoleStore`, `PermissionStore`
*   **File:** `src/defaults/permissions.ts`
*   **Behavior:** Provide simple, in-memory storage for user-to-role and role-to-permission mappings, configured via constructor arguments. `InMemoryPermissionStore` supports a basic wildcard (`*`) for granting all permissions to a role.
*   **Production Readiness:** **NO.** These stores are volatile (data is lost on restart) and not scalable. Replace with implementations that query your actual authorization systems (e.g., LDAP/Active Directory groups, database tables, IDP role claims, dedicated policy engine).

## Default Permission Derivation (`defaultDerivePermission`)

*   **Interface:** `GovernedServerOptions['derivePermission']`
*   **File:** `src/defaults/permissions.ts`
*   **Behavior:** Generates basic permission strings based on the MCP request method and some parameters. Examples:
    *   `tools/call` with `name: 'cleanup'` -> `"tool:call:cleanup"`
    *   `resources/read` with `uri: 'db://orders/123'` -> `"resource:read:db://orders/123"`
    *   `resources/list` -> `"resource:list"`
    *   `prompts/get` with `name: 'summary'` -> `"prompt:get:summary"`
    *   `completion/complete` with prompt ref -> `"completion:prompt:<prompt_name>:<arg_name>"`
    *   `initialize`, `ping` -> `null` (no check needed)
*   **Production Readiness:** **Maybe.** This provides a reasonable starting point, but you might need more granular permissions based on specific parameters or context. Review the generated strings and customize the function if necessary to match your authorization model. See **[Authorization](./authorization.md)**.

## Default Audit Sanitization (`defaultSanitizeForAudit`)

*   **Interface:** `GovernedServerOptions['sanitizeForAudit']`
*   **File:** `src/defaults/sanitization.ts`
*   **Behavior:** Attempts to mask common credential patterns (keywords like `key`, `token`, `secret`, `password`; `Bearer` tokens) and truncates very long string values within the `AuditRecord` before it's logged. It checks headers, MCP parameters, results, identity objects, and error details.
*   **Production Readiness:** **NEEDS REVIEW.** This is a **critical security function**. The default patterns are generic and might **miss sensitive data specific to your domain** or **incorrectly mask non-sensitive data**. You **MUST** review this function's behavior with your actual data and likely customize it significantly to ensure PII, business secrets, and other confidential information are properly redacted before logging. See **[Auditing & Logging](./auditing-logging.md)** and **[Security](./security.md)**.

## Default Trace Context Provider (`defaultTraceContextProvider`)

*   **Interface:** `TraceContextProvider`
*   **File:** `src/defaults/tracing.ts`
*   **Behavior:** Extracts trace context information from standard W3C Trace Context HTTP headers (`traceparent`, `tracestate`) found in `transportContext.headers`.
*   **Production Readiness:** **Yes, if using W3C Trace Context.** If your systems use W3C Trace Context for distributed tracing, this default should work well. If you use a different propagation format (e.g., B3), provide a custom `TraceContextProvider` function.

**Navigation:**
* [← Back to Auditing & Logging](./auditing-logging.md)
* [Next: Security Considerations →](./security.md) 