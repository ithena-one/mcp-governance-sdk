# Core Concepts

**Navigation:**
* [← Back to Getting Started](./getting-started.md)
* [Next: Configuration →](./configuration.md)

The `@ithena/mcp-governance` SDK introduces several key concepts built around the base `@modelcontextprotocol/sdk`.

## 1. `GovernedServer`

The `GovernedServer` is the main class you interact with. It acts as a **wrapper** around the standard MCP `Server` instance provided by `@modelcontextprotocol/sdk`.

*   **Purpose:** To orchestrate the governance pipeline and manage the lifecycle of governance components.
*   **Usage:**
    *   You instantiate it by passing a base `Server` instance and `GovernedServerOptions`.
    *   You register your MCP request and notification handlers (for tools, resources, prompts) directly with the `GovernedServer` instance, typically using Zod schemas for validation.
    *   You call `governedServer.connect(transport)` and `governedServer.close()` instead of calling these methods on the base `Server`.
*   **Lifecycle Management:** The `GovernedServer` uses the `LifecycleManager` internally to automatically call the optional `initialize()` method on your provided governance components (Logger, Stores, Resolvers) during `connect()` and the optional `shutdown()` method during `close()`.

## 2. Governance Pipeline

This is the sequence of steps executed by the `GovernedServer` for each incoming MCP request or notification. It allows for consistent application of governance controls.

**Request Pipeline Steps:**

1.  **Context Setup:** A unique `eventId` is generated. A request-scoped `Logger` (child logger if supported) and `TraceContext` (via `TraceContextProvider`) are created. An initial `OperationContext` and `AuditRecord` are prepared.
2.  **Identity Resolution:** If an `IdentityResolver` is configured, its `resolveIdentity` method is called to determine the `UserIdentity` of the caller. The identity is added to the `OperationContext` and `AuditRecord`. Failure here (and throwing an `AuthenticationError`) typically stops the pipeline.
3.  **RBAC (Authorization):** If `enableRbac` is true:
    *   Requires a resolved `UserIdentity`. Failure results in an `AuthorizationError`.
    *   `derivePermission` is called to get the permission string for the request (e.g., `tool:call:my_tool`).
    *   If a permission string is derived:
        *   The `RoleStore`'s `getRoles` method is called to fetch roles for the identity.
        *   The `PermissionStore`'s `hasPermission` method is checked for each role against the derived permission.
        *   If no role grants the permission, an `AuthorizationError` is thrown, stopping the pipeline.
    *   The authorization decision (`granted`, `denied`, `not_applicable`) and roles are added to the `AuditRecord`.
4.  **Post-Authorization Hook:** If configured (`postAuthorizationHook`), this asynchronous function is called *after* successful authorization (or if authorization was not applicable). It receives the resolved identity and the `OperationContext`. Failure here can optionally stop the pipeline.
5.  **Credential Resolution:** If a `CredentialResolver` is configured, its `resolveCredentials` method is called.
    *   It receives the resolved `identity` (or null) and the `OperationContext`.
    *   It should return the necessary secrets/credentials for the handler.
    *   If it fails and `failOnCredentialResolutionError` is true (default), a `CredentialResolutionError` is thrown, stopping the pipeline. If false, the error is logged, and the pipeline continues (handler receives null/undefined credentials).
    *   The outcome is added to the `AuditRecord`.
6.  **Execute Governed Handler:** The specific MCP handler (tool, resource, prompt) you registered with `GovernedServer` is executed.
    *   It receives the parsed request and `GovernedRequestHandlerExtra`, which includes the `logger`, `identity`, `roles`, `resolvedCredentials`, `traceContext`, `eventId`, etc.
    *   Errors thrown by the handler are wrapped in a `HandlerError`.
7.  **Auditing:** Regardless of success or failure, a final `AuditRecord` is assembled.
    *   The `sanitizeForAudit` function is called (if configured).
    *   If auditing is enabled for the outcome (e.g., success, failure, or denied based on `auditDeniedRequests`), the sanitized record is passed to the `AuditLogStore`'s `log` method. Auditing failures are logged but do not fail the original request.
8.  **Response/Error:** A successful result is sent back, or a mapped JSON-RPC error (based on errors caught during the pipeline) is sent.

**Notification Pipeline Steps:**

Notifications follow a simpler path, primarily focused on execution and auditing (if enabled):

1.  Context Setup (similar to requests).
2.  Identity Resolution (optional, primarily for logging/auditing context; failures typically don't stop the pipeline).
3.  Execute Governed Handler (if one is registered for the notification method). Handler errors are logged.
4.  Auditing (if `auditNotifications` is true).

*(Refer to the Mermaid diagram in `README.md` for a visual representation)*

## 3. `OperationContext`

This object aggregates context information about the current MCP operation (request or notification) and is passed to various governance components (`IdentityResolver`, `RoleStore`, `PermissionStore`, `CredentialResolver`, hooks).

**Key Properties:**

*   `eventId`: Unique ID for this operation lifecycle.
*   `timestamp`: Start time of processing.
*   `transportContext`: Information about the connection (type, headers, IP).
*   `traceContext`: Distributed tracing information (traceId, spanId).
*   `logger`: Request-scoped logger instance.
*   `mcpMessage`: The raw incoming MCP Request or Notification.
*   `serviceIdentifier`: Optional ID for the server instance.
*   `identity`: (Added by IdentityResolver) The resolved user identity.
*   `derivedPermission`: (Added during RBAC) The permission string being checked.
*   `roles`: (Added during RBAC) The roles associated with the identity.

## 4. `GovernedRequestHandlerExtra` / `GovernedNotificationHandlerExtra`

These objects extend the base SDK's `RequestHandlerExtra` and provide the enriched context directly to *your* MCP business logic handlers registered via `GovernedServer`.

**Key Properties (Request):**

*   `eventId`: Unique ID for this operation.
*   `logger`: Request-scoped logger.
*   `identity`: Resolved identity (or null).
*   `roles`: Resolved roles (if RBAC enabled).
*   `resolvedCredentials`: Credentials fetched by `CredentialResolver`.
*   `traceContext`: Distributed tracing info.
*   `transportContext`: Transport info.
*   `signal`: AbortSignal from the base SDK.
*   `sessionId`: Session ID from the transport.

## 5. Lifecycle Management (`LifecycleManager`)

This internal component handles the initialization and shutdown of governance components.

*   **Initialization (`initialize()`):** During `GovernedServer.connect()`, it iterates through all configured components (Logger, Stores, Resolvers) and calls their optional `initialize()` method *sequentially*. If any `initialize()` method throws an error, the connection process is aborted, and any already-initialized components have their `shutdown()` method called.
*   **Shutdown (`shutdown()`):** During `GovernedServer.close()`, it iterates through all *successfully initialized* components and calls their optional `shutdown()` method *in parallel*. Errors during shutdown are logged but do not prevent other components from shutting down or the server from closing.

**Navigation:**
* [← Back to Getting Started](./getting-started.md)
* [Next: Configuration →](./configuration.md) 