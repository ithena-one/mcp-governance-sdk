# Auditing and Logging

> **⚠️ Production Warning:** This SDK provides default implementations for many components (e.g., `ConsoleAuditLogStore`, `ConsoleLogger`) to simplify initial setup and development. However, many of these defaults are **NOT suitable for production environments** due to limitations in persistence, performance, or security. Always review the defaults mentioned in this document and others (like Authorization) and provide production-ready implementations for critical components before deployment.

**Navigation:**
* [← Back to Authorization](./authorization.md)
* [Next: Default Implementations →](./defaults.md)

The `@ithena/mcp-governance` SDK provides robust mechanisms for observing the behavior of your MCP server through auditing and structured logging.

## Auditing

Auditing creates a detailed, structured record of each significant operation (primarily requests, optionally notifications) processed by the `GovernedServer`. This is crucial for security monitoring, compliance, and debugging.

**Key Components:**

1.  **`AuditRecord` (Type):** (`src/types.ts`) Defines the structure of the data captured for each audit event. Key fields include:
    *   `eventId`: Unique identifier for the operation.
    *   `timestamp`: When the operation completed (ISO 8601).
    *   `serviceIdentifier`: Optional ID of your server instance.
    *   `transport`: Details about the connection (`transportType`, `headers`, `remoteAddress`, `sessionId`).
    *   `mcp`: Details about the MCP message (`type`, `method`, `id`, `params`).
    *   `identity`: The resolved user identity (potentially sanitized).
    *   `trace`: Distributed tracing context (`traceId`, `spanId`, etc.).
    *   `outcome`: The final result of the operation:
        *   `status`: `'success'`, `'failure'`, or `'denied'`.
        *   `error?`: Details about any error that occurred (type, message, code, details).
        *   `mcpResponse?`: The result or error payload sent back to the client (for requests).
    *   `authorization?`: Details of the RBAC check (permission attempted, roles, decision).
    *   `credentialResolution?`: Outcome of the credential fetching step.
    *   `durationMs`: Total processing time.

2.  **`AuditLogStore` (Interface):** (`src/interfaces/audit.ts`) Your implementation receives `AuditRecord` objects and sends them to your chosen storage/analysis system (SIEM, database, log aggregator).
    *   Requires implementing the `log(record: AuditRecord): Promise<void>` method. This method **must handle its own errors** and should not throw, as it's called asynchronously after the request completes.
    *   Defaults:
        *   `NoOpAuditLogStore`: **The safe default if no `auditStore` is configured.** This store does nothing, effectively disabling audit logging.
        *   `ConsoleAuditLogStore`: Logs the full audit record as JSON to the console. **⚠️ Suitable for development and debugging only.** While not recommended for production, using this during initial development can be helpful to see the structure and content of audit records.
    *   **⚠️ Production Warning:** Default implementations like `InMemoryRoleStore` and `InMemoryPermissionStore` (used in Authorization) are often provided for ease of getting started but may not be suitable for production due to lack of persistence or security features. Always review the documentation for *all* configured components and their defaults to ensure they meet your production requirements.

3.  **`sanitizeForAudit` (Configuration Option):** (`GovernedServerOptions`) A function you provide to process the `AuditRecord` *before* it's sent to the `AuditLogStore`.
    *   **Purpose:** To remove, mask, or transform sensitive information (PII, secrets, proprietary data, etc.) within the `AuditRecord` before it reaches persistent storage, preventing accidental exposure in logs.
    *   **Default (`defaultSanitizeForAudit`):** The SDK provides a basic default sanitizer (`src/defaults/sanitization.ts`) that uses **regular expressions to match common secret key names** (e.g., `apiKey`, `secret`, `password`, `token`, including `Bearer` tokens) and masks their corresponding values. It also attempts to avoid simple substring matches (like `token` within `tokenizer`) and truncates very long string values.
    *   **⚠️ CRITICAL IMPORTANCE:** The default, key-based pattern-matching sanitizer serves only as a **basic starting point**. Robust secret detection is complex, and relying solely on key names is often **insufficient and potentially brittle** (prone to false positives and negatives) for production environments.
    *   **Recommendation:** You **MUST** carefully review the default sanitizer's logic and limitations. It is **strongly recommended** that you implement and provide your own `sanitizeForAudit` function tailored to your specific application's data structures, parameter names, result formats, identity object structure, and overall sensitivity requirements. Failure to implement adequate sanitization can lead to **severe security vulnerabilities and compliance issues** if sensitive data leaks into audit logs.

4.  **Configuration Options:**
    *   `auditStore`: Provide your `AuditLogStore` implementation.
    *   `sanitizeForAudit`: Provide your custom sanitization function.
    *   `auditDeniedRequests` (default `true`): Log audits even if RBAC denied the request.
    *   `auditNotifications` (default `false`): Log audits for incoming notifications (requires `auditStore` and `sanitizeForAudit`).

## Structured Logging

The SDK uses a structured logging approach, allowing you to capture log messages with associated context (like `eventId`, `traceId`, `userId`).

**Key Components:**

1.  **`Logger` (Interface):** (`src/interfaces/logger.ts`) Defines the standard logging methods (`debug`, `info`, `warn`, `error`).
    *   Accepts an optional `context` object for structured data.
    *   The `error` method accepts an optional `Error` object.
    *   The optional `child(bindings: LogContext): Logger` method is used by the SDK to create request-scoped loggers, automatically adding context like `eventId`, `requestId`, `method`, `traceId`, etc., to every message logged during that request's lifecycle.

2.  **`ConsoleLogger` (Default):** (`src/defaults/logger.ts`) A basic implementation that logs JSON objects to the console, including any provided context. Supports creating child loggers. **⚠️ Suitable for development and debugging only; do not use in production.**

3.  **Usage:**
    *   Provide your `Logger` implementation via the `logger` option in `GovernedServerOptions`.
    *   The SDK automatically creates request-scoped loggers and passes them to:
        *   Governance components (via `OperationContext.logger`).
        *   Your MCP handlers (via `GovernedRequestHandlerExtra.logger` / `GovernedNotificationHandlerExtra.logger`).
    *   Use the provided logger instance within your components and handlers to emit logs with consistent context.

    ```typescript
    // Example within a request handler
    governedServer.setRequestHandler(mySchema,
        async (request, extra) => {
            extra.logger.info("Handler started", { customData: "value" });
            try {
                // ... handler logic ...
                extra.logger.debug("Intermediate step successful");
                return { success: true };
            } catch (err) {
                extra.logger.error("Handler failed", err, { input: request.params });
                throw err; // Re-throw for pipeline error handling
            }
        }
    );
    ```

4.  **Integration:** Create an adapter for your preferred Node.js logging library (e.g., Pino, Winston, Bunyan) that implements the `Logger` interface. Ensure your adapter correctly implements the `child` method if you want request-scoped logging context.

## Tracing

The SDK facilitates distributed tracing by extracting trace context information.

1.  **`TraceContext` (Type):** (`src/types.ts`) Holds standard tracing identifiers (e.g., `traceId`, `spanId`, `traceFlags`, `traceState`).
2.  **`TraceContextProvider` (Type):** (`src/interfaces/tracing.ts`) A function signature `(transportContext, mcpMessage) => TraceContext | undefined`.
3.  **`defaultTraceContextProvider` (Default):** (`src/defaults/tracing.ts`) Implements `TraceContextProvider` by looking for W3C Trace Context headers (`traceparent`, `tracestate`) in `transportContext.headers`.
4.  **Usage:**
    *   The `GovernedServer` calls the configured `traceContextProvider` at the start of the pipeline.
    *   The resulting `TraceContext` is added to:
        *   `OperationContext` (passed to governance components).
        *   `GovernedRequestHandlerExtra` / `GovernedNotificationHandlerExtra` (passed to your handlers).
        *   `AuditRecord`.
        *   The request-scoped `Logger`'s context (if the logger supports `child`).
    *   Use this context to correlate logs and traces across different services. Provide a custom provider if you use a different propagation standard.

**Navigation:**
* [← Back to Authorization](./authorization.md)
* [Next: Default Implementations →](./defaults.md) 