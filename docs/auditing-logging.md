# Auditing and Logging

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
    *   Defaults: `NoOpAuditLogStore` (disables auditing), `ConsoleAuditLogStore` (logs JSON to console - **for development only**).

3.  **`sanitizeForAudit` (Configuration Option):** (`GovernedServerOptions`) A function you provide to process the `AuditRecord` *before* it's sent to the `AuditLogStore`.
    *   **Purpose:** To remove or mask sensitive information (PII, secrets, proprietary data) to prevent it from being persisted in audit logs.
    *   **Default (`defaultSanitizeForAudit`):** Provides basic masking for common patterns (keywords like `token`, `password`, `secret`; `Bearer` tokens) and truncates long strings.
    *   **⚠️ CRITICAL:** The default sanitizer is **insufficient** for most production systems. You **MUST** review its behavior and **customize it** to redact sensitive data specific to your application's parameters, results, identity objects, and error details. Failure to do so can lead to severe security vulnerabilities and compliance violations.

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

2.  **`ConsoleLogger` (Default):** (`src/defaults/logger.ts`) A basic implementation that logs JSON objects to the console, including any provided context. Supports creating child loggers. **Suitable for development only.**

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