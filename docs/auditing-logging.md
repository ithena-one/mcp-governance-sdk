# Auditing and Logging

> **⚠️ Production Warning:** This SDK provides default implementations for many components (e.g., `ConsoleAuditLogStore`, `ConsoleLogger`) to simplify initial setup and development. However, many of these defaults are **NOT suitable for production environments** due to limitations in persistence, performance, or security. Always review the defaults mentioned in this document and others (like Authorization) and provide production-ready implementations for critical components before deployment.

**Navigation:**
* [← Back to Authorization](./authorization.md)
* [Next: Default Implementations →](./defaults.md)

The `@ithena-one/mcp-governance` SDK provides robust mechanisms for observing the behavior of your MCP server through auditing and structured logging.

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


## OpenTelemetry Tracing (Pipeline Instrumentation)

Beyond just propagating trace context, the SDK can optionally generate detailed OpenTelemetry spans for the internal stages of the governance pipeline, providing granular performance insights.

This uses the standard [`@opentelemetry/api`](https://github.com/open-telemetry/opentelemetry-js-api) package.

**Enabling the Feature:**

1.  **Configure SDK:** Your application needs a fully configured OpenTelemetry SDK (`@opentelemetry/sdk-node`) with an appropriate Span Exporter (e.g., `ConsoleSpanExporter` for development, or an OTLP exporter like `@opentelemetry/exporter-trace-otlp-http` to send data to systems like Jaeger, Tempo, Datadog, etc.). **This SDK setup must run in your application's entry point *before* `GovernedServer` is imported or used.** The `mcp-governance` SDK only uses the OTel *API*; it relies on your application to initialize the *SDK* to actually collect and export the spans.

    ```typescript
    // Example minimal SDK setup in your app's main file (e.g., server.ts)
    // Run this BEFORE other imports!
    import { NodeSDK } from '@opentelemetry/sdk-node';
    import { ConsoleSpanExporter } from '@opentelemetry/exporter-trace-console';
    import { SimpleSpanProcessor } from '@opentelemetry/sdk-trace-node';

    const sdk = new NodeSDK({
      spanProcessor: new SimpleSpanProcessor(new ConsoleSpanExporter()),
      // Add serviceName, other processors/exporters as needed
    });
    sdk.start();
    // --- Your application code starts here ---
    ```

2.  **Enable in GovernedServer:** Set the `enablePipelineTracing` option to `true` in `GovernedServerOptions`:

    ```typescript
    import { GovernedServer } from '@ithena-one/mcp-governance';
    // ... other imports

    const server = new GovernedServer(baseServer, {
        // ... other options ...
        enablePipelineTracing: true, // <-- Enable span generation
    });
    ```

**Instrumented Stages:**

When enabled, the SDK will automatically create spans for the following key pipeline stages for both requests and notifications (where applicable):

*   `Ithena: Identity Resolution`
*   `Ithena: RBAC Check` (Requests only)
*   `Ithena: Credential Resolution` (Requests only)
*   `Ithena: Post-Authorization Hook` (Requests only)
*   `Ithena: Handler Invocation` (Requests and Notifications)
*   `Ithena: Notification Handler Invocation` (Specific span for notifications)

These spans will automatically link to the incoming parent trace context extracted by the `TraceContextProvider`.

**Automatically Added Attributes (Non-Sensitive Only):**

To prioritize security and avoid accidental leakage of sensitive data, the automatically generated spans **only include predefined, non-sensitive attributes**:

*   `ithena.eventId`: The unique ID for the request/notification lifecycle.
*   `mcp.method`: The MCP method being called.
*   `mcp.requestId`: The MCP request ID (for requests).
*   `ithena.identity.resolved`: (boolean) Whether identity resolution succeeded.
*   `ithena.authz.decision`: `'granted'`, `'denied'`, or `'not_applicable'`.
*   `ithena.authz.permissionAttempted`: The permission string derived for the request (if applicable).
*   `ithena.creds.status`: `'success'`, `'failure'`, `'skipped'`, or `'not_configured'`.
*   `ithena.postAuthHook.configured`: (boolean) Whether a post-auth hook is configured.
*   `ithena.handler.found`: (boolean, Notifications) Whether a handler was found for the notification.
*   `ithena.handler.schemaValid`: (boolean, Notifications) Whether the notification passed schema validation.
*   `error.type`: If a pipeline step fails, the Error `name` (e.g., `AuthorizationError`) might be added.

**🚫 What is NOT automatically added:**

*   User Identifiers (`identity.id`, email, etc.)
*   Specific Roles assigned
*   Resolved Credentials or Secrets
*   Detailed error messages or stack traces (errors are recorded via `span.recordException`, but sensitive details in messages depend on the error itself)
*   Request parameters or handler results

**Adding Custom Attributes (Manual User Responsibility):**

You can add your own specific attributes to the currently active span from within your custom components (Identity Resolvers, Role/Permission Stores, Credential Resolvers, Post-Auth Hooks, Handlers).

1.  **Import the OTel API:**
    ```typescript
    import { trace } from '@opentelemetry/api';
    ```
2.  **Get the Active Span:** Call `trace.getActiveSpan()` within your component's logic.
3.  **Add Attributes:** Use `span?.setAttribute('my.custom.attribute', 'value')` or `span?.setAttributes({...})`.

```typescript
// Example inside a custom IdentityResolver
import { trace } from '@opentelemetry/api';
import { IdentityResolver, OperationContext, UserIdentity } from '@ithena-one/mcp-governance';

class MyCustomResolver implements IdentityResolver {
    async resolveIdentity(opCtx: OperationContext): Promise<UserIdentity | null> {
        const activeSpan = trace.getActiveSpan(); // Get the current span

        opCtx.logger.info('Resolving identity...');
        activeSpan?.addEvent('Starting external IDP lookup'); // Add an event

        // ... logic to resolve identity ...
        const identity = { id: 'user-xyz', tenant: 'acme-corp' };

        if (identity) {
            // Add a NON-SENSITIVE custom attribute
            activeSpan?.setAttribute('custom.identity.tenantId', identity.tenant);

            // ⚠️ WARNING: DO NOT DO THIS with sensitive data unless you understand the risks!
            // activeSpan?.setAttribute('custom.identity.userId_SENSITIVE', identity.id);
        } else {
             activeSpan?.setAttribute('custom.identity.resolved', false);
        }
        activeSpan?.addEvent('Finished external IDP lookup');

        return identity;
    }
}
```

**⚠️ IMPORTANT:** When adding custom attributes manually, **you are responsible for ensuring no sensitive data (PII, secrets, etc.) is included** unless you have explicitly decided it's safe and necessary for your specific tracing backend and compliance requirements. The SDK cannot automatically sanitize attributes added manually via `getActiveSpan()`.


**Navigation:**
* [← Back to Authorization](./authorization.md)
* [Next: Default Implementations →](./defaults.md) 