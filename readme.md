# MCP Governance SDK (@ithena/mcp-governance)

[![NPM Version](https://img.shields.io/npm/v/%40ithena%2Fmcp-governance)](https://www.npmjs.com/package/@ithena/mcp-governance)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
<!-- Add build status badge once CI is set up -->
<!-- [![Build Status](https://img.shields.io/github/actions/workflow/status/ithena-labs/mcp-governance/ci.yml?branch=main)](https://github.com/ithena-labs/mcp-governance/actions/workflows/ci.yml) -->

**Add essential governance capabilities – Identity, Authorization (RBAC), Credential Management, Auditing, Logging, and Tracing – to your Model Context Protocol (MCP) servers.**

This SDK provides a robust, pluggable framework that wraps the standard [`@modelcontextprotocol/sdk`](https://github.com/modelcontextprotocol/typescript-sdk) `Server` class, enabling secure and observable MCP deployments suitable for production and enterprise environments.

---

## Why This SDK?

The base `@modelcontextprotocol/sdk` provides the core mechanics for MCP communication but leaves critical governance aspects to the implementer. Building these features consistently and securely for every MCP server is complex, repetitive, and error-prone.

`@ithena/mcp-governance` solves this by providing a standard layer that addresses:

*   **❓ Who is making the request?** → **Identity Resolution**
*   **🔒 What are they allowed to do?** → **Authorization (RBAC)**
*   **🔑 How do handlers get secrets securely?** → **Credential Resolution**
*   **📝 What happened during the interaction?** → **Auditing**
*   **🩺 How can we observe and debug?** → **Structured Logging & Trace Context Propagation**

By using this SDK, you can focus on your core MCP resource, tool, and prompt logic, while leveraging a consistent framework for essential governance tasks.

## Key Features

*   🆔 **Pluggable Identity:** Integrate with your existing authentication systems via the `IdentityResolver` interface.
*   🛡️ **Flexible RBAC:** Define roles and permissions using `RoleStore` and `PermissionStore` interfaces. Includes simple in-memory defaults for easy start.
*   🔑 **Secure Credential Injection:** Use `CredentialResolver` to fetch and inject secrets (API keys, tokens) into handlers without hardcoding.
*   ✍️ **Comprehensive Auditing:** Generate detailed audit logs for requests and (optionally) notifications via the `AuditLogStore` interface. Includes defaults for console or no-op.
*   🪵 **Structured Logging:** Enhanced, request-scoped logging with context (event ID, trace ID, etc.) via the `Logger` interface. Includes console default.
*   🔗 **Trace Context Propagation:** Supports standards like W3C Trace Context out-of-the-box via `TraceContextProvider`.
*   ⚙️ **Configurable Pipeline:** Fine-tune behavior like RBAC enforcement, auditing rules, and error handling.
*   📦 **Minimal Intrusion:** Wraps the base SDK `Server` without requiring modifications to it.

## Installation

```bash
npm install @ithena/mcp-governance @modelcontextprotocol/sdk zod
```
or
```bash
yarn add @ithena/mcp-governance @modelcontextprotocol/sdk zod
```

**Note:** `@modelcontextprotocol/sdk` and `zod` are peer dependencies. Ensure you have compatible versions installed in your project.

## Quick Start

This example demonstrates wrapping a base MCP server, adding simple identity resolution (via a hardcoded header), RBAC using in-memory stores, and console logging/auditing.

```typescript
import { Server as BaseServer } from '@modelcontextprotocol/sdk/server';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio';
import { Request, Result } from '@modelcontextprotocol/sdk';
import {
    GovernedServer,
    ConsoleLogger,           // Default structured logger
    ConsoleAuditLogStore,    // Default audit store (logs to console)
    InMemoryRoleStore,       // Default in-memory RBAC store
    InMemoryPermissionStore, // Default in-memory RBAC store
    IdentityResolver,        // Interface for identity
    OperationContext,
    UserIdentity,
    GovernedRequestHandlerExtra
} from '@ithena/mcp-governance';
import { z } from 'zod'; // Peer dependency

// --- 1. Create Base MCP Server ---
const baseServer = new BaseServer({ name: "MyGovernedServer", version: "1.0.0" });

// --- 2. Configure Governance Components ---
const logger = new ConsoleLogger({}, 'debug'); // Log debug messages and above
const auditStore = new ConsoleAuditLogStore();

// Configure RBAC (In-memory example)
const roleStore = new InMemoryRoleStore({
    'user-admin': ['admin'],         // User 'user-admin' has role 'admin'
    'user-viewer': ['viewer'],       // User 'user-viewer' has role 'viewer'
});
const permissionStore = new InMemoryPermissionStore({
    'admin': ['tool:call:admin_tool', 'resource:read:*'], // 'admin' can call admin_tool and read any resource
    'viewer': ['resource:read:public/*'],               // 'viewer' can read resources matching public/*
});

// Simple Identity Resolver (Example: trusts a header)
// !! Replace with real authentication logic in production !!
const identityResolver: IdentityResolver = {
    async resolveIdentity(opCtx: OperationContext): Promise<UserIdentity | null> {
        const userHeader = opCtx.transportContext.headers?.['x-user-id'];
        const userId = Array.isArray(userHeader) ? userHeader[0] : userHeader;
        if (userId) {
            logger.debug(`Resolved identity from header: ${userId}`);
            return userId; // Return the user ID string
        }
        logger.debug('No user ID header found');
        return null;
    }
};

// --- 3. Create GovernedServer ---
const governedServer = new GovernedServer(baseServer, {
    logger: logger,
    auditStore: auditStore,
    identityResolver: identityResolver,
    roleStore: roleStore,
    permissionStore: permissionStore,
    enableRbac: true, // Turn on RBAC checks
    auditDeniedRequests: true, // Log requests even if denied by RBAC
    // auditNotifications: false, // Default: don't audit notifications
    // failOnCredentialResolutionError: true, // Default: fail if creds needed but not resolved
    serviceIdentifier: "my-mcp-service-instance-1", // Optional ID for audit/logs
});

// --- 4. Register Handlers via GovernedServer ---
// Note: Handlers receive 'GovernedRequestHandlerExtra' with added context

// Example Tool accessible only by 'admin' role
const adminToolSchema = z.object({
    method: z.literal('tools/call'),
    params: z.object({ name: z.literal('admin_tool') })
});
governedServer.setRequestHandler(adminToolSchema,
    async (request: z.infer<typeof adminToolSchema>, extra: GovernedRequestHandlerExtra): Promise<Result> => {
        extra.logger.info(`Executing admin_tool for identity: ${extra.identity}`);
        // Access roles: extra.roles
        return { content: [{ type: 'text', text: `Admin operation successful for ${extra.identity}` }] };
    }
);

// Example Resource accessible by 'admin' (via wildcard) and 'viewer' (if URI matches)
const resourceSchema = z.object({
    method: z.literal('resources/read'),
    params: z.object({ uri: z.string() })
});
governedServer.setRequestHandler(resourceSchema,
    async (request: z.infer<typeof resourceSchema>, extra: GovernedRequestHandlerExtra): Promise<Result> => {
         extra.logger.info(`Reading resource ${request.params.uri} for ${extra.identity}`);
        // Example: Check if URI matches viewer permission specifically (already handled by RBAC engine)
        // if (!extra.roles?.includes('admin') && !request.params.uri.startsWith('public/')) {
        //    throw new Error("Access denied by handler logic"); // Should be caught by RBAC ideally
        // }
        return { contents: [{ uri: request.params.uri, text: `Content of ${request.params.uri}` }] };
     }
);

// --- 5. Connect Transport ---
const transport = new StdioServerTransport();
await governedServer.connect(transport);

logger.info("Governed MCP server started on stdio.");
logger.info("Try sending requests with 'x-user-id' header context (e.g., via curl + SSE or a test client).");
logger.info("Example valid user IDs: user-admin, user-viewer");

// --- Graceful Shutdown ---
process.on('SIGINT', async () => {
    logger.info("SIGINT received, shutting down...");
    await governedServer.close();
    logger.info("Shutdown complete.");
    process.exit(0);
});
```

## Core Concepts & Interfaces

The SDK uses a set of interfaces to allow plugging in your own logic or infrastructure components.

*   **`GovernedServer`**: The main class that wraps the base `Server`. You register handlers with this class.
*   **`IdentityResolver`**: Implement this to determine the `UserIdentity` from incoming request context (e.g., parse JWT, validate API key).
    ```typescript
    interface IdentityResolver {
      resolveIdentity(opCtx: OperationContext): Promise<UserIdentity | null>;
    }
    ```
*   **`RoleStore`**: Implement this to fetch the roles associated with a `UserIdentity`.
    ```typescript
    interface RoleStore {
      getRoles(identity: UserIdentity, opCtx: OperationContext): Promise<string[]>;
    }
    ```
*   **`PermissionStore`**: Implement this to check if a given `role` has a specific `permission`. Permissions are strings, typically derived from the MCP method and parameters (e.g., `tool:call:my_tool`, `resource:read:users/*`).
    ```typescript
    interface PermissionStore {
      hasPermission(role: string, permission: string, opCtx: OperationContext): Promise<boolean>;
    }
    ```
*   **`CredentialResolver`**: Implement this to securely fetch secrets (API keys, database passwords, etc.) needed by your MCP handlers. These secrets are passed via `GovernedRequestHandlerExtra.resolvedCredentials`.
    ```typescript
    interface CredentialResolver {
      resolveCredentials(identity: UserIdentity | null, opCtx: OperationContext): Promise<ResolvedCredentials | null | undefined>;
    }
    ```
*   **`AuditLogStore`**: Implement this to send structured `AuditRecord` data to your logging or SIEM system.
    ```typescript
    interface AuditLogStore {
      log(record: AuditRecord): Promise<void>;
      shutdown?: () => Promise<void>; // Optional: For flushing buffers, etc.
    }
    ```
*   **`Logger`**: Interface for structured logging. You can provide your own logger (e.g., Pino, Winston adapter) or use the `ConsoleLogger` default. Request-scoped loggers include context like `eventId` and `traceId`.
    ```typescript
    interface Logger {
      debug(message: string, context?: LogContext): void;
      // info, warn, error methods...
      child?: (bindings: LogContext) => Logger; // Important for scoping
    }
    ```
*   **`TraceContextProvider`**: A function to extract `TraceContext` (like `traceId`, `spanId`) from incoming requests, typically from headers (e.g., `traceparent`).
    ```typescript
    type TraceContextProvider = (
        transportContext: TransportContext,
        mcpMessage: Request | Notification
    ) => TraceContext | undefined;
    ```

## Configuration (`GovernedServerOptions`)

You configure the `GovernedServer` via its second constructor argument:

```typescript
const server = new GovernedServer(baseServer, {
    // --- Core Components (Plug in your implementations) ---
    identityResolver: myIdentityResolver, // Required for RBAC
    roleStore: myRoleStore,               // Required for RBAC
    permissionStore: myPermissionStore,     // Required for RBAC
    credentialResolver: myCredentialResolver, // Optional
    auditStore: myAuditStore,             // Optional (defaults to NoOp)
    logger: myLogger,                   // Optional (defaults to ConsoleLogger)
    traceContextProvider: myTraceProvider,  // Optional (defaults to W3C)

    // --- Behavior Flags ---
    enableRbac: true,                       // Default: false
    failOnCredentialResolutionError: true,  // Default: true
    auditDeniedRequests: true,              // Default: true
    auditNotifications: false,              // Default: false

    // --- Customization Hooks ---
    derivePermission: myPermissionDeriver,  // Optional (defaults provided)
    sanitizeForAudit: myAuditSanitizer,     // Optional (defaults provided)
    postAuthorizationHook: myPostAuthHook,  // Optional hook after successful AuthZ

    // --- Optional Metadata ---
    serviceIdentifier: "my-service-1",      // Optional string ID for logs/audits
});
```

## Default Implementations

For ease of development and testing, the SDK provides:

*   `ConsoleLogger`: Logs structured JSON to the console.
*   `NoOpAuditLogStore`: Disables auditing (default).
*   `ConsoleAuditLogStore`: Logs audit records as JSON to the console.
*   `InMemoryRoleStore` / `InMemoryPermissionStore`: Simple stores for defining roles/permissions programmatically. **Not for production.**
*   `defaultTraceContextProvider`: Parses W3C `traceparent` and `tracestate` headers.
*   `defaultDerivePermission`: Creates permission strings like `tool:call:<name>`.
*   `defaultSanitizeForAudit`: Basic masking of common secret patterns in audit logs. **Review and enhance for production.**

## Architecture: The Governance Pipeline

When `GovernedServer` receives an MCP Request, it executes these steps sequentially:

1.  **Context Setup:** Generate `eventId`, get `TransportContext`, extract `TraceContext`, create scoped `Logger`.
2.  **Identity Resolution:** Call `identityResolver`.
3.  **Authorization (RBAC):** (If `enableRbac: true`) Derive permission, call `roleStore`, call `permissionStore`. Throws `AuthorizationError` on denial.
4.  **Post-Authorization Hook:** (If provided) Execute hook after successful authorization.
5.  **Credential Resolution:** (If `credentialResolver` provided) Call `credentialResolver`. Handle errors based on `failOnCredentialResolutionError`.
6.  **Execute Handler:** Call the user-provided handler registered via `setRequestHandler`, passing `GovernedRequestHandlerExtra`.
7.  **Send Response:** Send the handler's result or mapped error back via the transport.
8.  **Auditing:** Assemble `AuditRecord`, sanitize, and call `auditStore.log` asynchronously (fire-and-forget).

Notifications follow a simpler pipeline (Context -> Identity -> Handler -> Audit). Errors in governance steps typically prevent handler execution and result in an appropriate MCP error response.

## Security Considerations

*   **Component Security:** The security of your MCP server heavily depends on the implementations you provide for `IdentityResolver`, `RoleStore`, `PermissionStore`, and `CredentialResolver`. Validate inputs and handle errors securely within these components.
*   **Authentication:** This SDK does *not* perform authentication itself. It relies on the `IdentityResolver` to integrate with your external authentication mechanism (e.g., validating JWTs, session cookies, API keys passed via headers).
*   **Audit Sanitization:** The `defaultSanitizeForAudit` provides basic masking. **Carefully review and customize sanitization** to prevent sensitive data (secrets, PII) from leaking into audit logs.
*   **Input Validation:** Always validate inputs within your MCP request handlers (using Zod schemas provided to `setRequestHandler` is strongly recommended) and within your custom governance components.
*   **Error Messages:** Be cautious about revealing excessive internal details in error messages sent back to the client.

## Contributing

Contributions (bug reports, feature requests, pull requests) are welcome! Please refer to the contribution guidelines in the repository (if available) or follow standard GitHub practices.

## License

This project is licensed under the MIT License.
