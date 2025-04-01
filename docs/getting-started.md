# Getting Started with MCP Governance SDK

**Navigation:**
* [← Back to README](../README.md)
* [Next: Core Concepts →](./core-concepts.md)

This guide provides a basic example of how to wrap a standard `@modelcontextprotocol/sdk` `Server` with the `@ithena/mcp-governance` SDK to add identity, RBAC, logging, and auditing.

## Prerequisites

*   Node.js (version compatible with the SDKs)
*   A package manager (npm, yarn, or pnpm)

## Installation

First, install the necessary packages:

```bash
npm install @ithena/mcp-governance @modelcontextprotocol/sdk zod
# or
yarn add @ithena/mcp-governance @modelcontextprotocol/sdk zod
# or
pnpm add @ithena/mcp-governance @modelcontextprotocol/sdk zod
```

**Peer Dependencies:** Ensure you have compatible versions of `@modelcontextprotocol/sdk` and `zod` installed (check `peerDependencies` in `@ithena/mcp-governance`'s `package.json`).

## Example Code

This example demonstrates:

*   Creating a base MCP `Server`.
*   Setting up simple, **in-memory** governance components (Logger, Audit Store, Identity Resolver, RBAC Stores).
*   Wrapping the base server with `GovernedServer`.
*   Registering request handlers through the `GovernedServer`.
*   Connecting using `StdioServerTransport`.

```typescript
// main.ts
import { Server as BaseServer } from '@modelcontextprotocol/sdk/server';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio';
import { Request, Result, CallToolResult } from '@modelcontextprotocol/sdk/types'; // Import base types
import {
    GovernedServer,
    GovernedServerOptions,
    ConsoleLogger,           // Default structured logger
    ConsoleAuditLogStore,    // Default audit store (logs to console)
    InMemoryRoleStore,       // Default in-memory RBAC store
    InMemoryPermissionStore, // Default in-memory RBAC store
    IdentityResolver,        // Interface for identity
    OperationContext,
    UserIdentity,
    GovernedRequestHandlerExtra,
    defaultDerivePermission, // Default permission derivation logic
    defaultSanitizeForAudit  // Default audit sanitization logic
} from '@ithena/mcp-governance';
import { z } from 'zod'; // Peer dependency
import process from 'node:process';

// --- 1. Create Base MCP Server ---
// This is the standard server from @modelcontextprotocol/sdk
const baseServer = new BaseServer(
    { name: "MyGovernedServer", version: "1.0.0" },
    {
        // Base server capabilities (optional, governance SDK adds its own)
        capabilities: {
            tools: {},
            resources: {},
        }
    }
);

// --- 2. Configure Governance Components ---
// Use default console logger and auditor for demonstration
const logger = new ConsoleLogger({}, 'debug'); // Log debug messages and above
const auditStore = new ConsoleAuditLogStore();

// Configure RBAC (In-memory example - REPLACE FOR PRODUCTION)
// Map user IDs to roles
const roleStore = new InMemoryRoleStore({
    'user-admin': ['admin'],
    'user-viewer': ['viewer'],
});
// Map roles to permissions
const permissionStore = new InMemoryPermissionStore({
    'admin': ['tool:call:admin_tool', 'resource:read:*'], // Admins can call 'admin_tool' and read any resource
    'viewer': ['resource:read:public/*'], // Viewers can only read resources under 'public/'
});

// Simple Identity Resolver (Example: trusts a header - INSECURE FOR PRODUCTION)
// !! Replace with real authentication logic (JWT, OAuth introspection, etc.) !!
const identityResolver: IdentityResolver = {
    async resolveIdentity(opCtx: OperationContext): Promise<UserIdentity | null> {
        const userHeader = opCtx.transportContext.headers?.['x-user-id'];
        // Note: Headers might be arrays if sent multiple times
        const userId = Array.isArray(userHeader) ? userHeader[0] : userHeader;

        if (userId) {
            logger.debug(`Resolved identity: ${userId}`, { eventId: opCtx.eventId });
            // You could return a structured object too: return { id: userId, tenant: '...' };
            return userId;
        }
        logger.debug('No identity found in x-user-id header', { eventId: opCtx.eventId });
        return null; // Return null if no identity can be determined
    }
};

// --- 3. Create GovernedServer ---
// Wrap the base server and provide the configured components
const governedServerOptions: GovernedServerOptions = {
    logger: logger,
    auditStore: auditStore,
    identityResolver: identityResolver, // Provide the identity resolver
    roleStore: roleStore,             // Provide the role store
    permissionStore: permissionStore,   // Provide the permission store
    enableRbac: true,                 // IMPORTANT: Enable RBAC checks
    auditDeniedRequests: true,        // Log requests even if denied by RBAC
    auditNotifications: false,        // Don't audit notifications in this example
    serviceIdentifier: "my-mcp-service-instance-1", // Optional identifier for logs/audits
    // derivePermission: defaultDerivePermission, // Uses default logic if omitted
    // sanitizeForAudit: defaultSanitizeForAudit, // Uses default logic if omitted
};
const governedServer = new GovernedServer(baseServer, governedServerOptions);

// --- 4. Register Handlers via GovernedServer ---
// Use Zod schemas for automatic validation. Handlers receive GovernedRequestHandlerExtra.

// Zod schema for the admin tool request
const adminToolSchema = z.object({
    jsonrpc: z.literal("2.0"),
    id: z.union([z.string(), z.number()]),
    method: z.literal('tools/call'),
    params: z.object({
        name: z.literal('admin_tool'),
        arguments: z.any().optional(), // Define specific args if needed
        _meta: z.any().optional() // Allow _meta from base schema
    })
});

governedServer.setRequestHandler(adminToolSchema,
    async (request, extra: GovernedRequestHandlerExtra): Promise<CallToolResult> => {
        // Access identity, roles, logger, etc. from 'extra'
        extra.logger.info(`Executing admin_tool for identity: ${JSON.stringify(extra.identity)}`, { roles: extra.roles });

        // RBAC already checked 'tool:call:admin_tool' permission before calling this handler

        // Handler logic...
        return { content: [{ type: 'text', text: `Admin operation successful for ${extra.identity}` }] };
    }
);

// Zod schema for resource read requests
const resourceReadSchema = z.object({
    jsonrpc: z.literal("2.0"),
    id: z.union([z.string(), z.number()]),
    method: z.literal('resources/read'),
    params: z.object({
        uri: z.string(),
        _meta: z.any().optional() // Allow _meta from base schema
    })
});

governedServer.setRequestHandler(resourceReadSchema,
    async (request, extra: GovernedRequestHandlerExtra) => {
         extra.logger.info(`Reading resource ${request.params.uri}`, { identity: extra.identity, roles: extra.roles });

         // RBAC checked 'resource:read:<uri>' permission

         // Your resource fetching logic here...
         const content = `Content of ${request.params.uri} for user ${extra.identity}`;

        return { contents: [{ uri: request.params.uri, text: content }] };
     }
);

// --- 5. Connect Transport ---
// Use the appropriate transport for your server (Stdio, SSE, WebSocket)
const transport = new StdioServerTransport();

// Connect the GovernedServer (which internally connects the baseServer)
await governedServer.connect(transport);

logger.info("Governed MCP server started on stdio.");
logger.info("Connect with an MCP client and send requests.");
logger.info("Try sending with header 'x-user-id: user-admin' or 'x-user-id: user-viewer'");

// --- 6. Graceful Shutdown ---
const shutdown = async () => {
    logger.info("Shutting down...");
    try {
        await governedServer.close(); // Close the governed server
        logger.info("Shutdown complete.");
        process.exit(0);
    } catch (err) {
        logger.error("Error during shutdown:", err);
        process.exit(1);
    }
};
process.on('SIGINT', shutdown); // Handle Ctrl+C
process.on('SIGTERM', shutdown); // Handle kill signals
```

## Running the Example

1.  Save the code above as `main.ts`.
2.  Compile it: `tsc main.ts` (you might need `npm install -g typescript @types/node`).
3.  Run the server: `node main.js`.
4.  Connect using an MCP client (like a simple Node.js client using `StdioClientTransport` or Anthropic's example clients).

**Testing RBAC:**

*   Use an MCP client that allows setting headers.
*   **To act as admin:** Send a request with the header `x-user-id: user-admin`. Try calling `admin_tool` or reading `resource:read:secret/mysecret`.
*   **To act as viewer:** Send a request with the header `x-user-id: user-viewer`. Try reading `resource:read:public/data`. Try calling `admin_tool` (should be denied). Try reading `resource:read:secret/mysecret` (should be denied).
*   **To act anonymously:** Send a request without the `x-user-id` header. Try calling `admin_tool` (should be denied).

You should see corresponding log messages and audit records (if using `ConsoleAuditLogStore`) on the server console.

## Next Steps

*   Understand the **[Core Concepts](./core-concepts.md)**.
*   Review **[Configuration](./configuration.md)** options.
*   Follow the **[Tutorial: Identity & RBAC](./tutorial.md)** for a step-by-step guide.
*   Implement **production-ready** versions of the governance components, especially `IdentityResolver`, `RoleStore`, `PermissionStore`, and potentially `CredentialResolver` and `AuditLogStore`. See the **[Interfaces](./interfaces.md)** documentation.
*   Review the **[Security Considerations](./security.md)**.

**Navigation:**
* [← Back to README](../README.md)
* [Next: Core Concepts →](./core-concepts.md) 