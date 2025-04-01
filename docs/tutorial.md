# Tutorial: Implementing Basic Governance (Identity & RBAC) with `@ithena-one/mcp-governance`

This tutorial guides you through incrementally adding **Identity Resolution** and **Role-Based Access Control (RBAC)** to a Model Context Protocol (MCP) server using the `@ithena-one/mcp-governance` SDK. We'll start with a basic setup and progressively enhance a single application file (`src/governed-app.ts`).

**Prerequisites:**

*   Node.js (v18 or later recommended)
*   npm, yarn, or pnpm
*   Basic understanding of TypeScript
*   Familiarity with the base `@modelcontextprotocol/sdk`
*   `@ithena-one/mcp-governance` SDK installed (e.g., `npm install @ithena-one/mcp-governance`)

**Goal:** To create a governed MCP server that identifies callers and enforces basic permissions using RBAC.

---

## Step 0: Project Setup & Initial Governed Server

**Why?** We need a starting point: a working MCP server using your governance SDK, but with most governance features turned off or using defaults. This ensures the basic SDK setup is correct before we add complexity.

1.  **Create Project & Install Dependencies:**
    ```bash
    mkdir my-governed-mcp-app
    cd my-governed-mcp-app
    npm init -y
    npm install @modelcontextprotocol/sdk @ithena-one/mcp-governance zod
    npm install --save-dev typescript @types/node
    npx tsc --init --rootDir src --outDir dist --esModuleInterop --resolveJsonModule --lib esnext --module nodenext --moduleResolution nodenext --strict
    mkdir src
    ```

2.  **Create `src/governed-app.ts`:**
    This initial version uses `GovernedServer` but only configures the default console logger and auditor. No identity or RBAC yet.

    ```typescript
    // src/governed-app.ts
    import { Server as BaseServer } from '@modelcontextprotocol/sdk/server/index.js';
    import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
    import { z } from 'zod';
    import process from 'node:process';

    // --- Import Governance SDK ---
    import {
        GovernedServer,
        GovernedServerOptions,
        ConsoleLogger,           // Default logger
        ConsoleAuditLogStore,    // Default auditor
        GovernedRequestHandlerExtra, // Type for handler context
        // We'll import interfaces as needed in later steps
    } from '@ithena-one/mcp-governance';

    console.log('Starting Governed MCP Server...');

    // --- 1. Create Base MCP Server ---
    const baseServer = new BaseServer(
        { name: "MyGovernedMCPServer", version: "1.0.0" },
        { capabilities: { tools: {} } } // Enable tools capability
    );

    // --- 2. Governance Components (Initial Defaults) ---
    const logger = new ConsoleLogger({}, 'debug'); // Log debug and above
    const auditStore = new ConsoleAuditLogStore(); // Log audits to console (NOT FOR PRODUCTION)

    // --- 3. GovernedServer Configuration (Initial) ---
    const governedServerOptions: GovernedServerOptions = {
        logger: logger,
        auditStore: auditStore,
        serviceIdentifier: "governed-app-instance",
        enableRbac: false, // Explicitly OFF for Step 0
    };

    // --- 4. Create GovernedServer instance ---
    const governedServer = new GovernedServer(baseServer, governedServerOptions);
    logger.info('GovernedServer created');

    // --- 5. Define Tool Schema ---
    const helloToolSchema = z.object({
        jsonrpc: z.literal("2.0"), id: z.union([z.string(), z.number()]),
        method: z.literal('tools/callHello'), // Unique method name
        params: z.object({
            arguments: z.object({ greeting: z.string().optional().default('Hello') }).optional().default({ greeting: 'Hello' }),
            testUserId: z.string().optional(), // We'll use this later for stdio identity testing
            _meta: z.any().optional() }) });

    // --- 6. Register Handler ---
    governedServer.setRequestHandler(helloToolSchema,
        async (request, extra: GovernedRequestHandlerExtra) => {
            const scopedLogger = extra.logger || logger;
            // Identity will be null here
            scopedLogger.info(`[Handler] Executing callHello. EventID: ${extra.eventId}`);
            const greeting = request.params?.arguments?.greeting || 'DefaultGreeting';
            const responseText = `${greeting} World from governed server!`; // No identity yet
            return { content: [{ type: 'text', text: responseText }] };
        }
    );
    logger.info('Handler registered.');

    // --- 7. Connect and Shutdown ---
    const transport = new StdioServerTransport();
    async function startServer() { /* ... (Standard startServer logic as before) ... */ }
    const shutdown = async () => { /* ... (Standard shutdown logic as before) ... */ };
    process.on('SIGINT', shutdown); process.on('SIGTERM', shutdown);
    startServer(); // Call startServer at the end
    ```
    *(Self-contained `startServer` and `shutdown` functions omitted for brevity - use the ones from the previous example)*

3.  **Build and Run:**
    ```bash
    npm run build
    node dist/governed-app.js
    ```

4.  **Test:** Send a request via stdin:
    ```json
    {"jsonrpc":"2.0","id":1,"method":"tools/callHello","params":{"arguments":{"greeting":"Initial"}}}
    ```
    *Observe:* The request should succeed. You'll see logs from the SDK and the handler, plus an audit record showing `identity: null` and `authorization: {decision: 'not_applicable'}`. This confirms the base governed setup works without specific governance logic active. Stop the server (Ctrl+C).

---

## Step 1: Implement Identity Resolution

**Why?** The first step in governance is knowing *who* is making the request. We need to implement the `IdentityResolver` interface and configure the `GovernedServer` to use it.

**Modify `src/governed-app.ts`:**

1.  **Add Imports:** Add the necessary types/interfaces near the top:
    ```typescript
    // Add near other governance imports
    import {
        IdentityResolver,
        OperationContext,
        UserIdentity
        // ... other imports ...
    } from '@ithena-one/mcp-governance';
    ```

2.  **Implement Resolver:** Define the logic for identifying the user. Place this code *before* the `governedServerOptions` definition. We'll use the parameter-based approach for stdio testing.
    ```typescript
    // --- ADDED FOR STEP 1: IdentityResolver ---
    const testIdentityResolver: IdentityResolver = {
        async resolveIdentity(opCtx: OperationContext): Promise<UserIdentity | null> {
            const scopedLogger = opCtx.logger || logger; // Use context logger
            scopedLogger.debug('Entering IdentityResolver', { eventId: opCtx.eventId });
            // Check param first for stdio testing
            const paramsObj = opCtx.mcpMessage.params as any;
            const testIdParam = paramsObj?.testUserId;
            if (testIdParam) {
                scopedLogger.info(`Identity resolved via param: ${testIdParam}`, { eventId: opCtx.eventId });
                return { id: testIdParam, source: 'param' }; // Return structured identity
            }
            // Fallback to header (for potential future SSE/HTTP testing)
            const userHeader = opCtx.transportContext.headers?.['x-test-user-id'];
            const userIdFromHeader = Array.isArray(userHeader) ? userHeader[0] : userHeader;
            if (userIdFromHeader) {
                 scopedLogger.info(`Identity resolved via header: ${userIdFromHeader}`, { eventId: opCtx.eventId });
                 return { id: userIdFromHeader, source: 'header' };
            }
            scopedLogger.info('No test identity found', { eventId: opCtx.eventId });
            return null;
        }
    };
    // --- END STEP 1 ---
    ```

3.  **Update `governedServerOptions`:** Add the `identityResolver` to the configuration object:
    ```typescript
    // --- 3. GovernedServer Configuration (Initial) ---
    const governedServerOptions: GovernedServerOptions = {
        logger: logger,
        auditStore: auditStore,
        identityResolver: testIdentityResolver, // <-- ADDED
        serviceIdentifier: "governed-app-instance",
        enableRbac: false, // Still OFF for this step
    };
    ```

4.  **Update Handler:** Modify the `helloToolSchema` handler to use the resolved identity (which is passed via the `extra` argument):
    ```typescript
    // Find the setRequestHandler call for helloToolSchema
    governedServer.setRequestHandler(helloToolSchema,
        async (request, extra: GovernedRequestHandlerExtra) => {
            const scopedLogger = extra.logger || logger;
            // --- MODIFIED FOR STEP 1 ---
            const identityId = typeof extra.identity === 'string' ? extra.identity : extra.identity?.id; // Get ID
            scopedLogger.info(`[Handler] Executing callHello for identity: ${identityId || 'anonymous'}. EventID: ${extra.eventId}`);
            // --- END STEP 1 ---
            const greeting = request.params?.arguments?.greeting || 'DefaultGreeting';
            // --- MODIFIED FOR STEP 1 ---
            const responseText = `${greeting} ${identityId || 'World'} from governed server!`; // Use identity in response
            // --- END STEP 1 ---
            return { content: [{ type: 'text', text: responseText }] };
        }
    );
    ```

5.  **Rebuild and Run:**
    ```bash
    npm run build
    node dist/governed-app.js
    ```

6.  **Test:**
    *   *Without Identity:* `{"jsonrpc":"2.0","id":2,"method":"tools/callHello"}`
        *Observe:* Should still work, response includes "World". Check logs for "No test identity found". Audit log shows `identity: null`.
    *   *With Identity:* `{"jsonrpc":"2.0","id":3,"method":"tools/callHello","params":{"testUserId": "tester"}}`
        *Observe:* Should work, response includes "tester". Check logs for "Identity resolved via param". Audit log shows the resolved identity object.
    Stop the server.

---

## Step 2: Implement Basic RBAC

**Why?** Now that we know *who* the user is, we need to check *what* they are allowed to do. We implement `RoleStore` and `PermissionStore` and enable the RBAC check in the pipeline.

**Modify `src/governed-app.ts`:**

1.  **Add Imports:**
    ```typescript
    // Add near other governance imports
    import {
        RoleStore,
        PermissionStore,
        InMemoryRoleStore,
        InMemoryPermissionStore
        // ... other imports ...
    } from '@ithena-one/mcp-governance';
    ```

2.  **Implement RBAC Stores:** Define the roles and permissions. Place this *before* `governedServerOptions`.
    ```typescript
    // --- ADDED FOR STEP 2: RBAC Stores ---
    const testRoleStore: RoleStore = new InMemoryRoleStore({
        'admin-007': ['admin'], // User 'admin-007' has 'admin' role
        'user-123': ['user'],   // User 'user-123' has 'user' role
    });
    const testPermissionStore: PermissionStore = new InMemoryPermissionStore({
        // Define permissions granted by each role
        // Using colon format based on corrected defaultDerivePermission logic
        'admin': ['tool:callHello', 'tool:callSensitive'],
        'user': ['tool:callHello'],
    });
    // --- END STEP 2 ---
    ```

3.  **Update `governedServerOptions`:** Add the stores and crucially, set `enableRbac: true`.
    ```typescript
    // --- 3. GovernedServer Configuration (Initial) ---
    const governedServerOptions: GovernedServerOptions = {
        logger: logger,
        auditStore: auditStore,
        identityResolver: testIdentityResolver,
        roleStore: testRoleStore,             // <-- ADDED
        permissionStore: testPermissionStore,   // <-- ADDED
        enableRbac: true,                     // <-- ENABLED
        auditDeniedRequests: true,            // <-- Good practice to audit denials
        serviceIdentifier: "governed-app-instance",
    };
    ```

4.  **Add Sensitive Tool Handler:** We need a resource that requires specific permissions. Find the `// --- 6. Register Handlers ---` section and add the handler for `sensitiveToolSchema` (the schema was defined in Step 0).
    ```typescript
    // Add this alongside the helloToolSchema handler registration
    // --- ADDED FOR STEP 2 ---
    governedServer.setRequestHandler(sensitiveToolSchema,
        async (request, extra: GovernedRequestHandlerExtra) => {
            const identityId = typeof extra.identity === 'string' ? extra.identity : extra.identity?.id;
            const scopedLogger = extra.logger || logger;
            // Log roles received by the handler
            scopedLogger.info(`[Handler] Executing callSensitive for identity: ${identityId}`, { roles: extra.roles });
            // RBAC check 'tool:callSensitive' must have passed to reach here
            return { content: [{ type: 'text', text: `Sensitive data accessed by ${identityId}` }] };
        }
    );
    // --- END STEP 2 ---
    ```

5.  **Update Hello Handler Log (Optional):** You can add role logging here too for consistency.
    ```typescript
     // Modify helloTool handler log
     // --- MODIFIED FOR STEP 2 ---
     scopedLogger.info(`[Handler] Executing callHello for identity: ${identityId || 'anonymous'} with roles: ${JSON.stringify(extra.roles)}. EventID: ${extra.eventId}`);
     // --- END STEP 2 ---
    ```

6.  **Rebuild and Run:**
    ```bash
    npm run build
    node dist/governed-app.js
    ```

7.  **Test RBAC Scenarios:**
    *   *Hello (User):* `{"jsonrpc":"2.0","id":4,"method":"tools/callHello","params":{"testUserId": "user-123"}}`
        *Expected:* Success. Logs show identity resolved, roles `['user']`, permission `tool:callHello` derived and granted.
    *   *Sensitive (User):* `{"jsonrpc":"2.0","id":5,"method":"tools/callSensitive","params":{"testUserId": "user-123"}}`
        *Expected:* **Error `-32001`**. Logs show identity resolved, roles `['user']`, permission `tool:callSensitive` derived, but permission check *fails*. Handler not called. Audit shows `denied` with `reason: 'permission'`.
    *   *Sensitive (Admin):* `{"jsonrpc":"2.0","id":6,"method":"tools/callSensitive","params":{"testUserId": "admin-007"}}`
        *Expected:* Success. Logs show identity resolved, roles `['admin']`, permission `tool:callSensitive` derived and granted. Handler runs.
    *   *Hello (No ID):* `{"jsonrpc":"2.0","id":7,"method":"tools/callHello"}`
        *Expected:* **Error `-32001`**. Logs show identity resolved as `null`. RBAC check fails immediately (`reason: 'identity'`) because `enableRbac` is true.
    Stop the server.

---

## Final Code (`src/governed-app.ts` - Identity & RBAC)

After completing Step 2, your `src/governed-app.ts` should look similar to this, providing Identity Resolution and RBAC:

```typescript
// src/governed-app.ts
import { Server as BaseServer } from '@modelcontextprotocol/sdk/server';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio';
import { z } from 'zod';
import process from 'node:process';

// --- Import Governance SDK ---
import {
    GovernedServer,
    GovernedServerOptions,
    ConsoleLogger,
    ConsoleAuditLogStore,
    InMemoryRoleStore,
    InMemoryPermissionStore,
    IdentityResolver,
    RoleStore,
    PermissionStore,
    OperationContext,
    UserIdentity,
    GovernedRequestHandlerExtra,
} from '@ithena-one/mcp-governance';

console.log('Starting Governed MCP Server (Identity & RBAC)...');

// --- 1. Create Base MCP Server ---
const baseServer = new BaseServer(
    { name: "MyGovernedMCPServer-RBAC", version: "1.0.0" },
    { capabilities: { tools: {} } }
);

// --- 2. Governance Components Implementations ---
const logger = new ConsoleLogger({}, 'debug');
const auditStore = new ConsoleAuditLogStore(); // Not for Production

const testIdentityResolver: IdentityResolver = {
    async resolveIdentity(opCtx: OperationContext): Promise<UserIdentity | null> {
        const scopedLogger = opCtx.logger || logger;
        scopedLogger.debug('Entering IdentityResolver', { eventId: opCtx.eventId });
        const paramsObj = opCtx.mcpMessage.params as any; const testIdParam = paramsObj?.testUserId;
        if (testIdParam) { scopedLogger.info(`Identity resolved via param: ${testIdParam}`, { eventId: opCtx.eventId }); return { id: testIdParam, source: 'param' }; }
        const userHeader = opCtx.transportContext.headers?.['x-test-user-id']; const userIdFromHeader = Array.isArray(userHeader) ? userHeader[0] : userHeader;
        if (userIdFromHeader) { scopedLogger.info(`Identity resolved via header: ${userIdFromHeader}`, { eventId: opCtx.eventId }); return { id: userIdFromHeader, source: 'header' }; }
        scopedLogger.info('No test identity found', { eventId: opCtx.eventId }); return null;
    }
};

const testRoleStore: RoleStore = new InMemoryRoleStore({
    'admin-007': ['admin'], 'user-123': ['user'],
});
const testPermissionStore: PermissionStore = new InMemoryPermissionStore({
    'admin': ['tool:callHello', 'tool:callSensitive'],
    'user': ['tool:callHello'],
});

// --- 3. Final GovernedServer Configuration ---
const governedServerOptions: GovernedServerOptions = {
    logger: logger,
    auditStore: auditStore,
    identityResolver: testIdentityResolver,
    roleStore: testRoleStore,
    permissionStore: testPermissionStore,
    enableRbac: true, // RBAC is ON
    auditDeniedRequests: true,
    serviceIdentifier: "governed-app-rbac-instance",
};

// --- 4. Create Final GovernedServer instance ---
// We create the final instance directly here, no need for placeholders anymore
const governedServer = new GovernedServer(baseServer, governedServerOptions);
logger.info('GovernedServer created with Identity & RBAC options');

// --- 5. Define Tool Schemas ---
const helloToolSchema = z.object({ jsonrpc: z.literal("2.0"), id: z.union([z.string(), z.number()]), method: z.literal('tools/callHello'), params: z.object({ arguments: z.object({ greeting: z.string().optional().default('Hello') }).optional().default({ greeting: 'Hello' }), testUserId: z.string().optional(), _meta: z.any().optional() }) });
const sensitiveToolSchema = z.object({ jsonrpc: z.literal("2.0"), id: z.union([z.string(), z.number()]), method: z.literal('tools/callSensitive'), params: z.object({ arguments: z.any().optional(), testUserId: z.string().optional(), _meta: z.any().optional() }) });

// --- 6. Register Handlers ---
governedServer.setRequestHandler(helloToolSchema,
    async (request, extra: GovernedRequestHandlerExtra) => {
        const scopedLogger = extra.logger || logger; const identityId = typeof extra.identity === 'string' ? extra.identity : extra.identity?.id;
        scopedLogger.info(`[Handler] Executing callHello for identity: ${identityId || 'anonymous'} with roles: ${JSON.stringify(extra.roles)}. EventID: ${extra.eventId}`);
        const greeting = request.params?.arguments?.greeting || 'DefaultGreeting'; const responseText = `${greeting} ${identityId || 'World'} from governed server!`;
        return { content: [{ type: 'text', text: responseText }] }; });

governedServer.setRequestHandler(sensitiveToolSchema,
    async (request, extra: GovernedRequestHandlerExtra) => {
        const scopedLogger = extra.logger || logger; const identityId = typeof extra.identity === 'string' ? extra.identity : extra.identity?.id;
        scopedLogger.info(`[Handler] Executing callSensitive for identity: ${identityId}`, { roles: extra.roles });
        return { content: [{ type: 'text', text: `Sensitive data accessed by ${identityId}` }] }; });
logger.info('Handlers registered.');

// --- 7. Connect and Shutdown ---
const transport = new StdioServerTransport();
async function startServer() {
    try { await governedServer.connect(transport); logger.info("Governed MCP server (Identity & RBAC) started on stdio."); logger.info("Ready for requests..."); } catch (error) { logger.error("Failed to start server", error); process.exit(1); } }
const shutdown = async () => { logger.info("Shutting down..."); try { await governedServer.close(); logger.info("Shutdown complete."); process.exit(0); } catch (err) { logger.error("Error during shutdown:", err); process.exit(1); } };
process.on('SIGINT', shutdown); process.on('SIGTERM', shutdown);
startServer();
```

---

## Next Steps & Production Considerations

This tutorial covered the core of Identity and RBAC. The `@ithena-one/mcp-governance` SDK also supports:

*   **Credential Resolution:** Securely injecting secrets into handlers (`CredentialResolver`).
*   **Custom Audit Sanitization:** Preventing sensitive data leaks in logs (`sanitizeForAudit`).
*   **Hooks:** Running custom logic at specific pipeline points (`postAuthorizationHook`).

You can implement these by following similar steps: define the component logic, update `governedServerOptions`, and test.

**IMPORTANT:** This tutorial used simple, **non-production-ready** components. For deployment:

1.  Replace `IdentityResolver`, `RoleStore`, `PermissionStore` with implementations integrated with your actual Auth systems.
2.  Replace `ConsoleAuditLogStore` and `ConsoleLogger` with production-ready logging/auditing solutions.
3.  Implement and **thoroughly test** a custom `sanitizeForAudit` function suitable for your data.
4.  Consider using `CredentialResolver` for secure secret management.
5.  Secure your transport (TLS).

Building robust, secure governance requires careful implementation. If managing these components becomes complex, exploring managed platforms designed for MCP governance might be beneficial. *[Optional Subtle Mention: Keep an eye out for solutions that simplify this process, potentially reducing the need for extensive custom component development.]*

Refer to the full `@ithena-one/mcp-governance` documentation for detailed guides on all features and production best practices.