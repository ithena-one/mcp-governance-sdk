/* eslint-disable no-console */
/* eslint-disable @typescript-eslint/no-unused-vars */
// src/core/goverened-server.integration.test.ts
import { Server as BaseServer } from '@modelcontextprotocol/sdk/server/index.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { GovernedServer, GovernedServerOptions, GovernedRequestHandler } from './governed-server.js';
import { z } from 'zod';
import { JSONRPCRequest } from '@modelcontextprotocol/sdk/types.js';
import { McpError } from '@modelcontextprotocol/sdk/types.js'; // Import McpError
import { Logger } from '../interfaces/logger.js'; // Import Logger type
import { IdentityResolver } from '../interfaces/identity.js'; // Import other needed interfaces
import { AuditLogStore } from '../interfaces/audit.js';
import { RoleStore } from '../interfaces/rbac.js';
import { PermissionStore } from '../interfaces/rbac.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

// Type Helper for Mocks
type MockedInterface<T> = {
  [K in keyof T]: T[K] extends (...args: infer Args) => infer R
    ? jest.MockedFunction<(...args: Args) => R>
    : T[K];
};


describe('GovernedServer Integration Tests', () => {
    let client: Client;
    let governedServer: GovernedServer;
    let baseServer: BaseServer;
    let clientTransport: InMemoryTransport;
    let serverTransport: InMemoryTransport;
    let options: GovernedServerOptions;

    // --- Mocks ---
    // Explicitly type mockLogger first
    let mockLogger: MockedInterface<Logger>;
    let mockIdentityResolver: MockedInterface<IdentityResolver>;
    let mockAuditStore: MockedInterface<AuditLogStore>;
    let mockRoleStore: MockedInterface<RoleStore>;
    let mockPermissionStore: MockedInterface<PermissionStore>;


    // Define a simple request schema/handler for testing
    const testReqSchema = z.object({
        method: z.literal('test/hello'),
        params: z.object({ name: z.string() }).optional(),
        id: z.any(),
        jsonrpc: z.string().refine(val => val === '2.0', { message: 'jsonrpc must be "2.0"' }).optional()
    }).passthrough();
    const testHandler = jest.fn().mockImplementation(
        (async (req, extra) => ({ greeting: `Hello ${req.params?.name ?? 'anonymous'} from ${extra.identity}` })) as GovernedRequestHandler<typeof testReqSchema>
    );

    beforeEach(async () => {
        jest.clearAllMocks();
        [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

        // Define mocks inside beforeEach to ensure they are fresh
        mockLogger = {
             debug: jest.fn(), info: jest.fn(), warn: jest.fn(), error: jest.fn(),
             // Define child AFTER mockLogger is declared but before assignment
             child: jest.fn(() => mockLogger)
         };
        mockIdentityResolver = { resolveIdentity: jest.fn().mockResolvedValue('test-user') };
        mockAuditStore = { log: jest.fn().mockResolvedValue(undefined), initialize: jest.fn(), shutdown: jest.fn() }; // Add lifecycle mocks
        mockRoleStore = { getRoles: jest.fn().mockResolvedValue([]) }; // Add lifecycle mocks if needed
        mockPermissionStore = { hasPermission: jest.fn().mockResolvedValue(true) }; // Add lifecycle mocks if needed


        options = {
            logger: mockLogger,
            auditStore: mockAuditStore,
            identityResolver: mockIdentityResolver,
            // Add other mocked components (RBAC, Creds) and options as needed per test
        };

        // Create REAL base server, not mocked
        baseServer = new BaseServer({ name: 'BaseTestServer', version: '1.0' });
        governedServer = new GovernedServer(baseServer, options);
        governedServer.setRequestHandler(testReqSchema, testHandler); // Register handler on GovernedServer

        client = new Client({ name: 'TestClient', version: '1.0' });

        // Connect both ends
        await Promise.all([
            governedServer.connect(serverTransport),
            client.connect(clientTransport)
        ]);

        // Clear mocks called during connect/initialize AFTER connection
        testHandler.mockClear();
        mockIdentityResolver.resolveIdentity.mockClear();
        mockAuditStore.log.mockClear();
        mockLogger.debug.mockClear();
        mockLogger.info.mockClear();
        mockLogger.warn.mockClear();
        mockLogger.error.mockClear();

    });

    afterEach(async () => {
        // Ensure cleanup
        // Close client first to stop sending messages
        await client?.close();
        // Then close server
        await governedServer?.close();
        // Reset transports if needed, though createLinkedPair does this
    });

    it('should process request through governance pipeline and execute handler', async () => {
        const request = { method: 'test/hello', jsonrpc: '2.0' };
        mockLogger.debug.mockImplementation(console.log); // Temporarily log to console
        const result = await client.request(request, z.object({ greeting: z.string() })); // Use client to send request
        mockLogger.debug.mockRestore(); // Restore the mock

        expect(result.greeting).toBe('Hello anonymous from test-user');
        expect(mockIdentityResolver.resolveIdentity).toHaveBeenCalledTimes(1);
        expect(testHandler).toHaveBeenCalledTimes(1);
        // Check context passed to handler (simplified)
        expect(testHandler).toHaveBeenCalledWith(
            expect.objectContaining({ method: 'test/hello' }),
            expect.objectContaining({ identity: 'test-user' })
        );
        expect(mockAuditStore.log).toHaveBeenCalledTimes(1);
        const auditCall = mockAuditStore.log.mock.calls[0][0];
        expect(auditCall.outcome.status).toBe('success');
        expect(auditCall.identity).toBe('test-user');
    });

    // Add more tests for RBAC denial, credential resolution, errors etc.
    // by modifying the mocked governance components in `options` for each test.
    // Example: RBAC denial
    it('should deny request if RBAC fails', async () => {
        // --- Arrange ---
        // Close existing connections first to apply new options
        await client.close();
        await governedServer.close();

        // Configure new options with RBAC enabled and denying permission
        mockIdentityResolver.resolveIdentity.mockResolvedValue('test-user'); // Ensure identity resolves
        mockRoleStore.getRoles.mockResolvedValue(['viewer']);
        mockPermissionStore.hasPermission.mockResolvedValue(false); // DENY

        options.enableRbac = true;
        options.roleStore = mockRoleStore;
        options.permissionStore = mockPermissionStore;
        options.derivePermission = () => 'test:hello'; // Permission needed

        // Recreate server and client with new options
        baseServer = new BaseServer({ name: 'RBAC_Base', version: '1.0' });
        governedServer = new GovernedServer(baseServer, options);
        governedServer.setRequestHandler(testReqSchema, testHandler);
        client = new Client({ name: 'RBAC_Client', version: '1.0' });
        [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair(); // New pair needed
        await Promise.all([
            governedServer.connect(serverTransport),
            client.connect(clientTransport)
        ]);
        // Clear mocks again after reconnect
        jest.clearAllMocks();
        testHandler.mockClear();
        mockIdentityResolver.resolveIdentity.mockClear();
        mockRoleStore.getRoles.mockClear();
        mockPermissionStore.hasPermission.mockClear();
        mockAuditStore.log.mockClear();

        // --- Act ---
        const request = { method: 'test/hello', jsonrpc: '2.0' };

        // --- Assert ---
        await expect(client.request(request, z.any())) // Expect rejection
             .rejects.toThrow(McpError); // Base client throws McpError on receiving JSONRPC error

        // Check which mocks were called
        expect(mockIdentityResolver.resolveIdentity).toHaveBeenCalledTimes(1); // Called by pipeline
        expect(mockRoleStore.getRoles).toHaveBeenCalledTimes(1); // Called by pipeline
        expect(mockPermissionStore.hasPermission).toHaveBeenCalledTimes(1); // Called by pipeline
        expect(testHandler).not.toHaveBeenCalled(); // Handler should NOT be called
        expect(mockAuditStore.log).toHaveBeenCalledTimes(1); // Audit should still run
        const auditCall = mockAuditStore.log.mock.calls[0][0];
        expect(auditCall.outcome.status).toBe('denied');
        expect(auditCall.authorization?.decision).toBe('denied');
        expect(auditCall.authorization?.denialReason).toBe('permission');
    });

    // Add tests for credential resolver, errors, etc. following similar pattern:
    // - Close existing client/server
    // - Configure options with specific mock behaviors
    // - Recreate client/server with new options
    // - Reconnect transports
    // - Clear mocks
    // - Act (send request via client)
    // - Assert (check client result/error, check mock calls)

});