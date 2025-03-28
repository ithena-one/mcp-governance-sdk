// src/core/governance-pipeline.test.ts
/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { jest } from '@jest/globals';

import { GovernancePipeline } from '../core/governance-pipeline.js';
import { GovernedServerOptions } from '../core/governed-server.js';

// Mock interfaces
import { IdentityResolver } from '../interfaces/identity.js';
import { RoleStore, PermissionStore } from '../interfaces/rbac.js';
import { CredentialResolver } from '../interfaces/credentials.js';
import { AuditLogStore } from '../interfaces/audit.js';
import { Logger } from '../interfaces/logger.js';
import { TraceContextProvider } from '../interfaces/tracing.js';

// Types
import { OperationContext, AuditRecord, ResolvedCredentials, UserIdentity, TransportContext, GovernedNotificationHandlerExtra } from '../types.js';
import { JSONRPCRequest, McpError, ErrorCode as McpErrorCode, Request, JSONRPCNotification } from '@modelcontextprotocol/sdk/types.js';
import { RequestHandlerExtra as BaseRequestHandlerExtra } from '@modelcontextprotocol/sdk/shared/protocol.js';
import { AuthenticationError, AuthorizationError, CredentialResolutionError } from '../errors/index.js';
import { z } from 'zod';

// Define proper types for the mock functions
type DerivePermissionFn = (request: Request, transportContext: TransportContext) => string | null;
type SanitizeForAuditFn = (record: Partial<AuditRecord>) => Partial<AuditRecord>;
type PostAuthHookFn = (identity: UserIdentity, opCtx: OperationContext) => Promise<void>;
type TestHandlerResult = { success: boolean };

// --- Mock Implementations ---
const mockLogger: jest.Mocked<Logger> = {
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    child: jest.fn(() => mockLogger), // Return itself for simplified testing
};

const mockIdentityResolver: jest.Mocked<IdentityResolver> = {
    resolveIdentity: jest.fn(),
};

const mockRoleStore: jest.Mocked<RoleStore> = {
    getRoles: jest.fn(),
};

const mockPermissionStore: jest.Mocked<PermissionStore> = {
    hasPermission: jest.fn(),
};

const mockCredentialResolver: jest.Mocked<CredentialResolver> = {
    resolveCredentials: jest.fn(),
};

const mockAuditStore: jest.Mocked<AuditLogStore> = {
    log: jest.fn(),
    // Mock initialize/shutdown if needed for specific lifecycle tests elsewhere
};

const mockTraceContextProvider: jest.Mocked<TraceContextProvider> = jest.fn();

// Mock functions with type assertions
const mockDerivePermission = jest.fn() as jest.MockedFunction<DerivePermissionFn>;
const mockSanitizeForAudit = jest.fn(((record) => record) as SanitizeForAuditFn); // Default pass-through
const mockPostAuthHook = jest.fn() as jest.MockedFunction<PostAuthHookFn>;

// --- Mock Request Handler ---
const mockRequestHandler = jest.fn() as jest.MockedFunction<(req: any, extra: any) => Promise<TestHandlerResult>>;
const testMethod = 'test/method';
const TestRequestSchema = z.object({
    jsonrpc: z.literal('2.0'),
    id: z.union([z.string(), z.number()]),
    method: z.literal(testMethod),
    params: z.object({ data: z.string() }).optional(),
    _meta: z.any().optional(), // Allow _meta
}).strict(); // Use strict for better validation testing
type TestRequest = z.infer<typeof TestRequestSchema>;

const mockRequestHandlers = new Map<string, { handler: jest.Mocked<any>, schema: typeof TestRequestSchema }>();
mockRequestHandlers.set(testMethod, { handler: mockRequestHandler, schema: TestRequestSchema });

// --- Mock Notification Handler ---
const mockNotificationHandler = jest.fn() as jest.MockedFunction<(notif: any, extra: GovernedNotificationHandlerExtra) => Promise<void>>;
const testNotificationMethod = 'test/notification';
const TestNotificationSchema = z.object({
     jsonrpc: z.literal('2.0'),
     method: z.literal(testNotificationMethod),
     params: z.object({ info: z.string() }).optional(),
     _meta: z.any().optional(),
 }).strict();
type TestNotification = z.infer<typeof TestNotificationSchema>;

const mockNotificationHandlers = new Map<string, { handler: jest.Mocked<any>, schema: typeof TestNotificationSchema }>();
mockNotificationHandlers.set(testNotificationMethod, { handler: mockNotificationHandler, schema: TestNotificationSchema });


// --- Test Suite ---

describe('GovernancePipeline', () => {
    let pipeline: GovernancePipeline;
    let mockOptions: GovernedServerOptions; // Use mutable options for tests

    // Default mock inputs
    let mockRequest: JSONRPCRequest;
    let mockNotification: JSONRPCNotification;
    let mockBaseExtra: BaseRequestHandlerExtra;
    let mockOperationContext: OperationContext; // Base for request/notification contexts
    let mockAuditRecord: Partial<AuditRecord>; // Base for request/notification audit records

    beforeEach(() => {
        // Reset all mocks
        jest.clearAllMocks();

        // Setup default options for pipeline
        mockOptions = {
            identityResolver: mockIdentityResolver,
            roleStore: mockRoleStore,
            permissionStore: mockPermissionStore,
            auditStore: mockAuditStore,
            logger: mockLogger,
            traceContextProvider: mockTraceContextProvider,
            enableRbac: false, // Default to RBAC disabled
            failOnCredentialResolutionError: true,
            auditDeniedRequests: true,
            auditNotifications: false, // Default to false
            derivePermission: mockDerivePermission,
            sanitizeForAudit: mockSanitizeForAudit,
            postAuthorizationHook: mockPostAuthHook,
            serviceIdentifier: 'test-service',
            // credentialResolver intentionally left undefined by default
        };

        // Default return values for mocks (can be overridden in tests)
        mockIdentityResolver.resolveIdentity.mockResolvedValue(null); // Default anonymous
        mockRoleStore.getRoles.mockResolvedValue([]);
        mockPermissionStore.hasPermission.mockResolvedValue(false);
        mockDerivePermission.mockReturnValue(null); // Default no permission needed
        mockCredentialResolver.resolveCredentials.mockResolvedValue(undefined); // Default no creds
        mockRequestHandler.mockResolvedValue({ success: true }); // Default handler success
        mockNotificationHandler.mockResolvedValue(undefined); // Default notification handler success
        mockAuditStore.log.mockResolvedValue(undefined);
        mockTraceContextProvider.mockReturnValue(undefined);
        mockPostAuthHook.mockResolvedValue(undefined);
        mockSanitizeForAudit.mockImplementation((record) => record); // Pass-through sanitizer

        // Setup default inputs
        mockRequest = {
            jsonrpc: '2.0',
            id: 1,
            method: testMethod,
            params: { data: 'test-data' },
        };
        mockNotification = {
            jsonrpc: '2.0',
            method: testNotificationMethod,
            params: { info: 'some info' },
        };
        // Use a fresh signal for each baseExtra potentially
        mockBaseExtra = {
            signal: new AbortController().signal,
            sessionId: 'session-123',
        };
        // Base context - will be slightly adapted for request/notification
        mockOperationContext = {
            eventId: 'event-abc',
            timestamp: new Date(),
            transportContext: { transportType: 'test', sessionId: 'session-123', headers: {} },
            logger: mockLogger,
            mcpMessage: mockRequest, // Placeholder, set per test type
            serviceIdentifier: mockOptions.serviceIdentifier,
        };
        // Base audit record - will be slightly adapted
        mockAuditRecord = {
            eventId: mockOperationContext.eventId,
            timestamp: mockOperationContext.timestamp.toISOString(),
            serviceIdentifier: mockOptions.serviceIdentifier,
            transport: mockOperationContext.transportContext,
            // mcp section set per test type
        };

        // Instantiate the pipeline for each test
        pipeline = new GovernancePipeline(
            mockOptions,
            mockRequestHandlers as any, // Cast needed due to Jest mock type vs internal type
            mockNotificationHandlers as any
        );
    });

    // --- Test Cases for executeRequestPipeline ---
    describe('executeRequestPipeline', () => {

        beforeEach(() => {
            // Customize context/audit for requests
            Object.assign(mockOperationContext, { mcpMessage: mockRequest });
            mockAuditRecord.mcp = { type: "request", method: mockRequest.method, id: mockRequest.id };
        });

        it('should run happy path with no RBAC, no Creds, handler success', async () => {
            // Arrange: Default setup is sufficient

            // Act
            const result = await pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);

            // Assert
            expect(result).toEqual({ success: true });
            expect(mockIdentityResolver.resolveIdentity).toHaveBeenCalledTimes(1);
            expect(mockRoleStore.getRoles).not.toHaveBeenCalled();
            expect(mockPermissionStore.hasPermission).not.toHaveBeenCalled();
            expect(mockCredentialResolver.resolveCredentials).not.toHaveBeenCalled(); // Not configured
            expect(mockRequestHandler).toHaveBeenCalledTimes(1);
            expect(mockRequestHandler).toHaveBeenCalledWith(
                expect.objectContaining(mockRequest), // Pipeline validates schema
                expect.objectContaining({ // Verify extra object content
                    eventId: mockOperationContext.eventId,
                    identity: null,
                    resolvedCredentials: undefined,
                    logger: mockLogger,
                    sessionId: mockBaseExtra.sessionId,
                    signal: mockBaseExtra.signal, // Ensure signal is passed from baseExtra
                })
            );
            expect(mockAuditStore.log).toHaveBeenCalledTimes(1);
            const auditCall = mockAuditStore.log.mock.calls[0][0] as AuditRecord;
            expect(auditCall.outcome.status).toBe('success');
            expect(auditCall.outcome.mcpResponse?.result).toEqual({ success: true });
            expect(auditCall.identity).toBeNull();
        });

        it('should resolve identity if resolver is configured', async () => {
            // Arrange
            const mockUserId = 'user-abc';
            mockIdentityResolver.resolveIdentity.mockResolvedValue(mockUserId);
            mockOptions.identityResolver = mockIdentityResolver;

            // Act
            await pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);

            // Assert
            expect(mockIdentityResolver.resolveIdentity).toHaveBeenCalledWith(mockOperationContext);
            expect(mockRequestHandler).toHaveBeenCalledWith(
                expect.anything(),
                expect.objectContaining({ identity: mockUserId })
            );
            expect(mockAuditStore.log).toHaveBeenCalledWith(expect.objectContaining({ identity: mockUserId }));
        });

        it('should fail request if identity resolution fails', async () => {
            // Arrange
            const authError = new AuthenticationError('Invalid Token');
            mockIdentityResolver.resolveIdentity.mockRejectedValue(authError);
            mockOptions.identityResolver = mockIdentityResolver;

            // Act & Assert
            await expect(pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord))
                .rejects.toThrow(McpError); // Pipeline maps to McpError

            try {
                // Re-run to inspect the error easily
                await pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);
            } catch (e: any) {
                 expect(e).toBeInstanceOf(McpError);
                 // Internal error mapping should map AuthenticationError to InvalidRequest
                expect(e.code).toEqual(McpErrorCode.InvalidRequest);
                expect(e.message).toBe('MCP error -32600: Invalid Token'); // Updated to match actual message
                // The error type should be available in the mapped error's data
                expect(e.data?.type).toBe('AuthenticationError');
            }

            expect(mockRequestHandler).not.toHaveBeenCalled();
            expect(mockAuditStore.log).toHaveBeenCalledTimes(1);
            const auditCall = mockAuditStore.log.mock.calls[0][0] as AuditRecord;
            expect(auditCall.outcome.status).toBe('failure');
            // Audit log contains the mapped MCP error details
            expect(auditCall.outcome.error?.type).toBe('McpError');
            expect(auditCall.outcome.error?.message).toBe('MCP error -32600: Invalid Token');
            expect(auditCall.outcome.error?.code).toBe(McpErrorCode.InvalidRequest);
        });

        // --- RBAC Tests ---
        describe('when RBAC is enabled', () => {
            const testPermission = 'tool:call:test/method';

            beforeEach(() => {
                mockOptions.enableRbac = true;
                mockOptions.identityResolver = mockIdentityResolver; // Ensure needed components are present
                mockOptions.roleStore = mockRoleStore;
                mockOptions.permissionStore = mockPermissionStore;
                mockDerivePermission.mockReturnValue(testPermission); // Default to needing permission
            });

            it('should fail if identity is not resolved', async () => {
                // Arrange: mockIdentityResolver already defaults to returning null
                await expect(pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord))
                    .rejects.toThrow(McpError);
                try {
                    await pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);
                } catch (e: any) {
                    expect(e.code).toEqual(-32001); // Custom AuthZ code
                    expect(e.data?.type).toBe('AuthorizationError');
                    expect(e.data?.reason).toBe('identity');
                }
                expect(mockAuditStore.log).toHaveBeenCalledTimes(1);
                const auditCall = mockAuditStore.log.mock.calls[0][0] as AuditRecord;
                expect(auditCall.outcome.status).toBe('denied');
                expect(auditCall.authorization?.decision).toBe('denied');
                expect(auditCall.authorization?.denialReason).toBe('identity');
            });

            it('should fail if user has no roles granting permission', async () => {
                 // Arrange
                 mockIdentityResolver.resolveIdentity.mockResolvedValue('user-noroles');
                 mockRoleStore.getRoles.mockResolvedValue(['viewer']);
                 mockPermissionStore.hasPermission.mockResolvedValue(false);
                 await expect(pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord))
                     .rejects.toThrow(McpError);
                 try {
                    await pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);
                 } catch(e: any) {
                     expect(e.code).toEqual(-32001);
                     expect(e.data?.type).toBe('AuthorizationError');
                     expect(e.data?.reason).toBe('permission');
                     expect(e.message).toContain(testPermission);
                 }
                 expect(mockAuditStore.log).toHaveBeenCalledTimes(1);
                 const auditCall = mockAuditStore.log.mock.calls[0][0] as AuditRecord;
                 expect(auditCall.outcome.status).toBe('denied');
                 expect(auditCall.authorization?.decision).toBe('denied');
                 expect(auditCall.authorization?.denialReason).toBe('permission');
                 expect(auditCall.authorization?.roles).toEqual(['viewer']);
             });

            it('should succeed if user has a role granting permission', async () => {
                 const userId = 'user-admin';
                 const roles = ['viewer', 'admin'];
                 mockIdentityResolver.resolveIdentity.mockResolvedValue(userId);
                 mockRoleStore.getRoles.mockResolvedValue(roles);
                 mockPermissionStore.hasPermission.mockImplementation(async (role, perm) => role === 'admin' && perm === testPermission);

                 const result = await pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);

                 expect(result).toEqual({ success: true });
                 expect(mockPermissionStore.hasPermission).toHaveBeenCalledWith('viewer', testPermission, mockOperationContext);
                 expect(mockPermissionStore.hasPermission).toHaveBeenCalledWith('admin', testPermission, mockOperationContext);
                 expect(mockRequestHandler).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ identity: userId, roles }));
                 expect(mockAuditStore.log).toHaveBeenCalledWith(expect.objectContaining({
                     authorization: expect.objectContaining({ decision: 'granted', roles })
                 }));
             });

             it('should skip permission check if derivePermission returns null', async () => {
                 mockIdentityResolver.resolveIdentity.mockResolvedValue('user-any');
                 mockDerivePermission.mockReturnValue(null);

                 await pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);

                 expect(mockRoleStore.getRoles).not.toHaveBeenCalled();
                 expect(mockPermissionStore.hasPermission).not.toHaveBeenCalled();
                 expect(mockRequestHandler).toHaveBeenCalledTimes(1);
                 expect(mockAuditStore.log).toHaveBeenCalledWith(expect.objectContaining({
                     authorization: expect.objectContaining({ decision: 'granted', permissionAttempted: null })
                 }));
             });

             it('should skip audit log for denied request if auditDeniedRequests is false', async () => {
                 mockOptions.auditDeniedRequests = false;
                 mockIdentityResolver.resolveIdentity.mockResolvedValue('user-noroles');
                 mockRoleStore.getRoles.mockResolvedValue(['viewer']);
                 mockPermissionStore.hasPermission.mockResolvedValue(false);

                 await expect(pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord))
                     .rejects.toThrow(McpError);
                 expect(mockAuditStore.log).not.toHaveBeenCalled();
             });

            it('should fail if user has no roles (identity resolved but no roles)', async () => {
                // Arrange
                mockIdentityResolver.resolveIdentity.mockResolvedValue('user-noroles');
                mockRoleStore.getRoles.mockResolvedValue([]); // Empty roles array

                // Act & Assert
                const promise = pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);
                await expect(promise).rejects.toThrow(McpError);
                
                try {
                    await promise;
                } catch (e: any) {
                    expect(e.code).toEqual(-32001); // AuthZ error code
                    expect(e.data?.type).toBe('AuthorizationError');
                    expect(e.data?.reason).toBe('permission');
                }

                expect(mockIdentityResolver.resolveIdentity).toHaveBeenCalledTimes(1);
                expect(mockRoleStore.getRoles).toHaveBeenCalledTimes(1);
                expect(mockPermissionStore.hasPermission).not.toHaveBeenCalled(); // Should not check permissions if no roles
                expect(mockRequestHandler).not.toHaveBeenCalled();
                expect(mockAuditStore.log).toHaveBeenCalledWith(expect.objectContaining({
                    authorization: expect.objectContaining({
                        decision: 'denied',
                        denialReason: 'permission',
                        roles: [] // Empty roles array should be recorded
                    })
                }));
            });

            it('should fail with identity reason if identityResolver returns null with RBAC enabled', async () => {
                // Arrange
                mockIdentityResolver.resolveIdentity.mockResolvedValue(null);

                // Act & Assert
                const promise = pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);
                await expect(promise).rejects.toThrow(McpError);

                try {
                    await promise;
                } catch (e: any) {
                    expect(e.code).toEqual(-32001);
                    expect(e.data?.type).toBe('AuthorizationError');
                    expect(e.data?.reason).toBe('identity');
                }

                expect(mockIdentityResolver.resolveIdentity).toHaveBeenCalledTimes(1);
                expect(mockRoleStore.getRoles).not.toHaveBeenCalled(); // Should not call roleStore if no identity
                expect(mockPermissionStore.hasPermission).not.toHaveBeenCalled();
                expect(mockRequestHandler).not.toHaveBeenCalled();
                expect(mockAuditStore.log).toHaveBeenCalledWith(expect.objectContaining({
                    authorization: expect.objectContaining({
                        decision: 'denied',
                        denialReason: 'identity'
                    })
                }));
            });

            it('should stop checking permissions after first role grants access', async () => {
                // Arrange
                const userId = 'user-multirole';
                const roles = ['viewer', 'editor', 'admin'];
                mockIdentityResolver.resolveIdentity.mockResolvedValue(userId);
                mockRoleStore.getRoles.mockResolvedValue(roles);
                mockPermissionStore.hasPermission
                    .mockImplementation(async (role) => {
                        // Only editor role grants permission
                        return role === 'editor';
                    });

                // Act
                const result = await pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);

                // Assert
                expect(result).toEqual({ success: true });
                expect(mockIdentityResolver.resolveIdentity).toHaveBeenCalledTimes(1);
                expect(mockRoleStore.getRoles).toHaveBeenCalledTimes(1);
                
                // Should have checked viewer (false) and editor (true), but not admin
                expect(mockPermissionStore.hasPermission).toHaveBeenCalledTimes(2);
                expect(mockPermissionStore.hasPermission).toHaveBeenNthCalledWith(1, 'viewer', testPermission, expect.anything());
                expect(mockPermissionStore.hasPermission).toHaveBeenNthCalledWith(2, 'editor', testPermission, expect.anything());
                
                expect(mockRequestHandler).toHaveBeenCalledWith(
                    expect.anything(),
                    expect.objectContaining({
                        identity: userId,
                        roles: roles
                    })
                );
                expect(mockAuditStore.log).toHaveBeenCalledWith(expect.objectContaining({
                    authorization: expect.objectContaining({
                        decision: 'granted',
                        roles: roles
                    })
                }));
            });

        }); // End RBAC describe

        // --- Post-Authorization Hook ---
        describe('Post-Authorization Hook', () => {
            const userId = 'user-hook';
            beforeEach(() => {
                mockOptions.identityResolver = mockIdentityResolver;
                mockIdentityResolver.resolveIdentity.mockResolvedValue(userId);
                mockOptions.postAuthorizationHook = mockPostAuthHook;
                mockOptions.enableRbac = false; // Default to RBAC disabled
            });

            it('should call post-auth hook after successful identity resolution when RBAC is off', async () => {
                await pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);
                expect(mockPostAuthHook).toHaveBeenCalledWith(userId, mockOperationContext);
                expect(mockRequestHandler).toHaveBeenCalled();
                expect(mockAuditStore.log).toHaveBeenCalledWith(expect.objectContaining({
                    outcome: expect.objectContaining({ status: 'success' })
                }));
            });

            it('should call post-auth hook after successful RBAC check', async () => {
                // Arrange
                mockOptions.enableRbac = true;
                mockOptions.roleStore = mockRoleStore;
                mockOptions.permissionStore = mockPermissionStore;
                const roles = ['admin'];
                mockRoleStore.getRoles.mockResolvedValue(roles);
                mockPermissionStore.hasPermission.mockResolvedValue(true);
                mockDerivePermission.mockReturnValue('test:permission');

                // Act
                await pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);

                // Assert
                expect(mockPostAuthHook).toHaveBeenCalledWith(userId, expect.objectContaining({
                    roles: roles
                }));
                expect(mockRequestHandler).toHaveBeenCalled();
                expect(mockAuditStore.log).toHaveBeenCalledWith(expect.objectContaining({
                    authorization: expect.objectContaining({
                        decision: 'granted'
                    })
                }));
            });

            it('should call post-auth hook when RBAC is enabled but no permission is required', async () => {
                // Arrange
                mockOptions.enableRbac = true;
                mockOptions.roleStore = mockRoleStore;
                mockOptions.permissionStore = mockPermissionStore;
                mockDerivePermission.mockReturnValue(null); // No permission required

                // Act
                await pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);

                // Assert
                expect(mockPostAuthHook).toHaveBeenCalledWith(userId, mockOperationContext);
                expect(mockRoleStore.getRoles).not.toHaveBeenCalled(); // No roles needed
                expect(mockPermissionStore.hasPermission).not.toHaveBeenCalled();
                expect(mockRequestHandler).toHaveBeenCalled();
            });

            it('should not call post-auth hook if identity resolution fails', async () => {
                // Arrange
                const authError = new AuthenticationError('Invalid token');
                mockIdentityResolver.resolveIdentity.mockRejectedValue(authError);

                // Act & Assert
                await expect(pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord))
                    .rejects.toThrow(McpError);

                expect(mockPostAuthHook).not.toHaveBeenCalled();
                expect(mockRequestHandler).not.toHaveBeenCalled();
                expect(mockAuditStore.log).toHaveBeenCalledWith(expect.objectContaining({
                    outcome: expect.objectContaining({ 
                        status: 'failure',
                        error: expect.objectContaining({ type: 'McpError' })
                    })
                }));
            });

            it('should not call post-auth hook if RBAC denies access', async () => {
                // Arrange
                mockOptions.enableRbac = true;
                mockOptions.roleStore = mockRoleStore;
                mockOptions.permissionStore = mockPermissionStore;
                mockRoleStore.getRoles.mockResolvedValue(['viewer']);
                mockPermissionStore.hasPermission.mockResolvedValue(false);
                mockDerivePermission.mockReturnValue('test:permission');

                // Act & Assert
                await expect(pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord))
                    .rejects.toThrow(McpError);

                expect(mockPostAuthHook).not.toHaveBeenCalled();
                expect(mockRequestHandler).not.toHaveBeenCalled();
                expect(mockAuditStore.log).toHaveBeenCalledWith(expect.objectContaining({
                    authorization: expect.objectContaining({
                        decision: 'denied',
                        denialReason: 'permission'
                    })
                }));
            });

            it('should fail pipeline if post-auth hook rejects', async () => {
                // Arrange
                const hookError = new Error("Hook failed");
                mockPostAuthHook.mockRejectedValue(hookError);

                // Act & Assert
                const promise = pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);
                await expect(promise).rejects.toThrow(McpError);

                try {
                    await promise;
                } catch (e: any) {
                    expect(e.message).toContain("Post-authorization hook failed");
                    expect(e.code).toEqual(McpErrorCode.InternalError);
                    expect(e.data?.type).toBe('GovernanceError');
                }

                expect(mockRequestHandler).not.toHaveBeenCalled();
                expect(mockAuditStore.log).toHaveBeenCalledWith(expect.objectContaining({
                    outcome: expect.objectContaining({ 
                        status: 'failure',
                        error: expect.objectContaining({ 
                            type: 'McpError',
                            message: expect.stringContaining('Post-authorization hook failed')
                        })
                    })
                }));
            });

            it('should include resolved credentials in operation context passed to hook', async () => {
                // Arrange
                const mockCreds = { apiKey: 'test-key' };
                mockOptions.credentialResolver = mockCredentialResolver;
                mockCredentialResolver.resolveCredentials.mockResolvedValue(mockCreds);

                // Act
                await pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);

                // Assert
                expect(mockPostAuthHook).toHaveBeenCalledWith(
                    userId,
                    expect.objectContaining({
                        resolvedCredentials: mockCreds
                    })
                );
            });
        });

        // --- Credential Resolution Tests ---
        // Note: No changes needed here based on suggestions, tests look correct.
        describe('Credential Resolution', () => {
            const mockCreds: ResolvedCredentials = { apiKey: 'abc' };
             beforeEach(() => {
                 mockOptions.identityResolver = mockIdentityResolver;
                 mockIdentityResolver.resolveIdentity.mockResolvedValue('user-creds');
                 mockOptions.credentialResolver = mockCredentialResolver;
             });
             // ... credential tests from before ...

             it('should fail pipeline if resolution fails and failOnCredentialResolutionError=true', async () => {
                const credError = new CredentialResolutionError('Vault fetch failed');
                mockCredentialResolver.resolveCredentials.mockRejectedValue(credError);
                mockOptions.failOnCredentialResolutionError = true;

                await expect(pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord))
                    .rejects.toThrow(McpError);
                 try {
                     await pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);
                 } catch(e: any) {
                     expect(e.message).toBe('MCP error -32603: Vault fetch failed'); // Updated to match actual message
                     expect(e.code).toEqual(McpErrorCode.InternalError);
                     expect(e.data?.type).toBe('CredentialResolutionError');
                 }
                expect(mockAuditStore.log).toHaveBeenCalledWith(expect.objectContaining({
                    credentialResolution: expect.objectContaining({ status: 'failure', error: expect.anything() })
                }));
             });
        });

        // --- Handler Execution and Error Handling ---
        // Note: No changes needed here based on suggestions, tests look correct.
        it('should fail pipeline if handler throws an error', async () => {
            const handlerError = new Error('Handler logic failed');
            mockRequestHandler.mockRejectedValue(handlerError);

            await expect(pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord))
                .rejects.toThrow(McpError);
            try {
                 await pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);
            } catch (e: any) {
                 expect(e.message).toBe('MCP error -32603: Handler execution failed'); // Updated to match actual message
                 expect(e.code).toEqual(McpErrorCode.InternalError);
                 expect(e.data?.type).toBe('HandlerError'); // Wrapped error type
            }
            expect(mockAuditStore.log).toHaveBeenCalledWith(expect.objectContaining({
                 outcome: expect.objectContaining({ status: 'failure', error: expect.objectContaining({ type: 'McpError', message: expect.stringContaining('Handler execution failed') }) }) // Error mapped for client
            }));
         });

        // --- Corrected Schema Validation Test ---
        it('should fail pipeline if request schema validation fails', async () => {
             // Arrange
             const invalidRequest = { ...mockRequest, params: { wrong: 123 } }; // Invalid params
             const zodError = new z.ZodError([{ // Simulate a ZodError structure
                 code: z.ZodIssueCode.invalid_type,
                 expected: 'string',
                 received: 'number',
                 path: ['params', 'data'],
                 message: 'Expected string, received number'
             }]);
             // Correctly spy on the *specific schema instance* used for this method
             const handlerInfo = mockRequestHandlers.get(testMethod);
             if (!handlerInfo) throw new Error('Test setup error: handler info not found');
             const safeParseSpy = jest.spyOn(handlerInfo.schema, 'safeParse')
                                     .mockReturnValue({ success: false, error: zodError });
             // Update context/audit record for the invalid request being tested
             Object.assign(mockOperationContext, { mcpMessage: invalidRequest });
             Object.assign(mockAuditRecord, { mcp: { type: 'request', method: invalidRequest.method, id: invalidRequest.id } });

             // Act & Assert
             await expect(pipeline.executeRequestPipeline(invalidRequest, mockBaseExtra, mockOperationContext, mockAuditRecord))
                 .rejects.toThrow(McpError);

             try {
                 await pipeline.executeRequestPipeline(invalidRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);
             } catch(e: any) {
                 expect(e.code).toEqual(McpErrorCode.InvalidParams);
                 expect(e.message).toBe(`MCP error -32602: Invalid request structure: ${zodError.message}`); // Updated to match actual format
             }

             expect(mockRequestHandler).not.toHaveBeenCalled();
             expect(mockAuditStore.log).toHaveBeenCalledTimes(1);
             const auditCall = mockAuditStore.log.mock.calls[0][0] as AuditRecord;
             expect(auditCall.outcome.status).toBe('failure');
             expect(auditCall.outcome.error?.type).toBe('McpError');

             safeParseSpy.mockRestore(); // Clean up spy
         });


        // ... method not found test ...

        // --- Auditing Specifics ---
        it('should call sanitizeForAudit before logging', async () => {
             mockOptions.sanitizeForAudit = mockSanitizeForAudit;
             const sanitizedRecord = { sanitized: true }; // Known value
             mockSanitizeForAudit.mockReturnValue(sanitizedRecord);

             await pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);

             // Check sanitize was called with the *final* record before log call
             expect(mockSanitizeForAudit).toHaveBeenCalledTimes(1);
             const recordPassedToSanitize = mockSanitizeForAudit.mock.calls[0][0];
             expect(recordPassedToSanitize).toMatchObject({
                eventId: mockOperationContext.eventId,
                outcome: expect.objectContaining({ status: 'success' }) // Ensure outcome is present
             })
             expect(mockAuditStore.log).toHaveBeenCalledWith(sanitizedRecord);
         });

        // ... audit failure tests from before ...

    }); // End executeRequestPipeline describe


    // --- Test Cases for executeNotificationPipeline ---
    describe('executeNotificationPipeline', () => {

        beforeEach(() => {
            // Customize context/audit for notifications
            Object.assign(mockOperationContext, { mcpMessage: mockNotification });
            mockAuditRecord.mcp = { type: "notification", method: mockNotification.method };
            // Set default auditNotifications to true for easier testing, override if needed
            mockOptions.auditNotifications = true;
            mockOptions.auditStore = mockAuditStore; // Ensure store is configured
            mockOptions.sanitizeForAudit = mockSanitizeForAudit; // Ensure sanitizer is configured
        });

        it('should run happy path, call handler, and audit if enabled', async () => {
            // Act
            await pipeline.executeNotificationPipeline(mockNotification, mockBaseExtra, mockOperationContext, mockAuditRecord);

            // Assert
            expect(mockNotificationHandler).toHaveBeenCalledTimes(1);
            expect(mockNotificationHandler).toHaveBeenCalledWith(
                expect.objectContaining(mockNotification), // Pipeline validates schema
                expect.objectContaining({ // Verify extra object content
                    eventId: mockOperationContext.eventId,
                    identity: null, // Default mock
                    logger: mockLogger,
                    sessionId: mockBaseExtra.sessionId,
                    signal: mockBaseExtra.signal,
                })
            );
            expect(mockAuditStore.log).toHaveBeenCalledTimes(1);
            const auditCall = mockAuditStore.log.mock.calls[0][0] as AuditRecord;
            expect(auditCall.eventId).toBe(mockOperationContext.eventId);
            expect(auditCall.mcp.method).toBe(testNotificationMethod);
            expect(auditCall.outcome.status).toBe('success');
            expect(auditCall.outcome.error).toBeUndefined();
        });

        it('should attempt identity resolution if configured, but not fail pipeline on error', async () => {
            // Arrange
            const idError = new AuthenticationError("ID resolve failed for notif");
            mockIdentityResolver.resolveIdentity.mockRejectedValue(idError);
            mockOptions.identityResolver = mockIdentityResolver;

            // Act
            await pipeline.executeNotificationPipeline(mockNotification, mockBaseExtra, mockOperationContext, mockAuditRecord);

            // Assert
            expect(mockIdentityResolver.resolveIdentity).toHaveBeenCalledTimes(1);
            expect(mockLogger.warn).toHaveBeenCalledWith("Identity resolution failed during notification processing", { error: idError });
            expect(mockNotificationHandler).toHaveBeenCalledTimes(1); // Handler should still run
            expect(mockAuditStore.log).toHaveBeenCalledTimes(1);
            const auditCall = mockAuditStore.log.mock.calls[0][0] as AuditRecord;
            expect(auditCall.identity).toBeUndefined(); // Identity should be missing or null in audit
            expect(auditCall.outcome.status).toBe('success'); // Pipeline succeeded overall
        });

        it('should resolve identity and include it in audit/handler extra', async () => {
             const userId = 'notif-user';
             mockIdentityResolver.resolveIdentity.mockResolvedValue(userId);
             mockOptions.identityResolver = mockIdentityResolver;

             await pipeline.executeNotificationPipeline(mockNotification, mockBaseExtra, mockOperationContext, mockAuditRecord);

             expect(mockNotificationHandler).toHaveBeenCalledWith(
                 expect.anything(),
                 expect.objectContaining({ identity: userId })
             );
             expect(mockAuditStore.log).toHaveBeenCalledWith(expect.objectContaining({ identity: userId }));
         });

        it('should log handler error and audit failure if handler throws', async () => {
             // Arrange
             const handlerError = new Error('Notification handler failed');
             mockNotificationHandler.mockRejectedValue(handlerError);

             // Act
             await pipeline.executeNotificationPipeline(mockNotification, mockBaseExtra, mockOperationContext, mockAuditRecord);

             // Assert
             expect(mockLogger.error).toHaveBeenCalledWith("User notification handler failed", { error: handlerError });
             expect(mockAuditStore.log).toHaveBeenCalledTimes(1);
             const auditCall = mockAuditStore.log.mock.calls[0][0] as AuditRecord;
             expect(auditCall.outcome.status).toBe('failure');
             expect(auditCall.outcome.error?.message).toBe('Notification handler failed');
             expect(auditCall.outcome.error?.type).toBe('HandlerError');
         });

        it('should skip audit log if auditNotifications is false', async () => {
             // Arrange
             mockOptions.auditNotifications = false;

             // Act
             await pipeline.executeNotificationPipeline(mockNotification, mockBaseExtra, mockOperationContext, mockAuditRecord);

             // Assert
             expect(mockNotificationHandler).toHaveBeenCalledTimes(1);
             expect(mockAuditStore.log).not.toHaveBeenCalled();
             expect(mockLogger.debug).toHaveBeenCalledWith("Skipping notification audit log", expect.anything());
         });

         it('should not call handler and audit success if method unknown', async () => {
             // Arrange
             const unknownNotification = { ...mockNotification, method: 'unknown/notif' };
             Object.assign(mockOperationContext, { mcpMessage: unknownNotification }); // Update context
             mockAuditRecord.mcp = { type: 'notification', method: unknownNotification.method }; // Update audit base

             // Act
             await pipeline.executeNotificationPipeline(unknownNotification, mockBaseExtra, mockOperationContext, mockAuditRecord);

             // Assert
             expect(mockNotificationHandler).not.toHaveBeenCalled();
             expect(mockLogger.debug).toHaveBeenCalledWith(expect.stringContaining("No governed handler for notification unknown/notif, ignoring."));
             expect(mockAuditStore.log).toHaveBeenCalledTimes(1); // Still audits if enabled
             const auditCall = mockAuditStore.log.mock.calls[0][0] as AuditRecord;
             expect(auditCall.outcome.status).toBe('success'); // Ignoring is success
         });

         it('should handle notification schema validation failure', async () => {
            // Arrange
            const invalidNotif = { ...mockNotification, params: { wrong: 123 } }; // Invalid params
            const zodError = new z.ZodError([]);
            const handlerInfo = mockNotificationHandlers.get(testNotificationMethod);
             if (!handlerInfo) throw new Error('Test setup error: handler info not found');
             const safeParseSpy = jest.spyOn(handlerInfo.schema, 'safeParse')
                                     .mockReturnValue({ success: false, error: zodError });

            Object.assign(mockOperationContext, { mcpMessage: invalidNotif }); // Update context

            // Act
            await pipeline.executeNotificationPipeline(invalidNotif, mockBaseExtra, mockOperationContext, mockAuditRecord);

            // Assert
            expect(mockLogger.error).toHaveBeenCalledWith("Notification failed schema validation", expect.anything());
            expect(mockNotificationHandler).not.toHaveBeenCalled();
            expect(mockAuditStore.log).toHaveBeenCalledTimes(1);
            const auditCall = mockAuditStore.log.mock.calls[0][0] as AuditRecord;
            expect(auditCall.outcome.status).toBe('success'); // Treat validation failure as ignored (success)

            safeParseSpy.mockRestore();
         });

         it('should skip audit if auditStore or sanitizeForAudit are missing when auditNotifications=true', async () => {
             // Arrange auditNotifications = true is default for this describe block

             // Case 1: No auditStore
             mockOptions.auditStore = undefined as any; // Force undefined
             pipeline = new GovernancePipeline(mockOptions, mockRequestHandlers as any, mockNotificationHandlers as any); // Recreate pipeline
             await pipeline.executeNotificationPipeline(mockNotification, mockBaseExtra, mockOperationContext, mockAuditRecord);
             expect(mockLogger.error).toHaveBeenCalledWith(expect.stringContaining("auditStore is not configured"));
             expect(mockAuditStore.log).not.toHaveBeenCalled(); // Original mock store log wasn't called
             mockLogger.error.mockClear(); // Clear mock for next case

             // Case 2: No sanitize function
             mockOptions.auditStore = mockAuditStore; // Put store back
             mockOptions.sanitizeForAudit = undefined as any; // Force undefined
             pipeline = new GovernancePipeline(mockOptions, mockRequestHandlers as any, mockNotificationHandlers as any); // Recreate pipeline
             await pipeline.executeNotificationPipeline(mockNotification, mockBaseExtra, mockOperationContext, mockAuditRecord);
             expect(mockLogger.error).toHaveBeenCalledWith(expect.stringContaining("sanitizeForAudit is not configured"));
             expect(mockAuditStore.log).not.toHaveBeenCalled();

         });


    }); // End executeNotificationPipeline describe

});