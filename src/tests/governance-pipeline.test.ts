/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-explicit-any */
// src/core/governance-pipeline.test.ts
import { jest } from '@jest/globals'; // Use if needed for explicit mocking, often implicit

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
import { OperationContext, AuditRecord, ResolvedCredentials, UserIdentity, TransportContext } from '../types.js';
import { JSONRPCRequest, McpError, ErrorCode as McpErrorCode, Request } from '@modelcontextprotocol/sdk/types.js';
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
    child: jest.fn(() => mockLogger),
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
};

const mockTraceContextProvider: jest.Mocked<TraceContextProvider> = jest.fn();

// Mock functions with type assertions
const mockDerivePermission = jest.fn() as jest.MockedFunction<(request: Request, transportContext: TransportContext) => string | null>;
const mockSanitizeForAudit = jest.fn() as jest.MockedFunction<(record: Partial<AuditRecord>) => Partial<AuditRecord>>;
const mockPostAuthHook = jest.fn() as jest.MockedFunction<(identity: UserIdentity, opCtx: OperationContext) => Promise<void>>;

// Mock Request Handler with type assertion
const mockRequestHandler = jest.fn() as jest.MockedFunction<(req: any, extra: any) => Promise<{ success: boolean }>>;
mockRequestHandler.mockResolvedValue({ success: true });

const testMethod = 'test/method';
const TestRequestSchema = z.object({
    jsonrpc: z.literal('2.0'),
    id: z.union([z.string(), z.number()]),
    method: z.literal(testMethod),
    params: z.object({ data: z.string() }).optional(),
});
type TestRequest = z.infer<typeof TestRequestSchema>;

const mockRequestHandlers = new Map<string, { handler: jest.Mocked<any>, schema: typeof TestRequestSchema }>();
mockRequestHandlers.set(testMethod, { handler: mockRequestHandler, schema: TestRequestSchema });

// Mock Notification Handler (for later tests)
const mockNotificationHandler = jest.fn();
const mockNotificationHandlers = new Map<string, { handler: jest.Mocked<any>, schema: any }>();
// notificationHandlers.set('test/notif', { handler: mockNotificationHandler, schema: ... });


// --- Test Suite ---

describe('GovernancePipeline', () => {
    let pipeline: GovernancePipeline;
    let mockOptions: GovernedServerOptions; // Use mutable options for tests

    // Default mock inputs
    let mockRequest: JSONRPCRequest;
    let mockBaseExtra: BaseRequestHandlerExtra;
    let mockOperationContext: OperationContext;
    let mockAuditRecord: Partial<AuditRecord>;

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
            auditNotifications: false,
            derivePermission: mockDerivePermission,
            sanitizeForAudit: mockSanitizeForAudit,
            postAuthorizationHook: mockPostAuthHook,
            serviceIdentifier: 'test-service',
        };

        // Default return values for mocks (can be overridden in tests)
        mockIdentityResolver.resolveIdentity.mockResolvedValue(null); // Default anonymous
        mockRoleStore.getRoles.mockResolvedValue([]);
        mockPermissionStore.hasPermission.mockResolvedValue(false);
        mockDerivePermission.mockReturnValue(null); // Default no permission needed
        mockCredentialResolver.resolveCredentials.mockResolvedValue(undefined); // Default no creds
        mockRequestHandler.mockResolvedValue({ success: true }); // Default handler success
        mockAuditStore.log.mockResolvedValue(undefined);
        mockTraceContextProvider.mockReturnValue(undefined);
        mockPostAuthHook.mockResolvedValue(undefined);

        // Setup default inputs for executeRequestPipeline
        mockRequest = {
            jsonrpc: '2.0',
            id: 1,
            method: testMethod,
            params: { data: 'test-data' },
        };
        mockBaseExtra = {
            signal: new AbortController().signal, // Fresh signal each time
            sessionId: 'session-123',
        };
        mockOperationContext = {
            eventId: 'event-abc',
            timestamp: new Date(),
            transportContext: { transportType: 'test', sessionId: 'session-123', headers: {} },
            logger: mockLogger,
            mcpMessage: mockRequest,
            serviceIdentifier: mockOptions.serviceIdentifier,
            // identity, roles, derivedPermission will be added by pipeline
        };
        mockAuditRecord = { // Initial partial record passed to pipeline
            eventId: mockOperationContext.eventId,
            timestamp: mockOperationContext.timestamp.toISOString(),
            serviceIdentifier: mockOptions.serviceIdentifier,
            transport: mockOperationContext.transportContext,
            mcp: { type: "request", method: mockRequest.method, id: mockRequest.id },
            // identity, trace, outcome etc. added by pipeline/finally block
        };

        // Instantiate the pipeline for each test
        pipeline = new GovernancePipeline(
            mockOptions,
            mockRequestHandlers as any, // Cast needed due to Jest mock type vs internal type
            mockNotificationHandlers as any
        );
    });

    // --- Test Cases for executeRequestPipeline ---

    it('should run happy path with no RBAC, no Creds, handler success', async () => {
        // Arrange: Default setup is sufficient

        // Act
        const result = await pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);

        // Assert
        expect(result).toEqual({ success: true });
        expect(mockIdentityResolver.resolveIdentity).toHaveBeenCalledTimes(1);
        expect(mockRoleStore.getRoles).not.toHaveBeenCalled(); // RBAC disabled
        expect(mockPermissionStore.hasPermission).not.toHaveBeenCalled(); // RBAC disabled
        expect(mockCredentialResolver.resolveCredentials).not.toHaveBeenCalled(); // No resolver configured by default in options? Let's assume it wasn't added.
        expect(mockRequestHandler).toHaveBeenCalledTimes(1);
        // Verify handler received correct context (simplified check)
        expect(mockRequestHandler).toHaveBeenCalledWith(
            expect.objectContaining({ method: testMethod, params: mockRequest.params }), // Parsed request
            expect.objectContaining({
                eventId: mockOperationContext.eventId,
                identity: null, // No identity resolved by default
                resolvedCredentials: undefined,
                logger: mockLogger,
                sessionId: mockBaseExtra.sessionId,
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
        mockOptions.identityResolver = mockIdentityResolver; // Ensure resolver is in options

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
            .rejects.toThrow(McpError);

        try {
            await pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);
        } catch (e: any) {
            expect(e.code).toEqual(McpErrorCode.InvalidRequest);
            expect(e.message).toContain('Invalid Token');
            expect(e.data?.type).toBe('AuthenticationError');
        }

        expect(mockRequestHandler).not.toHaveBeenCalled();
        expect(mockAuditStore.log).toHaveBeenCalledTimes(1);
        const auditCall = mockAuditStore.log.mock.calls[0][0] as AuditRecord;
        expect(auditCall.outcome.status).toBe('failure');
        expect(auditCall.outcome.error?.type).toBe('McpError');
        expect(auditCall.outcome.error?.message).toContain('Invalid Token');
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

            // Act & Assert
            await expect(pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord))
                .rejects.toThrow(McpError);

            try {
                await pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);
            } catch (e: any) {
                expect(e).toBeInstanceOf(McpError);
                expect(e.code).toEqual(-32001);
                expect(e.data?.type).toBe('AuthorizationError');
                expect(e.data?.reason).toBe('identity');
            }

            expect(mockRequestHandler).not.toHaveBeenCalled();
            expect(mockAuditStore.log).toHaveBeenCalledTimes(1);
            const auditCall = mockAuditStore.log.mock.calls[0][0] as AuditRecord;
            expect(auditCall.outcome.status).toBe('denied');
            expect(auditCall.authorization?.decision).toBe('denied');
            expect(auditCall.authorization?.denialReason).toBe('identity');
        });

        it('should fail if user has no roles granting permission', async () => {
            // Arrange
            mockIdentityResolver.resolveIdentity.mockResolvedValue('user-noroles');
            mockRoleStore.getRoles.mockResolvedValue(['viewer']); // User has 'viewer' role
            mockPermissionStore.hasPermission.mockResolvedValue(false); // 'viewer' doesn't have permission

            // Act & Assert
            await expect(pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord))
                .rejects.toThrow(McpError);

            try {
                await pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);
            } catch (e: any) {
                expect(e).toBeInstanceOf(McpError);
                expect(e.code).toEqual(-32001);
                expect(e.data?.type).toBe('AuthorizationError');
                expect(e.data?.reason).toBe('permission');
                expect(e.message).toContain(testPermission);
            }

            expect(mockRoleStore.getRoles).toHaveBeenCalledWith('user-noroles', mockOperationContext);
            expect(mockPermissionStore.hasPermission).toHaveBeenCalledWith('viewer', testPermission, mockOperationContext);
            expect(mockRequestHandler).not.toHaveBeenCalled();
            expect(mockAuditStore.log).toHaveBeenCalledTimes(1);
            const auditCall = mockAuditStore.log.mock.calls[0][0] as AuditRecord;
            expect(auditCall.outcome.status).toBe('denied');
            expect(auditCall.authorization?.decision).toBe('denied');
            expect(auditCall.authorization?.denialReason).toBe('permission');
            expect(auditCall.authorization?.roles).toEqual(['viewer']);
        });

         it('should succeed if user has a role granting permission', async () => {
             // Arrange
             const userId = 'user-admin';
             const roles = ['viewer', 'admin'];
             mockIdentityResolver.resolveIdentity.mockResolvedValue(userId);
             mockRoleStore.getRoles.mockResolvedValue(roles);
             // Mock so only 'admin' grants permission
             mockPermissionStore.hasPermission.mockImplementation(async (role, perm) => {
                 return role === 'admin' && perm === testPermission;
             });

             // Act
             const result = await pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);

             // Assert
             expect(result).toEqual({ success: true });
             expect(mockRoleStore.getRoles).toHaveBeenCalledWith(userId, mockOperationContext);
             expect(mockPermissionStore.hasPermission).toHaveBeenCalledWith('viewer', testPermission, mockOperationContext);
             expect(mockPermissionStore.hasPermission).toHaveBeenCalledWith('admin', testPermission, mockOperationContext);
             expect(mockPermissionStore.hasPermission).toHaveBeenCalledTimes(2); // Called for both roles
             expect(mockRequestHandler).toHaveBeenCalledTimes(1);
             expect(mockRequestHandler).toHaveBeenCalledWith(
                 expect.anything(),
                 expect.objectContaining({ identity: userId, roles: roles })
             );
             expect(mockAuditStore.log).toHaveBeenCalledTimes(1);
             const auditCall = mockAuditStore.log.mock.calls[0][0] as AuditRecord;
             expect(auditCall.outcome.status).toBe('success');
             expect(auditCall.authorization?.decision).toBe('granted');
             expect(auditCall.authorization?.roles).toEqual(roles);
         });

         it('should skip permission check if derivePermission returns null', async () => {
             // Arrange
             mockIdentityResolver.resolveIdentity.mockResolvedValue('user-any');
             mockDerivePermission.mockReturnValue(null); // No permission needed

             // Act
             const result = await pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);

             // Assert
             expect(result).toEqual({ success: true });
             expect(mockRoleStore.getRoles).not.toHaveBeenCalled();
             expect(mockPermissionStore.hasPermission).not.toHaveBeenCalled();
             expect(mockRequestHandler).toHaveBeenCalledTimes(1);
             expect(mockAuditStore.log).toHaveBeenCalledTimes(1);
             const auditCall = mockAuditStore.log.mock.calls[0][0] as AuditRecord;
             expect(auditCall.authorization?.decision).toBe('granted'); // Or 'not_applicable'? 'granted' based on code
             expect(auditCall.authorization?.permissionAttempted).toBeNull();
         });

         it('should skip audit log for denied request if auditDeniedRequests is false', async () => {
             // Arrange
             mockOptions.auditDeniedRequests = false;
             mockIdentityResolver.resolveIdentity.mockResolvedValue('user-noroles');
             mockRoleStore.getRoles.mockResolvedValue(['viewer']);
             mockPermissionStore.hasPermission.mockResolvedValue(false);

             // Act & Assert
             await expect(pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord))
                 .rejects.toThrow(McpError);

             expect(mockAuditStore.log).not.toHaveBeenCalled();
         });

    }); // End RBAC describe

    // --- Post-Authorization Hook ---
    describe('Post-Authorization Hook', () => {
        const userId = 'user-hook';
        beforeEach(() => {
             mockOptions.identityResolver = mockIdentityResolver;
             mockIdentityResolver.resolveIdentity.mockResolvedValue(userId);
             mockOptions.postAuthorizationHook = mockPostAuthHook;
             // Assume RBAC passed or is disabled
             mockOptions.enableRbac = false;
         });

         it('should call post-auth hook after successful identity/auth', async () => {
             await pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);
             expect(mockPostAuthHook).toHaveBeenCalledTimes(1);
             expect(mockPostAuthHook).toHaveBeenCalledWith(userId, mockOperationContext);
             expect(mockRequestHandler).toHaveBeenCalled(); // Hook success allows handler
         });

          it('should NOT call post-auth hook if identity resolution fails', async () => {
              mockIdentityResolver.resolveIdentity.mockRejectedValue(new AuthenticationError());
              await expect(pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord))
                  .rejects.toThrow(McpError);
              expect(mockPostAuthHook).not.toHaveBeenCalled();
          });

          it('should NOT call post-auth hook if RBAC fails', async () => {
              mockOptions.enableRbac = true;
              mockDerivePermission.mockReturnValue('perm1');
              mockRoleStore.getRoles.mockResolvedValue(['role1']);
              mockPermissionStore.hasPermission.mockResolvedValue(false); // Deny

              await expect(pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord))
                  .rejects.toThrow(McpError);
              expect(mockPostAuthHook).not.toHaveBeenCalled();
          });


          it('should fail pipeline if post-auth hook rejects', async () => {
              const hookError = new Error("Hook failed");
              mockPostAuthHook.mockRejectedValue(hookError);

              await expect(pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord))
                  .rejects.toThrow(McpError);

              try {
                  await pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);
              } catch(e: any) {
                  expect(e.message).toContain("Post-authorization hook failed");
                  expect(e.code).toEqual(McpErrorCode.InternalError);
                  expect(e.data?.type).toBe('GovernanceError');
              }

              expect(mockRequestHandler).not.toHaveBeenCalled();
              expect(mockAuditStore.log).toHaveBeenCalledTimes(1);
              const auditCall = mockAuditStore.log.mock.calls[0][0] as AuditRecord;
              expect(auditCall.outcome.status).toBe('failure');
              expect(auditCall.outcome.error?.type).toBe('McpError');
              expect(auditCall.outcome.error?.message).toContain('Post-authorization hook failed');
          });
    });


    // --- Credential Resolution Tests ---
    describe('Credential Resolution', () => {
        const mockCreds: ResolvedCredentials = { apiKey: 'abc' };

         beforeEach(() => {
             // Assume identity resolution passed
             mockOptions.identityResolver = mockIdentityResolver;
             mockIdentityResolver.resolveIdentity.mockResolvedValue('user-creds');
             mockOptions.credentialResolver = mockCredentialResolver; // Ensure resolver is configured
         });

        it('should resolve credentials and pass them to handler', async () => {
            mockCredentialResolver.resolveCredentials.mockResolvedValue(mockCreds);

            await pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);

            expect(mockCredentialResolver.resolveCredentials).toHaveBeenCalledWith('user-creds', mockOperationContext);
            expect(mockRequestHandler).toHaveBeenCalledWith(
                expect.anything(),
                expect.objectContaining({ resolvedCredentials: mockCreds })
            );
            expect(mockAuditStore.log).toHaveBeenCalledWith(expect.objectContaining({
                credentialResolution: { status: 'success' }
            }));
        });

         it('should handle null identity passed to resolver', async () => {
             mockIdentityResolver.resolveIdentity.mockResolvedValue(null); // Anonymous
             mockCredentialResolver.resolveCredentials.mockResolvedValue(mockCreds);

             await pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);

             expect(mockCredentialResolver.resolveCredentials).toHaveBeenCalledWith(null, mockOperationContext);
             expect(mockRequestHandler).toHaveBeenCalledWith(
                 expect.anything(),
                 expect.objectContaining({ resolvedCredentials: mockCreds })
             );
         });

        it('should fail pipeline if resolution fails and failOnCredentialResolutionError=true', async () => {
            const credError = new CredentialResolutionError('Vault fetch failed');
            mockCredentialResolver.resolveCredentials.mockRejectedValue(credError);
            mockOptions.failOnCredentialResolutionError = true; // Explicitly set (default)

            await expect(pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord))
                .rejects.toThrow(McpError);

             try {
                  await pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);
              } catch(e: any) {
                  expect(e.message).toContain("Vault fetch failed");
                  expect(e.code).toEqual(McpErrorCode.InternalError);
              }

            expect(mockRequestHandler).not.toHaveBeenCalled();
            expect(mockAuditStore.log).toHaveBeenCalledWith(expect.objectContaining({
                credentialResolution: expect.objectContaining({ status: 'failure', error: expect.anything() })
            }));
        });

        it('should continue pipeline if resolution fails and failOnCredentialResolutionError=false', async () => {
            const credError = new CredentialResolutionError('Vault fetch failed');
            mockCredentialResolver.resolveCredentials.mockRejectedValue(credError);
            mockOptions.failOnCredentialResolutionError = false;

            const result = await pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);

            expect(result).toEqual({ success: true }); // Handler still runs
            expect(mockRequestHandler).toHaveBeenCalledWith(
                expect.anything(),
                expect.objectContaining({ resolvedCredentials: undefined }) // Creds are undefined
            );
            expect(mockLogger.warn).toHaveBeenCalledWith(expect.stringContaining("Credential resolution failed, but proceeding"));
            expect(mockAuditStore.log).toHaveBeenCalledWith(expect.objectContaining({
                credentialResolution: expect.objectContaining({ status: 'failure', error: expect.anything() })
            }));
        });

        it('should skip credential resolution if resolver is not configured', async () => {
             mockOptions.credentialResolver = undefined; // Remove resolver

             await pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);

             expect(mockCredentialResolver.resolveCredentials).not.toHaveBeenCalled();
             expect(mockRequestHandler).toHaveBeenCalledWith(
                 expect.anything(),
                 expect.objectContaining({ resolvedCredentials: undefined })
             );
             expect(mockAuditStore.log).toHaveBeenCalledWith(expect.objectContaining({
                 credentialResolution: { status: 'not_configured' }
             }));
         });
    });

    // --- Handler Execution and Error Handling ---
    it('should fail pipeline if handler throws an error', async () => {
        const handlerError = new Error('Handler logic failed');
        mockRequestHandler.mockRejectedValue(handlerError);

        await expect(pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord))
            .rejects.toThrow(McpError);

        try {
            await pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);
        } catch(e: any) {
            expect(e.message).toContain('Handler execution failed');
            expect(e.code).toEqual(McpErrorCode.InternalError);
            expect(e.data?.type).toBe('HandlerError');
        }

        expect(mockAuditStore.log).toHaveBeenCalledTimes(1);
        const auditCall = mockAuditStore.log.mock.calls[0][0] as AuditRecord;
        expect(auditCall.outcome.status).toBe('failure');
        expect(auditCall.outcome.error?.type).toBe('McpError');
        expect(auditCall.outcome.error?.message).toContain('Handler execution failed');
    });

    it('should fail pipeline if request schema validation fails', async () => {
        // Arrange
        const invalidRequest = { ...mockRequest, params: { wrong: 123 } }; // Invalid params
        const error = new z.ZodError([]); // Simulate zod error
        // Need to mock the schema's safeParse method used internally
        const mockSchema = TestRequestSchema;
        const safeParseSpy = jest.spyOn(mockSchema, 'safeParse').mockReturnValue({ success: false, error } as any);

        // Act & Assert
        await expect(pipeline.executeRequestPipeline(invalidRequest, mockBaseExtra, mockOperationContext, mockAuditRecord))
            .rejects.toThrow(McpError);

        try {
            await pipeline.executeRequestPipeline(invalidRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);
        } catch(e: any) {
            expect(e.code).toEqual(McpErrorCode.InvalidParams);
            expect(e.message).toContain('Invalid request structure');
        }

        expect(mockRequestHandler).not.toHaveBeenCalled();
        expect(mockAuditStore.log).toHaveBeenCalledTimes(1);
        const auditCall = mockAuditStore.log.mock.calls[0][0] as AuditRecord;
        expect(auditCall.outcome.status).toBe('failure');
        expect(auditCall.outcome.error?.type).toBe('McpError'); // Error comes from pipeline before handler

        safeParseSpy.mockRestore(); // Clean up spy
    });


    it('should fail pipeline if method handler is not found', async () => {
        // Arrange
        const unknownRequest = { ...mockRequest, method: 'unknown/method' };
        const updatedContext = {
            ...mockOperationContext,
            mcpMessage: unknownRequest
        };
        const updatedAuditRecord = {
            ...mockAuditRecord,
            mcp: { 
                type: "request" as const,
                method: 'unknown/method',
                id: unknownRequest.id,
                params: unknownRequest.params
            }
        };

        // Act & Assert
        await expect(pipeline.executeRequestPipeline(unknownRequest, mockBaseExtra, updatedContext, updatedAuditRecord))
            .rejects.toThrow(McpError);

        try {
            await pipeline.executeRequestPipeline(unknownRequest, mockBaseExtra, updatedContext, updatedAuditRecord);
        } catch(e: any) {
            expect(e.code).toEqual(McpErrorCode.MethodNotFound);
            expect(e.message).toContain('Method not found: unknown/method');
        }

        expect(mockRequestHandler).not.toHaveBeenCalled();
        expect(mockAuditStore.log).toHaveBeenCalledTimes(1);
        const auditCall = mockAuditStore.log.mock.calls[0][0] as AuditRecord;
        expect(auditCall.outcome.status).toBe('failure');
        expect(auditCall.outcome.error?.type).toBe('McpError');
    });

    // --- Auditing Specifics ---
    it('should call sanitizeForAudit before logging', async () => {
         // Arrange: Default success path
         mockOptions.sanitizeForAudit = mockSanitizeForAudit; // Ensure it's set
         // Setup sanitizer to return a known value
         const sanitizedRecord = { sanitized: true };
         mockSanitizeForAudit.mockReturnValue(sanitizedRecord);
         
         // Mock schema validation to always succeed
         const originalSafeParse = TestRequestSchema.safeParse;
         const mockSafeParseResult = { success: true, data: mockRequest };
         TestRequestSchema.safeParse = jest.fn().mockReturnValue(mockSafeParseResult) as any;
         mockRequestHandlers.get(testMethod)!.schema = TestRequestSchema;

         // Act
         await pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);

         // Assert
         expect(mockSanitizeForAudit).toHaveBeenCalledTimes(1);
         // Check that the object passed to log is the sanitized record
         expect(mockAuditStore.log).toHaveBeenCalledWith(sanitizedRecord);
         
         // Restore original function
         TestRequestSchema.safeParse = originalSafeParse;
     });

     it('should log audit error if sanitizeForAudit throws', async () => {
        // Arrange
        const sanitizeError = new Error('Sanitization failed!');
        mockSanitizeForAudit.mockImplementation(() => { throw sanitizeError; });
        mockOptions.sanitizeForAudit = mockSanitizeForAudit;
        // Spy on console.error for the fallback logging
        const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
        
        // Mock schema validation to always succeed
        const originalSafeParse = TestRequestSchema.safeParse;
        const mockSafeParseResult = { success: true, data: mockRequest };
        TestRequestSchema.safeParse = jest.fn().mockReturnValue(mockSafeParseResult) as any;
        mockRequestHandlers.get(testMethod)!.schema = TestRequestSchema;

        // Act
        await pipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);

        // Assert
        // Request should still succeed
        expect(mockRequestHandler).toHaveBeenCalledTimes(1);
        // Audit log function should NOT be called when sanitization fails
        expect(mockAuditStore.log).not.toHaveBeenCalled();
        // Error should be logged to logger
        expect(mockLogger.error).toHaveBeenCalledWith("Audit record sanitization failed", { error: sanitizeError, auditEventId: mockOperationContext.eventId });
        // And to console.error as fallback
        expect(consoleErrorSpy).toHaveBeenCalledWith(
            expect.stringContaining("FAILED TO SANITIZE AUDIT RECORD"),
            expect.anything(), // the record
            sanitizeError
        );

        consoleErrorSpy.mockRestore();
        // Restore original function
        TestRequestSchema.safeParse = originalSafeParse;
    });

    // Create a completely new test for audit store log rejection
    it('should handle audit log store rejection', async () => {
        // Reset mocks to ensure clean state
        jest.clearAllMocks();
        
        // Setup new pipeline with fresh mocks for this test
        const testLogError = new Error('Audit store unavailable');
        const mockLogFn = jest.fn().mockImplementation(() => Promise.reject(testLogError));
        const testAuditStore = {
            log: mockLogFn
        } as unknown as AuditLogStore;
        
        const testSanitizer = jest.fn((record: Partial<AuditRecord>) => record) as SanitizeForAuditFn;
        
        const testOptions = {
            ...mockOptions,
            auditStore: testAuditStore,
            sanitizeForAudit: testSanitizer,
        };
        
        // Create fresh pipeline
        const testPipeline = new GovernancePipeline(
            testOptions,
            mockRequestHandlers as any,
            mockNotificationHandlers as any
        );
        
        // Mock schema validation to succeed
        const originalSafeParse = TestRequestSchema.safeParse;
        const mockSafeParseResult = { success: true, data: mockRequest };
        TestRequestSchema.safeParse = jest.fn().mockReturnValue(mockSafeParseResult) as any;
        
        // Execute pipeline
        await testPipeline.executeRequestPipeline(mockRequest, mockBaseExtra, mockOperationContext, mockAuditRecord);
        
        // Assertions
        expect(mockRequestHandler).toHaveBeenCalledTimes(1);
        expect(mockLogFn).toHaveBeenCalledTimes(1);
        expect(testSanitizer).toHaveBeenCalledTimes(1);
        expect(mockLogger.error).toHaveBeenCalledWith(
            "Audit logging failed",
            expect.objectContaining({ 
                error: testLogError,
                auditEventId: mockOperationContext.eventId
            })
        );
        
        // Restore
        TestRequestSchema.safeParse = originalSafeParse;
    });

    // TODO: Add tests for executeNotificationPipeline
    // describe('executeNotificationPipeline', () => { ... });

});