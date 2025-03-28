// src/utils/audit-helpers.test.ts

import { JSONRPCResponse, JSONRPCError, ErrorCode as McpErrorCode } from '@modelcontextprotocol/sdk/types.js';
import { buildAuditOutcome } from '../utils/audit-helpers.js';
import { AuthorizationError, HandlerError } from '../errors/index.js';
import { mapErrorToAuditPayload } from '../utils/error-mapper.js'; // Import the dependency

describe('Audit Helpers', () => {
    describe('buildAuditOutcome', () => {
        const mockResponse: JSONRPCResponse = {
            jsonrpc: '2.0',
            id: 1,
            result: { data: 'success_data' },
        };
        const mockRpcError: JSONRPCError = {
            jsonrpc: '2.0',
            id: 1,
            error: { code: McpErrorCode.InternalError, message: 'RPC Error' },
        };
        const mockHandlerError = new HandlerError('Handler failed', new Error('Original'));
        const mockAuthzError = new AuthorizationError('permission', 'Permission Denied');

        it('should build success outcome with result', () => {
            const outcome = buildAuditOutcome('success', null, mockResponse);
            expect(outcome).toEqual({
                status: 'success',
                mcpResponse: {
                    result: { data: 'success_data' },
                },
            });
        });

         it('should build success outcome without result', () => {
            const emptyResponse: JSONRPCResponse = { jsonrpc: '2.0', id: 1, result: {} };
             const outcome = buildAuditOutcome('success', null, emptyResponse);
             expect(outcome).toEqual({
                 status: 'success',
                 mcpResponse: {
                     result: {},
                 },
             });
         });

        it('should build failure outcome with handler error and mapped RPC error', () => {
            const outcome = buildAuditOutcome('failure', mockHandlerError, mockRpcError);
            expect(outcome).toEqual({
                status: 'failure',
                error: mapErrorToAuditPayload(mockHandlerError),
                mcpResponse: {
                    error: { code: McpErrorCode.InternalError, message: 'RPC Error' },
                },
            });
        });

        it('should build denied outcome with authorization error and mapped RPC error', () => {
            const deniedRpcError: JSONRPCError = {
                jsonrpc: '2.0',
                id: 1,
                error: { code: -32001, message: 'Permission Denied', data: { reason: 'permission' } }
            };
            const outcome = buildAuditOutcome('denied', mockAuthzError, deniedRpcError);
            expect(outcome).toEqual({
                status: 'denied',
                error: mapErrorToAuditPayload(mockAuthzError),
                mcpResponse: {
                    error: { code: -32001, message: 'Permission Denied', data: { reason: 'permission' } },
                },
            });
        });

        it('should build failure outcome when response is null (e.g., critical error before response)', () => {
            const outcome = buildAuditOutcome('failure', mockHandlerError, null);
            expect(outcome).toEqual({
                status: 'failure',
                error: mapErrorToAuditPayload(mockHandlerError),
                mcpResponse: undefined, // No mcpResponse field
            });
        });

         it('should build failure outcome with error but no specific response payload', () => {
            // This might happen if the error occurs before a standard JSONRPCError is formatted
             const outcome = buildAuditOutcome('failure', mockHandlerError, null);
             expect(outcome).toEqual({
                 status: 'failure',
                 error: mapErrorToAuditPayload(mockHandlerError),
                 mcpResponse: undefined
             });
         });
    });
});