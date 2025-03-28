// src/utils/error-mapper.test.ts

import { McpError, ErrorCode as McpErrorCode } from '@modelcontextprotocol/sdk/types.js';
import { mapErrorToPayload, mapErrorToAuditPayload } from '../utils/error-mapper.js';
import { AuthenticationError, AuthorizationError, CredentialResolutionError, HandlerError, GovernanceError } from '../errors/index.js';

describe('Error Mapping Utilities', () => {

    // --- mapErrorToPayload Tests ---
    describe('mapErrorToPayload', () => {
        it('should map McpError correctly', () => {
            const mcpError = new McpError(McpErrorCode.InvalidParams, 'Invalid parameters', { detail: 'xyz' });
            const payload = mapErrorToPayload(mcpError, McpErrorCode.InternalError, 'Default');
            expect(payload).toEqual({
                code: McpErrorCode.InvalidParams,
                message: 'MCP error -32602: Invalid parameters',
                data: { detail: 'xyz' },
            });
        });

        it('should map AuthorizationError to custom code', () => {
            const authzError = new AuthorizationError('permission', 'Permission denied', { scope: 'admin' });
            const payload = mapErrorToPayload(authzError, McpErrorCode.InternalError, 'Default');
            expect(payload).toEqual({
                code: -32001, // Custom code for AuthZ
                message: 'Permission denied',
                data: { reason: 'permission', details: { scope: 'admin' } },
            });
        });

        it('should map AuthenticationError to InvalidRequest', () => {
            const authnError = new AuthenticationError('Token expired', { type: 'jwt' });
            const payload = mapErrorToPayload(authnError, McpErrorCode.InternalError, 'Default');
            expect(payload).toEqual({
                code: McpErrorCode.InvalidRequest,
                message: 'Token expired',
                data: { type: 'jwt' },
            });
        });

        it('should map CredentialResolutionError to InternalError', () => {
            const credError = new CredentialResolutionError('Vault unavailable', { target: 'db' });
            const payload = mapErrorToPayload(credError, McpErrorCode.InternalError, 'Default');
            expect(payload).toEqual({
                code: McpErrorCode.InternalError,
                message: 'Vault unavailable',
                data: { target: 'db' },
            });
        });

        it('should map HandlerError to InternalError', () => {
            const original = new Error('API failed');
            const handlerError = new HandlerError('Tool failed', original, { tool: 'calculator' });
            const payload = mapErrorToPayload(handlerError, McpErrorCode.InternalError, 'Default');
            expect(payload).toEqual({
                code: McpErrorCode.InternalError,
                message: 'Handler execution failed', // Generic message
                data: { tool: 'calculator' },
            });
        });

        it('should map generic GovernanceError to InternalError', () => {
            const govError = new GovernanceError('Policy engine error', { policy: 'p1' });
            const payload = mapErrorToPayload(govError, McpErrorCode.InternalError, 'Default');
            expect(payload).toEqual({
                code: McpErrorCode.InternalError,
                message: 'Policy engine error',
                data: { policy: 'p1' },
            });
        });

        it('should map standard Error using default code and message', () => {
            const stdError = new Error('Something went wrong');
            const payload = mapErrorToPayload(stdError, -32099, 'Default Error');
            expect(payload).toEqual({
                code: -32099,
                message: 'Something went wrong',
            });
        });

        it('should map unknown error using default code and message', () => {
            const unknownError = 'unexpected string error';
            const payload = mapErrorToPayload(unknownError, -32099, 'Default Error');
            expect(payload).toEqual({
                code: -32099,
                message: 'Default Error',
                data: 'unexpected string error',
            });
        });
    });

    // --- mapErrorToAuditPayload Tests ---
    describe('mapErrorToAuditPayload', () => {
        it('should map GovernanceError types correctly', () => {
            const authzError = new AuthorizationError('permission', 'Denied', { perm: 'p' });
            const authnError = new AuthenticationError('Failed', { type: 't' });
            const credError = new CredentialResolutionError('Creds', { detail: 'd' });
            const handlerError = new HandlerError('Handler', new Error('Orig'), { info: 'i' });
            const govError = new GovernanceError('Generic', { data: 'g' });

            expect(mapErrorToAuditPayload(authzError)).toEqual({
                type: 'AuthorizationError',
                message: 'Denied',
                details: { perm: 'p' },
                code: 'ACCESS_DENIED',
                reason: 'permission',
            });
            expect(mapErrorToAuditPayload(authnError)).toEqual({
                type: 'AuthenticationError',
                message: 'Failed',
                details: { type: 't' },
                code: 'AUTHENTICATION_FAILED',
            });
             expect(mapErrorToAuditPayload(credError)).toEqual({
                 type: 'CredentialResolutionError',
                 message: 'Creds',
                 details: { detail: 'd' },
                 code: 'CREDENTIAL_RESOLUTION_FAILED',
             });
             expect(mapErrorToAuditPayload(handlerError)).toEqual({
                 type: 'HandlerError',
                 message: 'Handler',
                 details: { info: 'i' }, // Note: doesn't include originalError by default
                 code: 'HANDLER_EXECUTION_FAILED',
             });
             expect(mapErrorToAuditPayload(govError)).toEqual({
                 type: 'GovernanceError',
                 message: 'Generic',
                 details: { data: 'g' },
             });
        });

        it('should map McpError correctly', () => {
            const mcpError = new McpError(McpErrorCode.ParseError, 'Bad JSON', { raw: '...' });
            expect(mapErrorToAuditPayload(mcpError)).toEqual({
                type: 'McpError',
                message: 'MCP error -32700: Bad JSON',
                code: McpErrorCode.ParseError,
                details: { raw: '...' },
            });
        });

        it('should map standard Error correctly', () => {
            const stdError = new Error('Standard');
            expect(mapErrorToAuditPayload(stdError)).toEqual({
                type: 'Error',
                message: 'Standard',
            });
        });

        it('should map unknown error correctly', () => {
            const unknownError = 123;
            expect(mapErrorToAuditPayload(unknownError)).toEqual({
                type: 'UnknownError',
                message: '123',
            });
        });
    });
});