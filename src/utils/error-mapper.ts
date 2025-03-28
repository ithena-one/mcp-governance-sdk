import { JSONRPCError, ErrorCode as McpErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';
import { AuthenticationError, AuthorizationError, CredentialResolutionError, HandlerError, GovernanceError } from '../errors/index.js';
import { AuditRecord } from '../types.js';

/** Maps internal errors to JSON-RPC error payloads */
export function mapErrorToPayload(error: Error | unknown, defaultCode: number, defaultMessage: string): JSONRPCError['error'] {
    if (error instanceof McpError) {
        return { code: error.code, message: error.message, data: error.data };
    }
    if (error instanceof AuthorizationError) {
        return { code: -32001, message: error.message, data: { reason: error.reason, details: error.details } }; // Custom code for AuthZ
    }
    if (error instanceof AuthenticationError) {
        return { code: McpErrorCode.InvalidRequest, message: error.message, data: error.details };
    }
    if (error instanceof CredentialResolutionError) {
        return { code: McpErrorCode.InternalError, message: error.message, data: error.details };
    }
    if (error instanceof HandlerError) {
        return { code: McpErrorCode.InternalError, message: "Handler execution failed", data: error.details };
    }
    if (error instanceof GovernanceError) {
        return { code: McpErrorCode.InternalError, message: error.message, data: error.details };
    }
    if (error instanceof Error) {
        return { code: defaultCode, message: error.message || defaultMessage };
    }
    return { code: defaultCode, message: defaultMessage, data: String(error) };
}

/** Maps internal errors to the AuditRecord['outcome']['error'] structure */
export function mapErrorToAuditPayload(error: Error | unknown): NonNullable<AuditRecord['outcome']['error']> {
    if (error instanceof GovernanceError) {
        return {
            type: error.constructor.name,
            message: error.message,
            details: typeof error.details === 'object' && error.details !== null ? { ...error.details } : error.details,
            ...(error instanceof AuthorizationError && { code: "ACCESS_DENIED", reason: error.reason }),
            ...(error instanceof AuthenticationError && { code: "AUTHENTICATION_FAILED" }),
            ...(error instanceof CredentialResolutionError && { code: "CREDENTIAL_RESOLUTION_FAILED" }),
            ...(error instanceof HandlerError && { code: "HANDLER_EXECUTION_FAILED" }),
        };
    }
    if (error instanceof McpError) {
        return {
            type: "McpError",
            message: error.message,
            code: error.code,
            details: error.data,
        };
    }
    if (error instanceof Error) {
        return {
            type: error.constructor.name,
            message: error.message,
        };
    }
    return {
        type: "UnknownError",
        message: String(error),
    };
}