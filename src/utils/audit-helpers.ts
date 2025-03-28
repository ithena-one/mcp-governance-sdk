import { AuditRecord } from '../types.js';
import { JSONRPCResponse, JSONRPCError } from '@modelcontextprotocol/sdk/types.js';
import { mapErrorToAuditPayload } from './error-mapper.js';

/** Builds the complete AuditRecord['outcome'] object */
export function buildAuditOutcome(
    status: AuditRecord['outcome']['status'],
    error: Error | unknown | null,
    response: JSONRPCResponse | JSONRPCError | null
): AuditRecord['outcome'] {
    const outcome: AuditRecord['outcome'] = { status };
    if ((status === 'failure' || status === 'denied') && error) {
        outcome.error = mapErrorToAuditPayload(error);
    }
    if (response) {
        outcome.mcpResponse = {};
        if ('result' in response && response.result !== undefined) {
            outcome.mcpResponse.result = response.result; // Will be sanitized later
        } else if ('error' in response && response.error) {
            outcome.mcpResponse.error = response.error; // Raw JSON-RPC error
        }
    }
    return outcome;
}

// Potential future helper: Assembling the initial AuditRecord structure
