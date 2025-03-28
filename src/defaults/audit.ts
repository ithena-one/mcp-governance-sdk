import { AuditLogStore, AuditRecord } from '../interfaces.js'; // Adjust path

/**
 * Default AuditLogStore that performs no operations.
 * Use this when auditing is not required or handled externally.
 */
export class NoOpAuditLogStore implements AuditLogStore {
    /** Does nothing. */
    async log(_record: AuditRecord): Promise<void> {
        // No-operation
        return Promise.resolve();
    }
    /** Does nothing. */
    async shutdown(): Promise<void> {
        // No-operation
        return Promise.resolve();
    }
}

/**
 * Basic AuditLogStore implementation that logs audit records as
 * structured JSON strings to the console. Suitable for development and debugging.
 * **Not recommended for production environments** due to lack of persistence,
 * searching capabilities, and potential performance impact under load.
 */
export class ConsoleAuditLogStore implements AuditLogStore {
    /** Logs the audit record to the console as JSON. */
    async log(record: AuditRecord): Promise<void> {
        try {
            // Prefixing helps filter console output, e.g., `node your_server.js | grep "AUDIT:"`
            console.log(`AUDIT: ${JSON.stringify(record)}`);
        } catch (error) {
            // Fallback logging in case JSON stringification fails
            console.error(
                'AUDIT_ERROR: Failed to stringify audit record for console logging:',
                error,
                // Log key fields individually as a fallback
                {
                    eventId: record.eventId,
                    method: record.mcpMethod,
                    authOutcome: record.authorizationOutcome,
                    execOutcome: record.executionOutcome,
                    identityId: typeof record.identity === 'string' ? record.identity : record.identity?.id,
                    timestamp: record.timestamp
                }
            );
        }
        // `console.log` is synchronous, but we maintain the async interface
        return Promise.resolve();
    }

    /** Logs a shutdown message to the console. */
    async shutdown(): Promise<void> {
        console.info('ConsoleAuditLogStore shutdown complete.');
        return Promise.resolve();
    }
} 