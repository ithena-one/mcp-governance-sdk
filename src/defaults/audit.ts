import { AuditLogStore } from '../interfaces/audit.js';
import { AuditRecord } from '../types.js';

/**
 * An AuditLogStore that does nothing. Used as the default if no store is provided.
 */
export class NoOpAuditLogStore implements AuditLogStore {
    async log(_record: AuditRecord): Promise<void> {
        // Do nothing
    }
    async shutdown(): Promise<void> {
        // Do nothing
    }
}

/**
 * An AuditLogStore that logs audit records as JSON to the console.
 * Suitable for development and debugging.
 */
export class ConsoleAuditLogStore implements AuditLogStore {
    async log(record: AuditRecord): Promise<void> {
        try {
            console.log(JSON.stringify(record));
        } catch (error) {
            console.error("Failed to serialize or log audit record:", error, record);
        }
    }
    // No shutdown needed for console logging
}

export const defaultAuditStore: AuditLogStore = new NoOpAuditLogStore(); 