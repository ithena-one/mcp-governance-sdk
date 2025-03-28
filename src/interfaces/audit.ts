import { AuditRecord } from '../types.js';

/**
 * Interface for logging audit records.
 */
export interface AuditLogStore {
    /** Optional initialization logic. */
    initialize?(): Promise<void>;
    
    /**
     * Logs a completed audit record. Implementations should handle errors gracefully
     * (e.g., log to console) and avoid throwing errors that would disrupt the
     * main MCP request flow. This method is typically called asynchronously.
     * @param record - The audit record to log.
     */
    log(record: AuditRecord): Promise<void>;

    /**
     * Optional: Performs graceful shutdown operations, such as flushing
     * buffered logs or closing connections. Called during `GovernedServer.close()`.
     */
    shutdown?: () => Promise<void>;
} 