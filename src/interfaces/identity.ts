import { UserIdentity, OperationContext } from '../types.js';

/**
 * Interface for resolving the identity of the caller based on the operation context.
 */
export interface IdentityResolver {
    /**
     * Optional asynchronous initialization logic. Called once during GovernedServer.connect().
     * Useful for setting up connections, caches, etc.
     * Should throw an error if initialization fails.
     */
    initialize?(): Promise<void>;

    /**
     * Resolves the identity of the caller based on transport/message context.
     * @param opCtx - The context of the current operation.
     * @returns The resolved UserIdentity, or null if identity cannot be determined.
     * @throws {AuthenticationError} or other specific error on failure if necessary.
     */
    resolveIdentity(opCtx: OperationContext): Promise<UserIdentity | null>;

    /**
     * Optional asynchronous cleanup logic. Called once during GovernedServer.close().
     * Useful for closing connections, flushing buffers, etc.
     * Should handle errors gracefully and not prevent shutdown.
     */
    shutdown?(): Promise<void>;
} 