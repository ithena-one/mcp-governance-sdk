import { UserIdentity, OperationContext } from '../types.js';

/**
 * Interface for resolving the identity of the caller based on the operation context.
 */
export interface IdentityResolver {
    /**
     * Resolves the identity of the caller based on transport/message context.
     * @param opCtx - The context of the current operation.
     * @returns The resolved UserIdentity, or null if identity cannot be determined.
     * @throws {AuthenticationError} or other specific error on failure if necessary.
     */
    resolveIdentity(opCtx: OperationContext): Promise<UserIdentity | null>;
} 