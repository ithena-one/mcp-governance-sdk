import { UserIdentity, ResolvedCredentials, OperationContext } from '../types.js';

/**
 * Interface for resolving credentials (secrets, API keys, etc.) needed for an operation.
 */
export interface CredentialResolver {
    /**
     * Resolves credentials needed for the operation, potentially based on identity.
     * This is typically called *after* successful authorization.
     * @param identity - The resolved user identity (or null if auth is skipped/not applicable).
     * @param opCtx - The context of the current operation.
     * @returns The resolved credentials, or null/undefined if no credentials apply.
     * @throws {CredentialResolutionError} on failure to resolve required credentials.
     */
    resolveCredentials(identity: UserIdentity | null, opCtx: OperationContext): Promise<ResolvedCredentials | null | undefined>;
} 