import {
    McpError,
    ErrorCode as McpErrorCode
} from '@modelcontextprotocol/sdk/types.js';
import {
    UserIdentity, OperationContext, GovernedServerOptions, AuditRecord, ResolvedCredentials
} from '../../../types.js'; // Adjust path
import { CredentialResolutionError } from '../../../errors/index.js'; // Adjust path

// Define a type for the context expected by this step
interface CredentialContext extends OperationContext {
    // Include properties from previous steps if needed, e.g., identity, roles
    identity?: UserIdentity | null;
    roles?: string[];
    derivedPermission?: string | null;
}

/**
 * Pipeline Step: Credential Resolution
 * Resolves credentials based on the identity and context from previous steps.
 * Updates the audit record with the credential resolution status and potential errors.
 * Returns the resolved credentials or null/undefined.
 * Throws McpError if resolution fails *and* failOnCredentialResolutionError is true.
 */
export async function resolveCredentialsStep(
    options: Pick<GovernedServerOptions, 'credentialResolver' | 'failOnCredentialResolutionError'>,
    identity: UserIdentity | null,
    context: Readonly<CredentialContext>, // Context built up from previous steps
    auditRecord: Partial<AuditRecord>
): Promise<ResolvedCredentials | null | undefined> {
    const logger = context.logger;
    let resolvedCredentials: ResolvedCredentials | null | undefined = undefined;

    // Ensure credentialResolution part of audit record is initialized
    if (!auditRecord.credentialResolution) {
        auditRecord.credentialResolution = { status: 'not_configured' };
    }

    if (options.credentialResolver) {
        auditRecord.credentialResolution.status = 'failure'; // Assume failure until success
        try {
            logger.debug("[Pipeline Step] Starting Credential Resolution...");
            resolvedCredentials = await options.credentialResolver.resolveCredentials(identity, context);
            auditRecord.credentialResolution.status = 'success';
            logger.debug("[Pipeline Step] Credential Resolution completed.", { resolved: resolvedCredentials !== undefined && resolvedCredentials !== null });
            return resolvedCredentials;
        } catch (err) {
            auditRecord.credentialResolution.error = {
                message: err instanceof Error ? err.message : String(err),
                type: err?.constructor?.name
            };
            logger.error("Credential resolution failed", { error: err });
            logger.debug("[Pipeline Step] Credential Resolution failed.");
            if (options.failOnCredentialResolutionError) {
                const credError = err instanceof Error
                    ? new CredentialResolutionError(err.message, { originalError: err })
                    : new CredentialResolutionError("Credential resolution failed", { originalError: err });
                throw new McpError(McpErrorCode.InternalError, credError.message, {
                    type: 'CredentialResolutionError',
                    originalError: err
                });
            } else {
                logger.warn("Credential resolution failed, but proceeding as failOnCredentialResolutionError=false");
                // Return whatever might have been partially resolved, or undefined
                return resolvedCredentials;
            }
        }
    } else {
        logger.debug("[Pipeline Step] Skipping Credential Resolution (no resolver configured).");
        auditRecord.credentialResolution.status = 'not_configured';
        return undefined;
    }
} 