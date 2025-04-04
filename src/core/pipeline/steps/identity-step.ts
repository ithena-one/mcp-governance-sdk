import {
    McpError,
    ErrorCode as McpErrorCode
} from '@modelcontextprotocol/sdk/types.js';
import {
    UserIdentity, OperationContext, GovernedServerOptions, AuditRecord
} from '../../../types.js'; // Adjust path
import { AuthenticationError } from '../../../errors/index.js'; // Adjust path

/**
 * Pipeline Step: Identity Resolution
 * Resolves the user identity based on the incoming context.
 * Updates the audit record with the resolved identity.
 * Returns the resolved identity or null.
 * Throws McpError if identity resolution fails.
 */
export async function resolveIdentityStep(
    options: Pick<GovernedServerOptions, 'identityResolver'>,
    context: Readonly<OperationContext>,
    auditRecord: Partial<AuditRecord>
): Promise<UserIdentity | null> {
    const logger = context.logger;
    let identity: UserIdentity | null = null;

    if (options.identityResolver) {
        try {
            logger.debug("[Pipeline Step] Starting Identity Resolution...");
            identity = await options.identityResolver.resolveIdentity(context);
            auditRecord.identity = identity;
            logger.debug("[Pipeline Step] Identity Resolution completed.", { identity: identity ? 'resolved' : 'null' });
            return identity;
        } catch (err) {
            logger.error("Identity resolution failed", { error: err });
            logger.debug("[Pipeline Step] Identity Resolution failed.");
            const authError = err instanceof Error
                ? new AuthenticationError(err.message)
                : new AuthenticationError("Identity resolution failed");
            throw new McpError(McpErrorCode.InvalidRequest, authError.message, {
                type: 'AuthenticationError',
                originalError: err
            });
        }
    } else {
        logger.debug("[Pipeline Step] Skipping Identity Resolution (no resolver configured).");
        return null;
    }
} 