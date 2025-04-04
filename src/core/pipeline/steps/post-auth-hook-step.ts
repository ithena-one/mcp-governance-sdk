import {
    McpError,
    ErrorCode as McpErrorCode
} from '@modelcontextprotocol/sdk/types.js';
import {
    UserIdentity, OperationContext, GovernedServerOptions, AuditRecord, ResolvedCredentials
} from '../../../types.js'; // Adjust path
import { GovernanceError } from '../../../errors/index.js'; // Adjust path

// Define a type for the context expected by the hook
interface PostAuthHookContext extends OperationContext {
    // Define the specific properties the hook receives
    // This usually includes results from previous steps passed explicitly
    roles?: string[];
    resolvedCredentials?: ResolvedCredentials | null | undefined;
}

/**
 * Pipeline Step: Post-Authorization Hook
 * Executes a custom hook function after successful authorization (or if auth is not applicable).
 * Passes relevant context (identity, roles, credentials) to the hook.
 * Throws McpError if the hook execution fails.
 */
export async function executePostAuthHookStep(
    options: Pick<GovernedServerOptions, 'postAuthorizationHook'>,
    identity: UserIdentity | null,
    baseContext: Readonly<OperationContext>, // The initial base context
    roles: string[] | undefined,
    resolvedCredentials: ResolvedCredentials | null | undefined,
    auditRecord: Partial<AuditRecord> // Only needed for decision check
): Promise<void> {
    const logger = baseContext.logger;

    // Hook should only run if identity exists and authorization succeeded or wasn't needed
    if (options.postAuthorizationHook && identity &&
        (auditRecord.authorization?.decision === 'granted' || auditRecord.authorization?.decision === 'not_applicable'))
    {
        try {
            logger.debug("[Pipeline Step] Starting Post-Authorization Hook...");
            // Construct the specific context object for the hook
            const hookContext: PostAuthHookContext = {
                ...baseContext,
                ...(roles && { roles }),
                ...(resolvedCredentials !== undefined && { resolvedCredentials })
                // Do NOT include identity again here, it's passed as the first argument
            };
            await options.postAuthorizationHook(identity, hookContext);
            logger.debug("[Pipeline Step] Post-Authorization Hook completed successfully.");
        } catch (err) {
            logger.error("Post-authorization hook failed", { error: err });
            logger.debug("[Pipeline Step] Post-Authorization Hook failed.");
            const govError = new GovernanceError("Post-authorization hook failed", { originalError: err });
            throw new McpError(McpErrorCode.InternalError, govError.message, {
                type: 'GovernanceError',
                originalError: err
            });
        }
    } else {
         logger.debug("[Pipeline Step] Skipping Post-Authorization Hook (conditions not met).");
    }
    // No return value
} 