import {
    JSONRPCRequest,
    McpError,
    ErrorCode as McpErrorCode
} from '@modelcontextprotocol/sdk/types.js';
import {
    UserIdentity, OperationContext, GovernedServerOptions, AuditRecord, TransportContext
} from '../../../types.js'; // Adjust path
import { AuthorizationError, GovernanceError } from '../../../errors/index.js'; // Adjust path

// Define a type for the RBAC context, extending OperationContext
interface RbacContext extends OperationContext {
    identity: UserIdentity; // Identity is required for RBAC
}

/**
 * Pipeline Step: RBAC (Role-Based Access Control)
 * Checks if the resolved identity has the required permission for the request.
 * Updates the audit record with the authorization decision, roles, and permission attempt.
 * Returns an object containing the derived permission and roles (if applicable).
 * Throws McpError if authorization fails or configuration is invalid.
 */
export async function checkRbacStep(
    options: Pick<GovernedServerOptions, 'enableRbac' | 'derivePermission' | 'roleStore' | 'permissionStore'>,
    identity: UserIdentity | null,
    context: Readonly<OperationContext>, // Base context
    identityContext: Readonly<RbacContext | OperationContext>, // Context potentially including identity
    transportContext: Readonly<TransportContext>, // Pass the proxied transport context separately
    auditRecord: Partial<AuditRecord>
): Promise<{ derivedPermission: string | null, roles: string[] | undefined }> {
    const logger = context.logger;
    let roles: string[] | undefined = undefined;
    let derivedPermission: string | null = null;

    // Initialize audit record part if not present
    if (!auditRecord.authorization) {
        auditRecord.authorization = { decision: 'not_applicable' };
    }

    if (options.enableRbac) {
        auditRecord.authorization.decision = 'denied'; // Assume denied until explicitly granted
        logger.debug("[Pipeline Step] Starting RBAC check...");

        if (identity === null) {
            auditRecord.authorization.denialReason = 'identity';
            const authzError = new AuthorizationError('identity', "Identity required for authorization but none was resolved.");
            logger.debug("[Pipeline Step] RBAC failed: Identity required but none resolved.");
            throw new McpError(-32001, authzError.message, {
                type: 'AuthorizationError',
                reason: 'identity'
            });
        }
        if (!options.roleStore || !options.permissionStore) {
            const govError = new GovernanceError("RBAC enabled but RoleStore or PermissionStore is missing.");
            throw new McpError(McpErrorCode.InternalError, govError.message, {
                type: 'GovernanceError'
            });
        }

        // Cast identityContext safely based on identity check
        const rbacIdentityContext = identityContext as RbacContext;

        derivedPermission = options.derivePermission?.(context.mcpMessage as JSONRPCRequest, transportContext) ?? null;
        logger.debug("[Pipeline Step] Permission derived.", { derivedPermission });
        auditRecord.authorization.permissionAttempted = derivedPermission;

        if (derivedPermission === null) {
            auditRecord.authorization.decision = 'granted'; // No permission needed
            logger.debug("[Pipeline Step] RBAC check skipped: No permission required (null derived).");
        } else {
            try {
                roles = await options.roleStore.getRoles(identity, rbacIdentityContext);
                logger.debug("[Pipeline Step] Roles retrieved.", { roles });
                auditRecord.authorization.roles = roles;

                if (!roles || roles.length === 0) {
                    auditRecord.authorization.denialReason = 'permission';
                    const authzError = new AuthorizationError('permission', `No roles assigned to check permission: ${derivedPermission}`);
                    throw new McpError(-32001, authzError.message, {
                        type: 'AuthorizationError',
                        reason: 'permission'
                    });
                }

                let hasPermission = false;
                for (const role of roles) {
                    logger.debug("[Pipeline Step] Checking permission for role.", { role, permission: derivedPermission });
                    try {
                        // Pass the *base* context to hasPermission, as it doesn't need identity/roles itself
                        if (await options.permissionStore!.hasPermission(role, derivedPermission!, context)) {
                            hasPermission = true;
                            logger.debug("[Pipeline Step] Permission granted by role.", { role, permission: derivedPermission });
                            break;
                        }
                    } catch (err) {
                        const govError = new GovernanceError("Error checking permissions", { originalError: err });
                        throw new McpError(McpErrorCode.InternalError, govError.message, {
                            type: 'GovernanceError',
                            originalError: err
                        });
                    }
                }

                if (!hasPermission) {
                    auditRecord.authorization.denialReason = 'permission';
                    const authzError = new AuthorizationError('permission', `Missing required permission: ${derivedPermission}`);
                    logger.debug("[Pipeline Step] RBAC failed: Permission denied.", { permission: derivedPermission, rolesChecked: roles });
                    throw new McpError(-32001, authzError.message, {
                        type: 'AuthorizationError',
                        reason: 'permission'
                    });
                }
                auditRecord.authorization.decision = 'granted';
                logger.debug("[Pipeline Step] RBAC completed: Granted.", { permission: derivedPermission, grantedByRoles: roles });

            } catch (err) {
                logger.debug("[Pipeline Step] RBAC check encountered an error.", { error: err });
                if (err instanceof McpError) throw err; // Rethrow known errors
                // Wrap unknown errors
                const govError = new GovernanceError("Error checking permissions", { originalError: err });
                throw new McpError(McpErrorCode.InternalError, govError.message, {
                    type: 'GovernanceError',
                    originalError: err
                });
            }
        }
    } else {
        logger.debug("[Pipeline Step] Skipping RBAC (disabled).");
        // Still derive permission if configured, for potential use elsewhere or testing
        if (options.derivePermission) {
            derivedPermission = options.derivePermission(context.mcpMessage as JSONRPCRequest, transportContext);
            logger.debug("[Pipeline Step] Permission derived (RBAC disabled).", { derivedPermission });
        }
        // If RBAC is disabled, the decision remains 'not_applicable'
    }

    return { derivedPermission, roles };
} 