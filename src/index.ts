import { createServer } from '@modelcontextprotocol/sdk';
import type {
    JSONRPCRequest,
    JSONRPCNotification,
    McpError,
} from '@modelcontextprotocol/sdk/types';
import type {
    UserIdentity,
    Logger,
    IdentityResolver,
    RoleStore,
    PermissionStore,
    CredentialResolver,
    AuditLogStore,
    OperationContext,
    AuditRecord,
    GovernedServerOptions,
} from './interfaces.js';
import {
    NoOpAuditLogStore,
    NoOpCredentialResolver,
    PassThroughIdentityResolver,
    NoOpRoleStore,
    NoOpPermissionStore,
    ConsoleLogger,
} from './defaults/index.js';

export * from './interfaces.js';
export * from './errors.js';
export * from './defaults/index.js';

/**
 * Creates a new governed server instance with the specified options.
 * @param options Server configuration options
 * @returns A new governed server instance
 */
export function createGovernedServer(options: GovernedServerOptions) {
    const {
        logger = new ConsoleLogger(),
        identityResolver = new PassThroughIdentityResolver(),
        roleStore = new NoOpRoleStore(),
        permissionStore = new NoOpPermissionStore(),
        credentialResolver = new NoOpCredentialResolver(),
        auditLogStore = new NoOpAuditLogStore(),
        ...serverOptions
    } = options;

    // Create the base server
    const server = createServer(serverOptions);

    // Wrap the server's execute method to add governance
    const originalExecute = server.execute.bind(server);
    server.execute = async function execute(
        identity: UserIdentity,
        method: string,
        params: unknown,
        context?: OperationContext
    ): Promise<unknown> {
        // Create a unique event ID for this operation
        const eventId = crypto.randomUUID();
        const timestamp = new Date().toISOString();

        // Resolve the identity
        const resolvedIdentity = await identityResolver.resolveIdentity(identity);

        // Get roles and permissions
        const [roles, permissions] = await Promise.all([
            roleStore.getRoles(resolvedIdentity),
            permissionStore.getPermissions(resolvedIdentity),
        ]);

        // Get credentials if needed
        const credentials = await credentialResolver.resolveCredentials(resolvedIdentity, context);

        // Create operation context with governance info
        const governedContext: OperationContext = {
            ...context,
            eventId,
            mcpMessage: {
                jsonrpc: '2.0',
                method,
                params,
            } as JSONRPCRequest | JSONRPCNotification,
            transportContext: {
                transportType: 'memory',
            },
            logger: logger.child?.({
                eventId,
                method,
                identity: resolvedIdentity,
            }) || logger,
        };

        try {
            // Execute the operation
            const result = await originalExecute(resolvedIdentity, method, params, governedContext);

            // Log successful execution
            await auditLogStore.log({
                eventId,
                timestamp,
                identity: resolvedIdentity,
                mcpMethod: method,
                mcpType: 'request',
                authorizationOutcome: 'allowed',
                credentialResolutionOutcome: 'success',
                executionOutcome: 'success',
                roles,
                permissions,
                context: governedContext,
            } as AuditRecord);

            return result;
        } catch (error) {
            // Log failed execution
            await auditLogStore.log({
                eventId,
                timestamp,
                identity: resolvedIdentity,
                mcpMethod: method,
                mcpType: 'request',
                authorizationOutcome: 'allowed',
                credentialResolutionOutcome: 'success',
                executionOutcome: 'error',
                roles,
                permissions,
                context: governedContext,
                error: error instanceof Error ? error.message : String(error),
            } as AuditRecord);

            throw error;
        }
    };

    return server;
}