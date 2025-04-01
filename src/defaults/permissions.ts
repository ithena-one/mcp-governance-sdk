/* eslint-disable @typescript-eslint/no-explicit-any */
import { PermissionStore, RoleStore } from '../interfaces/rbac.js';
import { UserIdentity, OperationContext, TransportContext } from '../types.js';
import { Request } from '@modelcontextprotocol/sdk/types.js';

/**
 * Derives a permission string based on the MCP method and parameters.
 * Examples:
 * - `tool:call:<tool_name>`
 * - `resource:read:<uri>` (if fixed URI)
 * - `resource:read:<uri_template>` (if template URI)
 * - `resource:list`
 * - `resource:templates:list`
 * - `prompt:get:<prompt_name>`
 * - `prompt:list`
 * Returns null for protocol-level messages like 'initialize', 'ping'.
 */
export function defaultDerivePermission(
    request: Request,
    _transportContext: TransportContext
): string | null {
    const method = request.method;
    const params = request.params as Record<string, any> | undefined;

    // --- MODIFICATION START ---
    // Handle tool calls more generically
    if (method.startsWith('tools/')) {
        // Convert 'tools/callSomething' to 'tool:callSomething'
        // Assumes the part after 'tools/' is the action/name
        // Avoid double 'call' if method is 'tools/call' and params.name exists
        if (method === 'tools/call' && params?.name) {
             return `tool:call:${params.name}`;
        }
        return `tool:${method.substring('tools/'.length)}`;
    }
    // Handle resource reads more generically
    if (method.startsWith('resources/')) {
        const action = method.substring('resources/'.length);
        // Handle specific cases first if they have different logic or param needs
        if (action === 'read' && params?.uri) {
            return `resource:read:${params.uri}`;
        }
        if (action === 'subscribe' && params?.uri) {
             return `resource:subscribe:${params.uri}`;
        }
        if (action === 'unsubscribe' && params?.uri) {
            return `resource:unsubscribe:${params.uri}`;
        }
        // General conversion for simple patterns like 'resources/list' -> 'resource:list'
        // Only replace the *first* slash if applicable, or just use the action
        if (action.includes('/')) {
             return `resource:${action.replace('/', ':')}`; // Basic conversion for cases like templates/list
        } else {
             return `resource:${action}`; // For simple cases like 'list'
        }

    }
     // Handle prompts more generically
     if (method.startsWith('prompts/')) {
         const action = method.substring('prompts/'.length);
         if (action === 'get' && params?.name) {
            return `prompt:get:${params.name}`;
         }
         // Convert 'prompts/list' to 'prompt:list'
         return `prompt:${action.replace('/', ':')}`;
     }
    // --- MODIFICATION END ---


    // Keep specific cases or fall back to original switch if needed
    switch (method) {
        // Cases handled by the generic logic above or simple enough not to need explicit handling here anymore
        // case 'tools/call': // Handled above
        // case 'tools/list': // Handled above (implicitly by 'tools/')
        // case 'resources/read': // Handled above
        // case 'resources/list': // Handled above
        // case 'resources/templates/list': // Handled above
        // case 'resources/subscribe': // Handled above
        // case 'resources/unsubscribe': // Handled above
        // case 'prompts/get': // Handled above
        // case 'prompts/list': // Handled above

        case 'completion/complete': { // Complex logic, keep specific
            const ref = params?.ref as any;
            if (ref?.type === 'ref/prompt') return `completion:prompt:${ref.name}:${params?.argument?.name ?? '*'}`;
            if (ref?.type === 'ref/resource') return `completion:resource:${ref.uri}:${params?.argument?.name ?? '*'}`;
            return 'completion:complete';
        }

        // Other specific cases
        case 'sampling/createMessage':
            return 'sampling:createMessage';
        case 'roots/list':
            return 'roots:list';
        case 'logging/setLevel':
            return 'logging:setLevel';

        // Protocol messages needing no permission check
        case 'initialize':
        case 'ping':
            return null;

        default:
            // Fallback for truly unknown methods (might still be wrong format)
            // Consider logging a warning here if reached
            console.warn(`[defaultDerivePermission] Applying default permission format for unknown method: ${method}`);
            // Attempt a basic conversion just in case
            if (method.includes('/')) {
                const parts = method.split('/');
                return `${parts[0]}:${parts.slice(1).join(':')}`;
            }
            return method; // Or return null/throw error if unknown methods are disallowed
    }
}

// --- Default In-Memory Stores (for testing/development) ---

/**
 * Simple in-memory RoleStore implementation.
 */
export class InMemoryRoleStore implements RoleStore {
    private rolesByUser: Record<string, Set<string>>;

    constructor(initialRoles: Record<string, string[]> = {}) {
        this.rolesByUser = {};
        for (const [userId, roles] of Object.entries(initialRoles)) {
            this.rolesByUser[userId] = new Set(roles);
        }
    }

    async getRoles(identity: UserIdentity, _opCtx: OperationContext): Promise<string[]> {
        const userId = typeof identity === 'string' ? identity : identity?.id;
        if (!userId) {
            return [];
        }
        return Array.from(this.rolesByUser[userId] ?? []);
    }

    /** Adds roles to a user. */
    addUserRoles(userId: string, roles: string[]): void {
        if (!this.rolesByUser[userId]) {
            this.rolesByUser[userId] = new Set();
        }
        roles.forEach(role => this.rolesByUser[userId].add(role));
    }

    /** Removes roles from a user. */
    removeUserRoles(userId: string, roles: string[]): void {
        if (!this.rolesByUser[userId]) {
            return;
        }
        roles.forEach(role => this.rolesByUser[userId].delete(role));
    }
}

/**
 * Simple in-memory PermissionStore implementation.
 */
export class InMemoryPermissionStore implements PermissionStore {
    private permissionsByRole: Record<string, Set<string>>;
    private logger = console; // Keep using console for simplicity

    constructor(initialPermissions: Record<string, string[]> = {}) {
        this.permissionsByRole = {};
        for (const [role, permissions] of Object.entries(initialPermissions)) {
            this.permissionsByRole[role] = new Set(permissions);
        }
        this.logger.log(`[InMemoryPermissionStore CONSTRUCTOR] Initialized with permissions:`, JSON.stringify(this.permissionsByRole, (key, value) => value instanceof Set ? [...value] : value));
    }

    async hasPermission(role: string, permission: string, opCtx: OperationContext): Promise<boolean> {
        const scopedLogger = opCtx?.logger || this.logger;

        scopedLogger.debug(`[InMemoryPermissionStore HASPERMISSION_ENTRY] Checking role="${role}" (type: ${typeof role}), permission="${permission}" (type: ${typeof permission})`);

        const permissionsForRole = this.permissionsByRole[role];
        scopedLogger.debug(`[InMemoryPermissionStore HASPERMISSION_STATE] Permissions Set found for role "${role}": ${permissionsForRole ? `Set(${[...permissionsForRole].map(p => JSON.stringify(p)).join(', ')})` : 'undefined'}`);

        if (!permissionsForRole) {
            scopedLogger.debug(`[InMemoryPermissionStore HASPERMISSION_RESULT] No permissions found for role "${role}". Denying.`);
            return false; // Exit early if no set exists for the role
        }

        // Check for wildcard '*' separately
        if (permissionsForRole.has('*')) {
             scopedLogger.debug(`[InMemoryPermissionStore HASPERMISSION_RESULT] Role "${role}" has wildcard access. Granting.`);
             return true;
        }

        // *** DETAILED MANUAL CHECK ***
        let manualMatchFound = false;
        scopedLogger.debug(`[InMemoryPermissionStore MANUAL_CHECK] Iterating through permissions for role "${role}":`);
        for (const storedPermission of permissionsForRole) {
            const directComparison = storedPermission === permission;
            scopedLogger.debug(` - Comparing input "${permission}" (len: ${permission.length}) with stored "${storedPermission}" (len: ${storedPermission.length}). Strict Equal (===): ${directComparison}`);
            // Optional: Log character codes for very deep debugging
            // scopedLogger.debug(`   Input char codes: ${permission.split('').map(c => c.charCodeAt(0)).join(',')}`);
            // scopedLogger.debug(`   Stored char codes: ${storedPermission.split('').map(c => c.charCodeAt(0)).join(',')}`);
            if (directComparison) {
                manualMatchFound = true;
                // Don't break here yet, log all comparisons
            }
        }
        scopedLogger.debug(`[InMemoryPermissionStore MANUAL_CHECK_RESULT] Manual iteration found match: ${manualMatchFound}`);
        // *** END DETAILED MANUAL CHECK ***


        // Log the result of Set.has() again for comparison
        const setResult = permissionsForRole.has(permission);
        scopedLogger.debug(`[InMemoryPermissionStore SET_HAS_RESULT] Set.has("${permission}") returned: ${setResult}`);

        // Return the result of Set.has() as before, but now we have more logs
        return setResult;
    }

    /** Adds a permission to a role. */
    addPermission(role: string, permission: string): void {
        this.logger.debug(`[InMemoryPermissionStore] Adding permission "${permission}" to role "${role}"`);
        if (!this.permissionsByRole[role]) {
            this.permissionsByRole[role] = new Set();
            this.logger.debug(`[InMemoryPermissionStore] Created new permission set for role "${role}"`);
        }
        this.permissionsByRole[role].add(permission);
        this.logger.debug(`[InMemoryPermissionStore] Successfully added permission "${permission}" to role "${role}"`);
    }

    /** Removes a permission from a role. */
    removePermission(role: string, permission: string): void {
        this.logger.debug(`[InMemoryPermissionStore] Attempting to remove permission "${permission}" from role "${role}"`);
        if (!this.permissionsByRole[role]) {
            this.logger.debug(`[InMemoryPermissionStore] No permissions found for role "${role}" - nothing to remove`);
            return;
        }
        this.permissionsByRole[role].delete(permission);
        this.logger.debug(`[InMemoryPermissionStore] Successfully removed permission "${permission}" from role "${role}"`);
    }
}