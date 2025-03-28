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

    switch (method) {
        // Tools
        case 'tools/call':
            return params?.name ? `tool:call:${params.name}` : 'tool:call';
        case 'tools/list':
            return 'tool:list';

        // Resources
        case 'resources/read': {
            if (!params?.uri) return 'resource:read';
            return `resource:read:${params.uri}`;
        }
        case 'resources/list':
            return 'resource:list';
        case 'resources/templates/list':
            return 'resource:templates:list';
        case 'resources/subscribe':
            return `resource:subscribe:${params?.uri ?? '*'}`;
        case 'resources/unsubscribe':
            return `resource:unsubscribe:${params?.uri ?? '*'}`;

        // Prompts
        case 'prompts/get':
            return params?.name ? `prompt:get:${params.name}` : 'prompt:get';
        case 'prompts/list':
            return 'prompt:list';

        // Sampling (Server -> Client)
        case 'sampling/createMessage':
            return 'sampling:createMessage';

        // Roots (Server -> Client)
        case 'roots/list':
            return 'roots:list';

        // Completion
        case 'completion/complete': {
            const ref = params?.ref as any;
            if (ref?.type === 'ref/prompt') return `completion:prompt:${ref.name}:${params?.argument?.name ?? '*'}`;
            if (ref?.type === 'ref/resource') return `completion:resource:${ref.uri}:${params?.argument?.name ?? '*'}`;
            return 'completion:complete';
        }

        // Logging (Client -> Server)
        case 'logging/setLevel':
            return 'logging:setLevel';

        // Protocol
        case 'initialize':
        case 'ping':
            return null; // No permission check needed for basic protocol handshake/healthcheck

        default:
            // For unknown methods, default to method name
            return method;
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

    constructor(initialPermissions: Record<string, string[]> = {}) {
        this.permissionsByRole = {};
        for (const [role, permissions] of Object.entries(initialPermissions)) {
            this.permissionsByRole[role] = new Set(permissions);
        }
    }

    async hasPermission(role: string, permission: string, _opCtx: OperationContext): Promise<boolean> {
        // Basic wildcard support: check if role has '*' permission
        if (this.permissionsByRole[role]?.has('*')) {
            return true;
        }
        // Check for exact permission match
        return this.permissionsByRole[role]?.has(permission) ?? false;
    }

    /** Adds a permission to a role. */
    addPermission(role: string, permission: string): void {
        if (!this.permissionsByRole[role]) {
            this.permissionsByRole[role] = new Set();
        }
        this.permissionsByRole[role].add(permission);
    }

    /** Removes a permission from a role. */
    removePermission(role: string, permission: string): void {
        if (!this.permissionsByRole[role]) {
            return;
        }
        this.permissionsByRole[role].delete(permission);
    }
} 