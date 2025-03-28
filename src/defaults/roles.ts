import { RoleStore, UserIdentity } from '../interfaces.js'; // Adjust path

/**
 * Default RoleStore that always returns an empty array of roles.
 * Use this when role-based access control is not required or when
 * roles are managed externally.
 */
export class NoOpRoleStore implements RoleStore {
    /** Returns an empty array of roles. */
    async getRoles(_identity: UserIdentity): Promise<string[]> {
        return [];
    }
}

/**
 * Simple in-memory RoleStore implementation.
 * Suitable for development and testing, but not recommended for production
 * as it does not persist roles between server restarts.
 */
export class InMemoryRoleStore implements RoleStore {
    private roles: Map<string, Set<string>> = new Map();

    /** Returns the roles associated with the given identity. */
    async getRoles(identity: UserIdentity): Promise<string[]> {
        const identityId = typeof identity === 'string' ? identity : identity.id;
        return Array.from(this.roles.get(identityId) || []);
    }

    /** Adds a role to an identity. */
    async addRole(identity: UserIdentity, role: string): Promise<void> {
        const identityId = typeof identity === 'string' ? identity : identity.id;
        if (!this.roles.has(identityId)) {
            this.roles.set(identityId, new Set());
        }
        this.roles.get(identityId)!.add(role);
    }

    /** Removes a role from an identity. */
    async removeRole(identity: UserIdentity, role: string): Promise<void> {
        const identityId = typeof identity === 'string' ? identity : identity.id;
        this.roles.get(identityId)?.delete(role);
    }

    /** Removes all roles for an identity. */
    async removeAllRoles(identity: UserIdentity): Promise<void> {
        const identityId = typeof identity === 'string' ? identity : identity.id;
        this.roles.delete(identityId);
    }
} 