import { PermissionStore, UserIdentity } from '../interfaces.js'; // Adjust path

/**
 * Default PermissionStore that always returns an empty array of permissions.
 * Use this when permission-based access control is not required or when
 * permissions are managed externally.
 */
export class NoOpPermissionStore implements PermissionStore {
    /** Returns an empty array of permissions. */
    async getPermissions(_identity: UserIdentity): Promise<string[]> {
        return [];
    }
}

/**
 * Simple in-memory PermissionStore implementation.
 * Suitable for development and testing, but not recommended for production
 * as it does not persist permissions between server restarts.
 */
export class InMemoryPermissionStore implements PermissionStore {
    private permissions: Map<string, Set<string>> = new Map();

    /** Returns the permissions associated with the given identity. */
    async getPermissions(identity: UserIdentity): Promise<string[]> {
        const identityId = typeof identity === 'string' ? identity : identity.id;
        return Array.from(this.permissions.get(identityId) || []);
    }

    /** Adds a permission to an identity. */
    async addPermission(identity: UserIdentity, permission: string): Promise<void> {
        const identityId = typeof identity === 'string' ? identity : identity.id;
        if (!this.permissions.has(identityId)) {
            this.permissions.set(identityId, new Set());
        }
        this.permissions.get(identityId)!.add(permission);
    }

    /** Removes a permission from an identity. */
    async removePermission(identity: UserIdentity, permission: string): Promise<void> {
        const identityId = typeof identity === 'string' ? identity : identity.id;
        this.permissions.get(identityId)?.delete(permission);
    }

    /** Removes all permissions for an identity. */
    async removeAllPermissions(identity: UserIdentity): Promise<void> {
        const identityId = typeof identity === 'string' ? identity : identity.id;
        this.permissions.delete(identityId);
    }
} 