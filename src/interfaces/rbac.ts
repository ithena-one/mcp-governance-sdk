import { UserIdentity, OperationContext } from '../types.js';

/**
 * Interface for retrieving the roles associated with a user identity.
 */
export interface RoleStore {
    /** Optional initialization logic. */
    initialize?(): Promise<void>;
    
    /**
     * Retrieves the roles for a given identity.
     * @param identity - The resolved user identity.
     * @param opCtx - The context of the current operation.
     * @returns An array of role strings.
     */
    getRoles(identity: UserIdentity, opCtx: OperationContext): Promise<string[]>;

    /** Optional cleanup logic. */
    shutdown?(): Promise<void>;
}

/**
 * Interface for checking if a role possesses a specific permission.
 */
export interface PermissionStore {
    /** Optional initialization logic. */
    initialize?(): Promise<void>;
    
    /**
     * Checks if a given role has the specified permission.
     * @param role - The role string to check.
     * @param permission - The permission string to check for.
     * @param opCtx - The context of the current operation.
     * @returns True if the role has the permission, false otherwise.
     */
    hasPermission(role: string, permission: string, opCtx: OperationContext): Promise<boolean>;

    /** Optional cleanup logic. */
    shutdown?(): Promise<void>;
} 