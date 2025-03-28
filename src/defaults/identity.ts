import { IdentityResolver, UserIdentity } from '../interfaces.js'; // Adjust path

/**
 * Default IdentityResolver that always returns the provided identity.
 * Use this when no identity resolution is required or when the identity
 * is already in the correct format.
 */
export class PassThroughIdentityResolver implements IdentityResolver {
    /** Returns the provided identity unchanged. */
    async resolveIdentity(identity: UserIdentity): Promise<UserIdentity> {
        return identity;
    }
}

/**
 * IdentityResolver that validates the identity format but performs no transformation.
 * Throws an error if the identity is not in the expected format.
 */
export class StrictIdentityResolver implements IdentityResolver {
    /** Validates and returns the identity if it matches the expected format. */
    async resolveIdentity(identity: UserIdentity): Promise<UserIdentity> {
        if (typeof identity === 'string') {
            if (!identity.trim()) {
                throw new Error('Identity string cannot be empty');
            }
            return identity;
        }

        if (typeof identity === 'object' && identity !== null) {
            if (!identity.id || typeof identity.id !== 'string') {
                throw new Error('Identity object must have a non-empty string id');
            }
            return identity;
        }

        throw new Error('Identity must be a non-empty string or an object with an id property');
    }
} 