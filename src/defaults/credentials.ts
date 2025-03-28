import { CredentialResolver, UserIdentity } from '../interfaces.js'; // Adjust path

/**
 * Default CredentialResolver that always returns an empty object.
 * Use this when credential resolution is not required or when
 * credentials are managed externally.
 */
export class NoOpCredentialResolver implements CredentialResolver {
    /** Returns an empty object. */
    async resolveCredentials(_identity: UserIdentity): Promise<Record<string, string>> {
        return {};
    }
}

/**
 * Simple in-memory CredentialResolver implementation.
 * Suitable for development and testing, but not recommended for production
 * as it does not persist credentials between server restarts and stores
 * them in plain text.
 */
export class InMemoryCredentialResolver implements CredentialResolver {
    private credentials: Map<string, Record<string, string>> = new Map();

    /** Returns the credentials associated with the given identity. */
    async resolveCredentials(identity: UserIdentity): Promise<Record<string, string>> {
        const identityId = typeof identity === 'string' ? identity : identity.id;
        return this.credentials.get(identityId) || {};
    }

    /** Sets credentials for an identity. */
    async setCredentials(identity: UserIdentity, credentials: Record<string, string>): Promise<void> {
        const identityId = typeof identity === 'string' ? identity : identity.id;
        this.credentials.set(identityId, { ...credentials });
    }

    /** Removes all credentials for an identity. */
    async removeCredentials(identity: UserIdentity): Promise<void> {
        const identityId = typeof identity === 'string' ? identity : identity.id;
        this.credentials.delete(identityId);
    }
} 