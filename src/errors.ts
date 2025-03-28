import { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types';
import { OperationContext, UserIdentity } from './interfaces.js'; // Adjust path if needed

/** Base error class for governance-related issues within the SDK. */
export class GovernanceError extends McpError {
    constructor(code: ErrorCode, message: string, data?: any) {
        super(code, message, data);
        // Ensure the name property is set correctly for classification
        Object.defineProperty(this, 'name', {
            value: new.target.name,
            enumerable: false,
            configurable: true,
        });
    }
}

/** Error indicating a failure during the identity resolution process. */
export class IdentityResolutionError extends GovernanceError {
    constructor(
        message: string,
        public readonly operationContext?: OperationContext // Optional context for debugging
    ) {
        // Using AccessDenied as the most appropriate standard code.
        super(ErrorCode.AccessDenied, message, {
            reason: 'identity_resolution_failed',
            eventId: operationContext?.eventId, // Include eventId if available
        });
    }
}

/** Error indicating that an authorization check (RBAC/Policy) failed. */
export class AuthorizationError extends GovernanceError {
    constructor(
        message: string,
        public readonly permission?: string | null,
        public readonly identity?: UserIdentity | null
    ) {
        super(ErrorCode.AccessDenied, message, {
            permission,
            // Include only non-sensitive parts of identity in error data
            identityId: identity
                ? typeof identity === 'string'
                    ? identity
                    : identity.id
                : null,
            reason: 'permission_denied',
        });
    }
}

/** Error indicating a failure during the credential resolution process. */
export class CredentialResolutionError extends GovernanceError {
    constructor(
        message: string,
        public readonly identity?: UserIdentity | null,
        public readonly operationContext?: OperationContext // Context useful for diagnosing credential issues
    ) {
        // Using InternalError as credential issues often relate to backend/config problems.
        super(ErrorCode.InternalError, message, {
            reason: 'credential_resolution_failed',
            eventId: operationContext?.eventId,
            identityId: identity
                ? typeof identity === 'string'
                    ? identity
                    : identity.id
                : null,
        });
    }
}

/** Error indicating a required configuration option was missing or invalid during setup. */
export class ConfigurationError extends GovernanceError {
    constructor(message: string) {
        super(ErrorCode.InternalError, message, { reason: 'configuration_error' });
    }
} 