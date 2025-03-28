/**
 * Base class for governance-specific errors.
 */
export class GovernanceError extends Error {
    constructor(message: string, public readonly details?: any) {
        super(message);
        this.name = this.constructor.name;
        // Maintains proper stack trace in V8
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, this.constructor);
        }
    }
}

/**
 * Error indicating a failure during authentication or identity resolution.
 */
export class AuthenticationError extends GovernanceError {
    constructor(message: string = "Authentication failed", details?: any) {
        super(message, details);
    }
}

/**
 * Error indicating that an authenticated user is not authorized to perform an action.
 */
export class AuthorizationError extends GovernanceError {
    constructor(
        /** Reason for denial ('identity' or 'permission'). */
        public readonly reason: 'identity' | 'permission',
        message: string = "Authorization denied",
        details?: any
    ) {
        super(message, details);
    }
}

/**
 * Error indicating a failure during credential resolution.
 */
export class CredentialResolutionError extends GovernanceError {
    constructor(message: string = "Failed to resolve credentials", details?: any) {
        super(message, details);
    }
}

/**
 * Error indicating an issue within a user-provided handler (tool, resource, prompt).
 * This wraps the original error.
 */
export class HandlerError extends GovernanceError {
    constructor(message: string, public readonly originalError?: Error | unknown, details?: any) {
        super(message, details);
    }
} 