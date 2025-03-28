import {
    JSONRPCRequest,
    JSONRPCNotification,
    RequestId,
    McpError,
} from '@modelcontextprotocol/sdk/types';
import { RequestHandlerExtra as BaseRequestHandlerExtra } from '@modelcontextprotocol/sdk/shared/protocol';

// --- Core Types ---

/**
 * Opaque user identity representation. A simple string ID is often sufficient,
 * but a structured object can carry richer context (e.g., tenant ID, groups).
 * Ensure the chosen representation is serializable if needed for audit logs.
 * @example "user-123"
 * @example { id: "user-123", tenant: "acme-corp", groups: ["dev", "admin"] }
 */
export type UserIdentity = string | { id: string; [key: string]: any };

/**
 * Represents tracing context, typically following standards like W3C Trace Context.
 * This allows correlating operations across distributed systems.
 */
export interface TraceContext {
    traceId?: string;
    spanId?: string;
    traceFlags?: number;
    isRemote?: boolean;
    /** Allows propagation of arbitrary key-value pairs (baggage items). */
    baggage?: Record<string, string>;
}

/**
 * Contains details about the underlying MCP transport layer for the current operation.
 */
export interface TransportContext {
    /** Type identifier for the transport (e.g., 'stdio', 'sse', 'websocket', 'memory'). */
    transportType: string;
    /** HTTP headers, if applicable (e.g., from SSE or WebSocket upgrade requests). */
    headers?: Record<string, string | string[] | undefined>;
    /** Remote client IP address, if available. */
    remoteAddress?: string;
    /** Session identifier provided by the transport, if any. */
    sessionId?: string;
}

/**
 * Central context object passed to various governance components (resolvers, stores).
 * It aggregates essential information about the current operation.
 */
export interface OperationContext {
    /** A unique identifier generated for this specific governed operation lifecycle. */
    readonly eventId: string;
    /** Distributed tracing context, if available. */
    readonly traceContext?: TraceContext;
    /** The original MCP request or notification message being processed. */
    readonly mcpMessage: JSONRPCRequest | JSONRPCNotification;
    /** Contextual details about the transport layer. */
    readonly transportContext: TransportContext;
    /** A logger instance, potentially scoped with operation-specific context. */
    readonly logger: Logger;
}

// --- Logging ---

/** Defines standard logging levels. */
export enum LogLevel {
    DEBUG = 1,
    INFO = 2,
    WARN = 3,
    ERROR = 4,
}

/** Abstract interface for logging within the SDK and user implementations. */
export interface Logger {
    /** Logs a message at the specified level. */
    log(
        level: LogLevel,
        message: string,
        data?: Record<string, any>,
        traceContext?: TraceContext
    ): void;
    /** Logs a debug message. */
    debug(
        message: string,
        data?: Record<string, any>,
        traceContext?: TraceContext
    ): void;
    /** Logs an informational message. */
    info(
        message: string,
        data?: Record<string, any>,
        traceContext?: TraceContext
    ): void;
    /** Logs a warning message. */
    warn(
        message: string,
        data?: Record<string, any>,
        traceContext?: TraceContext
    ): void;
    /** Logs an error message, potentially including an Error object. */
    error(
        message: string,
        error?: Error | McpError,
        data?: Record<string, any>,
        traceContext?: TraceContext
    ): void;
    /**
     * Creates a child logger instance that automatically includes the provided context
     * in all subsequent log messages. Useful for request-scoped logging.
     * @param context Key-value pairs to add to the logging context.
     * @returns A new Logger instance with the added context.
     */
    child?(context: Record<string, any>): Logger;
}

// --- Identity ---

/**
 * Defines the contract for resolving the user identity associated with an incoming MCP message.
 * Implementations should integrate with the application's authentication system (e.g., validating JWTs, session cookies, API keys).
 */
export interface IdentityResolver {
    /**
     * Resolves the user identity based on the operation context.
     * @param operationContext Context containing transport details and the MCP message.
     * @returns A promise resolving to the `UserIdentity` if successful, or `null` if the request is anonymous or authentication fails.
     * @throws {IdentityResolutionError} If a critical error occurs during resolution.
     */
    resolveIdentity(operationContext: OperationContext): Promise<UserIdentity | null>;
}

// --- Authorization (RBAC / Policy) ---

/**
 * Defines the contract for retrieving the roles associated with a user identity.
 * Implementations might query a database, an LDAP directory, or an identity provider.
 */
export interface RoleStore {
    /**
     * Gets the list of role names for a given identity.
     * @param identity The resolved user identity.
     * @param context Optional operation context for context-dependent roles.
     * @returns A promise resolving to an array of role strings.
     */
    getRoles(
        identity: UserIdentity,
        context?: OperationContext
    ): Promise<string[]>;
}

/**
 * Defines the contract for checking if a role possesses a specific permission.
 * Implementations might query a database, configuration files, or a policy engine.
 */
export interface PermissionStore {
    /**
     * Checks if a given role is granted the specified permission.
     * @param role The role name to check.
     * @param permission The permission string (e.g., "mcp:call:tool:my_tool"). Wildcards might be supported by specific implementations.
     * @param context Optional operation context for context-dependent permissions.
     * @returns A promise resolving to `true` if the permission is granted, `false` otherwise.
     */
    hasPermission(
        role: string,
        permission: string,
        context?: OperationContext
    ): Promise<boolean>;

    /**
     * Optional: Retrieves all permissions associated with a given role.
     * Useful for introspection or debugging.
     * @param role The role name.
     * @param context Optional operation context.
     * @returns A promise resolving to an array of permission strings.
     */
    getPermissions?(
        role: string,
        context?: OperationContext
    ): Promise<string[]>;
}

// --- Credentials ---

/**
 * Represents the credentials resolved for a specific MCP operation.
 * Keys should be descriptive (e.g., "SLACK_BOT_TOKEN", "GITHUB_PAT", "DATABASE_CONNECTION_STRING").
 * Values can be strings or structured objects (e.g., OAuth token responses).
 */
export type ResolvedCredentials = Record<
    string,
    string | object | undefined | null
>;

/**
 * Defines the contract for resolving external credentials needed by MCP handlers.
 * Implementations might fetch secrets from environment variables, a vault (like HashiCorp Vault, AWS Secrets Manager), or user-specific settings.
 */
export interface CredentialResolver {
    /**
     * Resolves the necessary credentials based on the identity and the target MCP operation.
     * @param identity The authenticated identity (or null).
     * @param operationContext Context containing the MCP message and other details.
     * @returns A promise resolving to the `ResolvedCredentials` map, or `null`/`undefined` if no credentials are required or resolved.
     * @throws {CredentialResolutionError} If resolution fails and is considered mandatory (based on `failOnCredentialResolutionError` option).
     */
    resolveCredentials(
        identity: UserIdentity | null,
        operationContext: OperationContext
    ): Promise<ResolvedCredentials | null | undefined>;
}

// --- Auditing ---

/**
 * Standardized structure for an audit log record, capturing the lifecycle of a governed operation.
 */
export interface AuditRecord {
    /** Unique identifier for this specific audit event instance. */
    eventId: string;
    /** Timestamp of the event occurrence in ISO 8601 format. */
    timestamp: string; // ISO 8601
    /** Trace ID from distributed tracing, if available. */
    traceId?: string;
    /** Span ID from distributed tracing, if available. */
    spanId?: string;
    /** The resolved user identity (sanitized). Null if anonymous or resolution failed. */
    identity: UserIdentity | null;
    /** Source IP address of the client, if available. */
    sourceIp?: string;
    /** Transport session identifier, if available. */
    sessionId?: string;
    /** Type of the MCP message ('request' or 'notification'). */
    mcpType: 'request' | 'notification';
    /** The MCP method that was invoked (e.g., 'tools/call', 'resources/read'). */
    mcpMethod: string;
    /** Parameters passed to the MCP method (sanitized). */
    mcpParams?: any;
    /** The unique ID of the MCP request, if applicable. */
    mcpRequestId?: RequestId;
    /** The permission string checked during authorization, if applicable. */
    permissionChecked?: string | null;
    /** The outcome of the authorization check. */
    authorizationOutcome:
        | 'allowed'
        | 'denied_identity'
        | 'denied_permission'
        | 'not_applicable'
        | 'skipped'
        | 'error';
    /** The outcome of the credential resolution step. */
    credentialResolutionOutcome:
        | 'success'
        | 'failed'
        | 'skipped'
        | 'not_applicable';
    /** The final outcome of the MCP handler execution. */
    executionOutcome: 'success' | 'error' | 'cancelled' | 'not_executed';
    /** The result returned by the handler or the error object thrown (sanitized). */
    resultOrError?: any;
    /** The total duration of the governed operation in milliseconds. */
    durationMs?: number;
    /** A flexible field for adding custom, operation-specific metadata to the audit record. */
    metadata?: Record<string, any>;
}

/**
 * Defines the contract for storing audit logs.
 * Implementations are responsible for persisting records reliably and performantly (e.g., batching, async writes).
 */
export interface AuditLogStore {
    /**
     * Persists an audit record. This method should handle its own errors gracefully
     * (e.g., log failures) and should generally not throw exceptions that would
     * interrupt the primary MCP request flow.
     * @param record The audit record to log.
     */
    log(record: AuditRecord): Promise<void>;

    /**
     * Optional: Performs graceful shutdown, ensuring any buffered logs are flushed.
     * Called when the `GovernedServer` is closed.
     */
    shutdown?(): Promise<void>;
}

// --- Tracing ---

/**
 * Defines the contract for extracting trace context (e.g., W3C Trace Context headers)
 * from incoming transport details to enable distributed tracing.
 */
export type TraceContextProvider = (
    transportContext: TransportContext,
    mcpMessage: JSONRPCRequest | JSONRPCNotification
) => TraceContext | undefined;

// --- Configuration ---

/**
 * Configuration options used when creating a `GovernedServer` instance.
 */
export interface GovernedServerOptions {
    // --- Core Components (Provide implementations or use defaults) ---
    /** Your implementation for resolving user identity. Required if `enableRbac` is true. */
    identityResolver?: IdentityResolver;
    /** Your implementation for fetching user roles. Required if `enableRbac` is true. */
    roleStore?: RoleStore;
    /** Your implementation for checking role permissions. Required if `enableRbac` is true. */
    permissionStore?: PermissionStore;
    /** Your implementation for resolving external credentials. */
    credentialResolver?: CredentialResolver;
    /** Your implementation for persisting audit logs. Defaults to `NoOpAuditLogStore`. */
    auditStore?: AuditLogStore;
    /** Your implementation for logging SDK/operational messages. Defaults to `ConsoleLogger`. */
    logger?: Logger;
    /** Your implementation for extracting trace context from incoming requests. Defaults to basic W3C Trace Context header parsing. */
    traceContextProvider?: TraceContextProvider;

    // --- Feature Flags & Behavior Control ---
    /** If true, enables and enforces RBAC checks using the provided stores. Default: `false`. */
    enableRbac?: boolean;
    /** If true, requests will fail if `credentialResolver` is configured but throws an error. If false, resolution errors are logged as warnings, and the handler proceeds without credentials. Default: `false`. */
    failOnCredentialResolutionError?: boolean;
    /** If true, audit logs will be generated even for requests denied due to identity or permission issues. Default: `false`. */
    auditDeniedRequests?: boolean;
    /** If true, audit logs will be generated for incoming notifications processed by the server. Default: `false`. */
    auditNotifications?: boolean;

    // --- Customization Hooks ---
    /** Override the default logic for deriving permission strings from MCP messages. */
    derivePermission?: (
        message: JSONRPCRequest | JSONRPCNotification
    ) => string | null;
    /** Override the default data sanitization logic for audit logs. Allows custom masking, truncation, etc. */
    sanitizeForAudit?: (
        key: string | number | symbol,
        value: any,
        record: Partial<AuditRecord>
    ) => any;
    /** Execute custom logic after successful authorization but before credential resolution. Can be used for additional checks or setup. */
    postAuthorizationHook?: (
        identity: UserIdentity | null,
        operationContext: OperationContext
    ) => Promise<void>;
}

// --- Execution Context ---

/**
 * Extended request handler context, including governance information, passed to user-defined handlers
 * registered via `GovernedServer.setRequestHandler`.
 */
export interface GovernedRequestHandlerExtra extends BaseRequestHandlerExtra {
    /** The unique event ID for tracking this specific operation through logs and audits. */
    readonly eventId: string;
    /** The resolved user identity for the request, or null if anonymous/unauthenticated. */
    readonly identity: UserIdentity | null;
    /** The credentials resolved by the `CredentialResolver`, if configured. */
    readonly resolvedCredentials?: ResolvedCredentials | null;
    /** A request-scoped logger instance, automatically including context like eventId, traceId, etc. */
    readonly logger: Logger;
    /** Distributed tracing context for this operation, if available. */
    readonly traceContext?: TraceContext;
} 