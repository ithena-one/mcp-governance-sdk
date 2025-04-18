/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-explicit-any */
import {
    Request,
    Notification,
    Result,
    RequestId,
    JSONRPCError,
} from '@modelcontextprotocol/sdk/types.js';
import { RequestHandlerExtra as BaseRequestHandlerExtra } from '@modelcontextprotocol/sdk/shared/protocol.js';
import { Logger } from './interfaces/logger.js';
import { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';

// --- Basic Governance Types ---

/**
 * Represents the resolved identity of the caller.
 * Can be a simple string (e.g., user ID, API key prefix) or a structured object.
 */
export type UserIdentity = string | { id: string; [key: string]: any };

/**
 * Holds credentials/secrets resolved by the CredentialResolver.
 * Keys are credential names/identifiers, values are the resolved secrets (e.g., API keys, tokens).
 */
export type ResolvedCredentials = Record<string, string | object | any>;

// --- Context Objects ---

/**
 * Context related to the underlying transport layer.
 */
export interface TransportContext {
    /** Type of transport (e.g., 'stdio', 'sse', 'websocket'). */
    transportType: string;
    /** Incoming headers, relevant for HTTP-based transports. */
    headers?: Record<string, string | string[] | undefined>;
    /** Client IP address, if available. */
    remoteAddress?: string;
    /** Transport-specific session identifier, if available. */
    sessionId?: string;
}

/**
 * Context related to distributed tracing standards (e.g., W3C Trace Context).
 */
export interface TraceContext {
    traceId?: string;
    spanId?: string;
    /** W3C trace flags or similar standard's flags. */
    traceFlags?: string;
    /** W3C tracestate header value or similar. */
    traceState?: string;
    /** Optional parent span ID if derivable. */
    parentSpanId?: string;
    /** Allow for other context propagation standards. */
    [key: string]: any;
}

/**
 * Aggregated context passed to resolver/store interfaces.
 */
export interface OperationContext {
    /** A unique identifier for this specific request/notification processing lifecycle. */
    readonly eventId: string;
    /** Timestamp when the operation processing started. */
    readonly timestamp: Date;
    /** Context about the transport layer. */
    readonly transportContext: TransportContext;
    /** Extracted distributed tracing context, if available. */
    readonly traceContext?: TraceContext;
    /** Request-scoped logger instance. */
    readonly logger: Logger;
    /** The raw incoming MCP Request or Notification message. */
    readonly mcpMessage: Request | Notification;
    /** Optional identifier for the service instance processing the request. */
    readonly serviceIdentifier?: string;

    // --- Fields added progressively during pipeline ---
    /** Resolved identity of the caller, or null if unresolved. */
    identity?: UserIdentity | null;
    /** The permission string derived for the current operation (if RBAC is enabled). */
    derivedPermission?: string | null;
    /** Roles associated with the resolved identity (if RBAC is enabled). */
    roles?: string[];
    /** Credentials resolved by the CredentialResolver (if configured). */
    resolvedCredentials?: ResolvedCredentials | null;
}

/**
 * Extra context provided to request handlers registered via `GovernedServer`.
 * Extends the base SDK's RequestHandlerExtra.
 */
export interface GovernedRequestHandlerExtra extends BaseRequestHandlerExtra {
    /** A unique identifier for this specific request processing lifecycle. */
    readonly eventId: string;
    /** Request-scoped logger instance. */
    readonly logger: Logger;
    /** Resolved identity of the caller (or null). */
    readonly identity: UserIdentity | null;
    /** Resolved roles for the identity (only if RBAC is enabled). */
    readonly roles?: string[];
    /** Credentials resolved by the CredentialResolver (or null/undefined). */
    readonly resolvedCredentials?: ResolvedCredentials | null;
    /** Extracted distributed tracing context, if available. */
    readonly traceContext?: TraceContext;
    /** Context about the transport layer. */
    readonly transportContext: TransportContext;
    // Inherits 'signal' and 'sessionId' from BaseRequestHandlerExtra
    // Explicitly add signal again for clarity if BaseRequestHandlerExtra definition is uncertain
    /** An abort signal used to communicate if the request was cancelled from the sender's side. */
    readonly signal: AbortSignal;
}

/**
 * Extra context provided to notification handlers registered via `GovernedServer`.
 */
export interface GovernedNotificationHandlerExtra {
    /** A unique identifier for this specific notification processing lifecycle. */
    readonly eventId: string;
    /** Request-scoped logger instance. */
    readonly logger: Logger;
    /** Resolved identity of the caller (or null) - primarily for context/auditing. */
    readonly identity: UserIdentity | null;
    /** Extracted distributed tracing context, if available. */
    readonly traceContext?: TraceContext;
    /** Context about the transport layer. */
    readonly transportContext: TransportContext;
    /** Session ID from transport, if available */
    readonly sessionId?: string;
     /**
     * An abort signal used to communicate if the processing was cancelled externally.
     * Provided by the base SDK's handler call.
     */
    readonly signal: AbortSignal;
}

/**
 * Structure for logging audit events related to MCP operations.
 */
export interface AuditRecord {
    /** Unique ID for this request/notification processing event. */
    eventId: string;
    /** Timestamp of the event completion in ISO 8601 format. */
    timestamp: string;
    /** Optional identifier for this service instance. */
    serviceIdentifier?: string;
    /** Context about the transport layer. */
    transport: TransportContext;
    /** Details about the MCP message. */
    mcp: {
        type: "request" | "notification";
        method: string;
        id?: RequestId; // For requests
        params?: any; // Sanitized params
    };
    /** Resolved identity (sanitized if needed). */
    identity?: UserIdentity | null;
    /** Distributed tracing context. */
    trace?: TraceContext;
    /** Outcome of the operation processing. */
    outcome: {
        status: "success" | "failure" | "denied";
        error?: {
            type: string; // e.g., 'AuthorizationError', 'HandlerError'
            message: string;
            code?: number | string; // e.g., JSON-RPC code
            details?: any; // Sanitized details
        };
        mcpResponse?: { // Only for requests
            result?: any; // Sanitized result
            error?: JSONRPCError['error']; // Raw JSON-RPC error
        };
    };
    /** Details about the authorization check (if RBAC enabled). */
    authorization?: {
        permissionAttempted?: string | null;
        roles?: string[];
        decision: "granted" | "denied" | "not_applicable";
        denialReason?: "identity" | "permission";
    };
    /** Details about credential resolution (if resolver configured). */
    credentialResolution?: {
        status: "success" | "failure" | "skipped" | "not_configured";
        error?: { message: string; type?: string };
    };
    /** Total processing time in milliseconds. */
    durationMs: number;
    /** Allow for custom fields added during sanitization. */
    [key: string]: any;
}

// --- Governed Server & Handler Types ---

import { ZodObject, ZodLiteral, z, ZodTypeAny } from 'zod';
import { IdentityResolver } from './interfaces/identity.js';
import { RoleStore, PermissionStore } from './interfaces/rbac.js';
import { CredentialResolver } from './interfaces/credentials.js';
import { AuditLogStore } from './interfaces/audit.js';
import { TraceContextProvider } from './interfaces/tracing.js';



// Handlers
export type GovernedRequestHandler<T extends AnyRequestSchema> = (
    request: InferRequest<T>,
    extra: GovernedRequestHandlerExtra
) => Promise<Result>;

export type GovernedNotificationHandler<T extends AnyNotificationSchema> = (
    notification: InferNotification<T>,
    extra: GovernedNotificationHandlerExtra
) => Promise<void>;

// Server Options
export interface GovernedServerOptions {
    identityResolver?: IdentityResolver;
    roleStore?: RoleStore;
    permissionStore?: PermissionStore;
    credentialResolver?: CredentialResolver;
    auditStore?: AuditLogStore;
    logger?: Logger;
    traceContextProvider?: TraceContextProvider;
    enableRbac?: boolean;
    failOnCredentialResolutionError?: boolean;
    auditDeniedRequests?: boolean;
    auditNotifications?: boolean;
    derivePermission?: (request: Request, transportContext: TransportContext) => string | null;
    sanitizeForAudit?: (record: Partial<AuditRecord>) => Partial<AuditRecord>;
    postAuthorizationHook?: (identity: UserIdentity, opCtx: OperationContext) => Promise<void>;
    serviceIdentifier?: string;
}

export type ProcessedGovernedServerOptions = Required<Pick<GovernedServerOptions,
    | 'auditStore' | 'logger' | 'traceContextProvider' | 'enableRbac'
    | 'failOnCredentialResolutionError' | 'auditDeniedRequests' | 'auditNotifications'
    | 'derivePermission' | 'sanitizeForAudit'
>> & GovernedServerOptions; 


export type AnyRequestSchema = ZodObject<{ method: ZodLiteral<string>; [key: string]: ZodTypeAny }>;
export type AnyNotificationSchema = ZodObject<{ method: ZodLiteral<string>; [key: string]: ZodTypeAny }>;
export type InferRequest<T extends AnyRequestSchema> = z.infer<T>;
export type InferNotification<T extends AnyNotificationSchema> = z.infer<T>;
export type RequestHandlerMap = Map<string, { handler: (req: any, extra: GovernedRequestHandlerExtra) => Promise<Result>, schema: AnyRequestSchema }>;
export type NotificationHandlerMap = Map<string, { handler: (notif: any, extra: GovernedNotificationHandlerExtra) => Promise<void>, schema: AnyNotificationSchema }>;
