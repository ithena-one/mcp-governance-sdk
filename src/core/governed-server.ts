/* eslint-disable @typescript-eslint/no-explicit-any */
// src/core/governed-server.ts

import {
    Request, Notification, Result, JSONRPCRequest, JSONRPCNotification,
    McpError, ErrorCode as McpErrorCode,
} from '@modelcontextprotocol/sdk/types.js';

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import { RequestHandlerExtra as BaseRequestHandlerExtra } from '@modelcontextprotocol/sdk/shared/protocol.js';
import { ZodObject, ZodLiteral, z, ZodTypeAny } from 'zod';
import {
    UserIdentity, TransportContext, OperationContext, GovernedRequestHandlerExtra, GovernedNotificationHandlerExtra, AuditRecord
} from '../types.js';
import { Logger } from '../interfaces/logger.js';
import { GovernancePipeline } from './governance-pipeline.js'; // Import the new class
import { LifecycleManager } from './lifecycle-manager.js'; // Import the new class
import { HandlerRegistry, HandlerInfo } from './handler-registry.js'; // <-- Import HandlerRegistry
import { mapErrorToPayload } from '../utils/error-mapper.js';
import { generateEventId, buildTransportContext } from '../utils/helpers.js';
import { defaultLogger } from '../defaults/logger.js';
import { defaultAuditStore } from '../defaults/audit.js';
import { defaultTraceContextProvider } from '../defaults/tracing.js';
import { defaultDerivePermission } from '../defaults/permissions.js';
import { defaultSanitizeForAudit } from '../defaults/sanitization.js';
// Import specific interfaces if needed for options type
import { IdentityResolver } from '../interfaces/identity.js';
import { RoleStore, PermissionStore } from '../interfaces/rbac.js';
import { CredentialResolver } from '../interfaces/credentials.js';
import { AuditLogStore } from '../interfaces/audit.js';
import { TraceContextProvider } from '../interfaces/tracing.js';

// Define handler map types again or import if moved
// Export these types so HandlerRegistry can use them
export type AnyRequestSchema = ZodObject<{ method: ZodLiteral<string>;[key: string]: ZodTypeAny }>;
export type AnyNotificationSchema = ZodObject<{ method: ZodLiteral<string>;[key: string]: ZodTypeAny }>;
type InferRequest<T extends AnyRequestSchema> = z.infer<T>;
type InferNotification<T extends AnyNotificationSchema> = z.infer<T>;

// Export these types so HandlerRegistry can use them
export type GovernedRequestHandler<T extends AnyRequestSchema> = (
    request: InferRequest<T>,
    extra: GovernedRequestHandlerExtra
) => Promise<Result>;

export type GovernedNotificationHandler<T extends AnyNotificationSchema> = (
    notification: InferNotification<T>,
    extra: GovernedNotificationHandlerExtra
) => Promise<void>;

// --- GovernedServerOptions remains the same ---
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
// --- ProcessedGovernedServerOptions remains the same ---
type ProcessedGovernedServerOptions = Required<Pick<GovernedServerOptions,
    | 'auditStore' | 'logger' | 'traceContextProvider' | 'enableRbac'
    | 'failOnCredentialResolutionError' | 'auditDeniedRequests' | 'auditNotifications'
    | 'derivePermission' | 'sanitizeForAudit'
>> & GovernedServerOptions;


/**
 * Wraps a base Model Context Protocol (MCP) Server to add a governance layer.
 */
export class GovernedServer {
    private readonly baseServer: Server;
    private readonly options: ProcessedGovernedServerOptions;
    private transportInternal?: Transport;
    private lifecycleManager: LifecycleManager;
    private readonly handlerRegistry: HandlerRegistry; // <-- Add HandlerRegistry instance
    private pipeline?: GovernancePipeline; // Instantiated after connect

    constructor(
        baseServer: Server,
        options: GovernedServerOptions = {}
    ) {
        this.baseServer = baseServer;
        this.options = { /* ... apply defaults as before ... */
            identityResolver: options.identityResolver,
            roleStore: options.roleStore,
            permissionStore: options.permissionStore,
            credentialResolver: options.credentialResolver,
            postAuthorizationHook: options.postAuthorizationHook,
            serviceIdentifier: options.serviceIdentifier,
            auditStore: options.auditStore ?? defaultAuditStore,
            logger: options.logger ?? defaultLogger,
            traceContextProvider: options.traceContextProvider ?? defaultTraceContextProvider,
            enableRbac: options.enableRbac ?? false,
            failOnCredentialResolutionError: options.failOnCredentialResolutionError ?? true,
            auditDeniedRequests: options.auditDeniedRequests ?? true,
            auditNotifications: options.auditNotifications ?? false,
            derivePermission: options.derivePermission ?? defaultDerivePermission,
            sanitizeForAudit: options.sanitizeForAudit ?? defaultSanitizeForAudit,
        };

        // Initialize HandlerRegistry
        this.handlerRegistry = new HandlerRegistry(this.options.logger); // <-- Initialize

        if (this.options.enableRbac && (!this.options.roleStore || !this.options.permissionStore)) {
            throw new Error("RoleStore and PermissionStore must be provided when RBAC is enabled.");
        }

        // Initialize LifecycleManager
        this.lifecycleManager = new LifecycleManager(this.options.logger, [
            this.options.logger,
            this.options.auditStore,
            this.options.identityResolver,
            this.options.roleStore,
            this.options.permissionStore,
            this.options.credentialResolver,
        ]);
    }

    public get transport(): Transport | undefined {
        return this.transportInternal;
    }

    async connect(transport: Transport): Promise<void> {
        if (this.transportInternal) {
            throw new Error("GovernedServer is already connected.");
        }
        const logger = this.options.logger;
        logger.info("GovernedServer connecting...");
        this.transportInternal = transport;

        try {
            // --- Initialize Components ---
            await this.lifecycleManager.initialize();

            // --- Set HandlerRegistry as connected ---
            this.handlerRegistry.setConnected(); // <-- Set connected

            // --- Instantiate Pipeline ---
            // Pass necessary options and handler maps from the registry to the pipeline instance
            this.pipeline = new GovernancePipeline(
                this.options,
                this.handlerRegistry.getRequestHandlers(),      // <-- Get handlers from registry
                this.handlerRegistry.getNotificationHandlers() // <-- Get handlers from registry
            );

            // --- Register Base Handlers ---
            this._registerBaseHandlers();

            // --- Connect Base Server ---
            await this.baseServer.connect(transport);

            // --- Setup Governed Close Handling ---
            const originalBaseOnClose = this.baseServer.onclose;
            this.baseServer.onclose = () => {
                Promise.resolve().then(async () => {
                    logger.info("Base server connection closed, running governed cleanup...");
                    await this.lifecycleManager.shutdown(); // Use manager for shutdown
                }).catch(err => {
                    logger.error("Error during component shutdown on close", err);
                }).finally(() => {
                    this.transportInternal = undefined;
                    this.pipeline = undefined; // Clear pipeline instance
                    this.handlerRegistry.setDisconnected(); // <-- Set disconnected
                    originalBaseOnClose?.();
                    logger.debug("Governed onclose handler finished.");
                });
            };

            logger.info("GovernedServer connected successfully.");

        } catch (error) {
            logger.error("GovernedServer connection failed during initialization", error);
            await this.lifecycleManager.shutdown(); // Attempt cleanup on failure
            this.transportInternal = undefined;
            this.pipeline = undefined;
            throw error;
        }
    }

    async close(): Promise<void> {
        const logger = this.options.logger;
        if (!this.transportInternal) {
            logger.info("GovernedServer close called, but already closed or not connected.");
            return;
        }
        logger.info("GovernedServer closing...");

        // Shutdown components first using the manager
        await this.lifecycleManager.shutdown();

        // Set registry as disconnected before potentially triggering onclose
        this.handlerRegistry.setDisconnected(); // <-- Set disconnected

        // Then close the base server (which should trigger our onclose handler)
        if (this.baseServer) {
            try {
                await this.baseServer.close();
            } catch (err) {
                logger.error("Error during baseServer.close()", err);
                // Ensure state is cleared anyway
                this.transportInternal = undefined;
                this.pipeline = undefined;
            }
        } else {
            this.transportInternal = undefined;
            this.pipeline = undefined;
            // Ensure disconnected is set even if no base server existed or failed to close
            this.handlerRegistry.setDisconnected(); // <-- Ensure disconnected
        }

        logger.info("GovernedServer closed.");
    }

    async notification(notification: Notification): Promise<void> {
        await this.baseServer.notification(notification as any);
    }

    // --- Handler Registration (remains the same, stores locally) ---
    setRequestHandler<T extends AnyRequestSchema>(
        requestSchema: T,
        handler: GovernedRequestHandler<T>
    ): void {
        const method = requestSchema.shape.method.value;
        if (this.transportInternal) {
            // Check transportInternal state instead of registry's isConnected
            // to maintain the original behavior/error message context.
            throw new Error(`Cannot register request handler for ${method} after connect() has been called.`);
        }
        // Delegate registration to HandlerRegistry
        this.handlerRegistry.registerRequestHandler(requestSchema, handler); // <-- Delegate
        // Logging is now handled within HandlerRegistry
        // this.options.logger.debug(`Stored governed request handler for: ${method}`);
    }

    setNotificationHandler<T extends AnyNotificationSchema>(
        notificationSchema: T,
        handler: GovernedNotificationHandler<T>
    ): void {
        const method = notificationSchema.shape.method.value;
        if (this.transportInternal) {
             // Check transportInternal state instead of registry's isConnected
             // to maintain the original behavior/error message context.
            throw new Error(`Cannot register notification handler for ${method} after connect() has been called.`);
        }
        // Delegate registration to HandlerRegistry
        this.handlerRegistry.registerNotificationHandler(notificationSchema, handler); // <-- Delegate
        // Logging is now handled within HandlerRegistry
        // this.options.logger.debug(`Stored governed notification handler for: ${method}`);
    }


    // --- Wrapper Handler Creation and Registration ---

    /** Registers wrapper functions with the baseServer for all stored handlers. */
   /** Registers wrapper functions with the baseServer for all stored handlers. */
   private _registerBaseHandlers(): void {
    this.options.logger.debug("Registering base server handlers for governed methods...");

    // Define a base schema that allows optional params
    // WORKAROUND: Registering with a schema that explicitly includes `params: z.any().optional()`
    // appears necessary to prevent the current version of the base SDK Server
    // from stripping the params object before calling this wrapper handler.
    // This is related to an upstream issue/PR: https://github.com/modelcontextprotocol/typescript-sdk/pull/248
    // This workaround should be removed once the upstream fix is incorporated.
    const baseMethodSchema = (method: string) => z.object({
        jsonrpc: z.literal("2.0").optional(), // Allow flexibility from base SDK parsing
        id: z.union([z.string(), z.number()]).optional(), // Allow flexibility
        method: z.literal(method),
        params: z.any().optional() // <-- Explicitly allow optional params of any type
    }).passthrough(); // Allow other fields like _meta

    // Iterate over handlers from the registry
    this.handlerRegistry.getRequestHandlers().forEach((_handlerInfo, method) => { // <-- Use registry
        const handler = this._createPipelineRequestHandler(method);
        const schemaForBaseServer = baseMethodSchema(method);
        // Register with the base server using the more permissive schema
        this.baseServer.setRequestHandler(schemaForBaseServer as any, handler as any);
        this.options.logger.debug(`Registered base request handler for: ${method}`);
    });

    // Iterate over handlers from the registry
    this.handlerRegistry.getNotificationHandlers().forEach((_handlerInfo, method) => { // <-- Use registry
        const handler = this._createPipelineNotificationHandler(method);
         // Notifications also might have params, allow them minimally
         const notificationSchemaForBaseServer = z.object({
             jsonrpc: z.literal("2.0").optional(),
             method: z.literal(method),
             params: z.any().optional()
         }).passthrough();
        this.baseServer.setNotificationHandler(notificationSchemaForBaseServer as any, handler as any);
         this.options.logger.debug(`Registered base notification handler for: ${method}`);
    });

    this.options.logger.debug("Base handler registration complete.");
}

    /** Creates the wrapper that calls the request pipeline. */
    private _createPipelineRequestHandler(method: string): (req: JSONRPCRequest, baseExtra: BaseRequestHandlerExtra) => Promise<Result> {
        return async (request: JSONRPCRequest, baseExtra: BaseRequestHandlerExtra): Promise<Result> => {
            if (!this.pipeline) {
                this.options.logger.error(`Request received for ${method} but pipeline is not initialized. Server not connected?`);
                throw new McpError(McpErrorCode.InternalError, "GovernedServer pipeline not initialized.");
            }

            // --- Prepare Initial Context for Pipeline ---
            const eventId = generateEventId();
            const startTime = Date.now();
            const transportContext = buildTransportContext(this.transportInternal);
            const traceContext = this.options.traceContextProvider(transportContext, request);
            const baseLogger = this.options.logger;
            const requestLogger = baseLogger.child ? baseLogger.child({
                eventId, requestId: request.id, method: request.method,
                ...(traceContext?.traceId && { traceId: traceContext.traceId }),
                ...(traceContext?.spanId && { spanId: traceContext.spanId }),
                ...(transportContext.sessionId && { sessionId: transportContext.sessionId }),
            }) : baseLogger;

            const operationContext: OperationContext = {
                eventId,
                timestamp: new Date(startTime),
                transportContext,
                traceContext,
                logger: requestLogger,
                mcpMessage: request,
                serviceIdentifier: this.options.serviceIdentifier,
            };

            const auditRecord: Partial<AuditRecord> = {
                eventId,
                timestamp: new Date(startTime).toISOString(),
                serviceIdentifier: this.options.serviceIdentifier,
                transport: transportContext,
                mcp: { type: "request", method: request.method, id: request.id },
                trace: traceContext,
                identity: null,
            };

            // --- Execute Pipeline ---
            try {
                requestLogger.debug(`Pipeline request handler invoked for: ${method}`);
                // Delegate actual execution to the pipeline instance
                return await this.pipeline.executeRequestPipeline(request, baseExtra, operationContext, auditRecord);
            } catch (error) {
                // Catch errors from the pipeline execution itself and map for baseServer
                requestLogger.error(`Unhandled error in request pipeline execution for ${method}`, error);
                const payload = mapErrorToPayload(error, McpErrorCode.InternalError, "Internal governance pipeline error");
                throw new McpError(payload.code, payload.message, payload.data);
            }
        };
    }

    /** Creates the wrapper that calls the notification pipeline. */
    private _createPipelineNotificationHandler(method: string): (notif: JSONRPCNotification, baseExtra: BaseRequestHandlerExtra) => Promise<void> {
        return async (notification: JSONRPCNotification, baseExtra: BaseRequestHandlerExtra): Promise<void> => {
            if (!this.pipeline) {
                this.options.logger.error(`Notification received for ${method} but pipeline is not initialized. Server not connected?`);
                // Don't throw for notifications, just log
                return;
            }

            // --- Prepare Initial Context ---
            const eventId = generateEventId();
            const startTime = Date.now();
            const transportContext = buildTransportContext(this.transportInternal);
            const traceContext = this.options.traceContextProvider(transportContext, notification);
            const baseLogger = this.options.logger;
            const notificationLogger = baseLogger.child ? baseLogger.child({
                eventId, method: notification.method,
                ...(traceContext?.traceId && { traceId: traceContext.traceId }),
                ...(traceContext?.spanId && { spanId: traceContext.spanId }),
                ...(transportContext.sessionId && { sessionId: transportContext.sessionId }),
             }) : baseLogger;

            const operationContext: OperationContext = {
                eventId, timestamp: new Date(startTime), transportContext, traceContext,
                logger: notificationLogger, mcpMessage: notification, serviceIdentifier: this.options.serviceIdentifier,
            };
            const auditRecord: Partial<AuditRecord> = {
                eventId, timestamp: new Date(startTime).toISOString(), serviceIdentifier: this.options.serviceIdentifier,
                transport: transportContext, mcp: { type: "notification", method: notification.method },
                trace: traceContext, identity: null,
            };

            // --- Execute Pipeline ---
            try {
                notificationLogger.debug(`Pipeline notification handler invoked for: ${method}`);
                await this.pipeline.executeNotificationPipeline(notification, baseExtra, operationContext, auditRecord);
            } catch (error) {
                // Log pipeline errors, but don't throw
                notificationLogger.error(`Unhandled error in notification pipeline execution for ${method}`, error);
            }
        };
    }

} // End GovernedServer class