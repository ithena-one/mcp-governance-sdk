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
type AnyRequestSchema = ZodObject<{ method: ZodLiteral<string>;[key: string]: ZodTypeAny }>;
type AnyNotificationSchema = ZodObject<{ method: ZodLiteral<string>;[key: string]: ZodTypeAny }>;
type InferRequest<T extends AnyRequestSchema> = z.infer<T>;
type InferNotification<T extends AnyNotificationSchema> = z.infer<T>;

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
    private pipeline?: GovernancePipeline; // Instantiated after connect

    private requestHandlers: Map<string, { handler: GovernedRequestHandler<any>, schema: AnyRequestSchema }> = new Map();
    private notificationHandlers: Map<string, { handler: GovernedNotificationHandler<any>, schema: AnyNotificationSchema }> = new Map();

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

            // --- Instantiate Pipeline ---
            // Pass necessary options and handler maps to the pipeline instance
            this.pipeline = new GovernancePipeline(
                this.options,
                this.requestHandlers,
                this.notificationHandlers
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
            throw new Error(`Cannot register request handler for ${method} after connect() has been called.`);
        }
        if (this.requestHandlers.has(method)) {
            this.options.logger.warn(`Overwriting request handler for method: ${method}`);
        }
        this.requestHandlers.set(method, { handler: handler as any, schema: requestSchema });
        this.options.logger.debug(`Stored governed request handler for: ${method}`);
    }

    setNotificationHandler<T extends AnyNotificationSchema>(
        notificationSchema: T,
        handler: GovernedNotificationHandler<T>
    ): void {
        const method = notificationSchema.shape.method.value;
        if (this.transportInternal) {
            throw new Error(`Cannot register notification handler for ${method} after connect() has been called.`);
        }
        if (this.notificationHandlers.has(method)) {
            this.options.logger.warn(`Overwriting notification handler for method: ${method}`);
        }
        this.notificationHandlers.set(method, { handler: handler as any, schema: notificationSchema });
        this.options.logger.debug(`Stored governed notification handler for: ${method}`);
    }


    // --- Wrapper Handler Creation and Registration ---

    /** Registers wrapper functions with the baseServer for all stored handlers. */
    private _registerBaseHandlers(): void {
        this.options.logger.debug("Registering base server handlers for governed methods...");
        this.requestHandlers.forEach((handlerInfo, method) => {
            const handler = this._createPipelineRequestHandler(method);
            // Create a minimal schema for the base server that matches its expected type
            const baseSchema = z.object({ method: z.literal(method) });
            this.baseServer.setRequestHandler(baseSchema, handler as any);
        });
        this.notificationHandlers.forEach((handlerInfo, method) => {
            const handler = this._createPipelineNotificationHandler(method);
            // Create a minimal schema for the base server that matches its expected type
            const baseSchema = z.object({ method: z.literal(method) });
            this.baseServer.setNotificationHandler(baseSchema, handler as any);
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
            const notificationLogger = baseLogger.child ? baseLogger.child({ /* ... context ... */ }) : baseLogger;

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