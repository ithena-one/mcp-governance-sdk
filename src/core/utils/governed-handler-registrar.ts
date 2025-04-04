/* eslint-disable @typescript-eslint/no-explicit-any */
import {
    Result, JSONRPCRequest, JSONRPCNotification,
    McpError, ErrorCode as McpErrorCode,
} from '@modelcontextprotocol/sdk/types.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import { RequestHandlerExtra as BaseRequestHandlerExtra } from '@modelcontextprotocol/sdk/shared/protocol.js';
import { z } from 'zod';
import {
    OperationContext, AuditRecord, ProcessedGovernedServerOptions,
} from '../../types.js';
import { Logger } from '../../interfaces/logger.js';
import { GovernancePipeline } from '../governance-pipeline.js';
import { HandlerRegistry } from './handler-registry.js';
import { mapErrorToPayload } from '../../utils/error-mapper.js';
import { generateEventId, buildTransportContext } from '../../utils/helpers.js';

/**
 * Handles the registration of governed handlers with the base MCP Server.
 * Creates wrapper functions that execute the governance pipeline.
 */
export class GovernedHandlerRegistrar {
    private readonly baseServer: Server;
    private readonly pipeline: GovernancePipeline;
    private readonly handlerRegistry: HandlerRegistry;
    private readonly options: ProcessedGovernedServerOptions;
    private readonly logger: Logger;
    private transport: Transport | undefined; // Transport is needed for context building

    constructor(
        baseServer: Server,
        pipeline: GovernancePipeline,
        handlerRegistry: HandlerRegistry,
        options: ProcessedGovernedServerOptions,
        transport: Transport | undefined // Pass transport during construction or update later
    ) {
        this.baseServer = baseServer;
        this.pipeline = pipeline;
        this.handlerRegistry = handlerRegistry;
        this.options = options;
        this.logger = options.logger; // Get logger from options
        this.transport = transport;
    }

    // Method to update transport if it's set after construction (e.g., in GovernedServer.connect)
    public updateTransport(transport: Transport | undefined): void {
        this.transport = transport;
    }

    /** Registers wrapper functions with the baseServer for all stored handlers. */
    public registerBaseHandlers(): void {
        this.logger.debug("Registering base server handlers for governed methods...");

        const baseMethodSchema = (method: string) => z.object({
            jsonrpc: z.literal("2.0").optional(),
            id: z.union([z.string(), z.number()]).optional(),
            method: z.literal(method),
            params: z.any().optional()
        }).passthrough();

        this.handlerRegistry.getRequestHandlers().forEach((_handlerInfo, method) => {
            const handler = this._createPipelineRequestHandler(method);
            const schemaForBaseServer = baseMethodSchema(method);
            this.baseServer.setRequestHandler(schemaForBaseServer as any, handler as any);
            this.logger.debug(`Registered base request handler for: ${method}`);
        });

        this.handlerRegistry.getNotificationHandlers().forEach((_handlerInfo, method) => {
            const handler = this._createPipelineNotificationHandler(method);
            const notificationSchemaForBaseServer = z.object({
                jsonrpc: z.literal("2.0").optional(),
                method: z.literal(method),
                params: z.any().optional()
            }).passthrough();
            this.baseServer.setNotificationHandler(notificationSchemaForBaseServer as any, handler as any);
            this.logger.debug(`Registered base notification handler for: ${method}`);
        });

        this.logger.debug("Base handler registration complete.");
    }

    /** Creates the wrapper that calls the request pipeline. */
    private _createPipelineRequestHandler(method: string): (req: JSONRPCRequest, baseExtra: BaseRequestHandlerExtra) => Promise<Result> {
        return async (request: JSONRPCRequest, baseExtra: BaseRequestHandlerExtra): Promise<Result> => {
            if (!this.pipeline) { // Should not happen if constructed correctly
                this.logger.error(`Request received for ${method} but pipeline is not available in registrar.`);
                throw new McpError(McpErrorCode.InternalError, "Internal server error: pipeline unavailable.");
            }
             if (!this.transport) {
                this.logger.error(`Request received for ${method} but transport is not set in registrar.`);
                throw new McpError(McpErrorCode.InternalError, "Internal server error: transport unavailable.");
            }

            const eventId = generateEventId();
            const startTime = Date.now();
            // Use the transport held by the registrar instance
            const transportContext = buildTransportContext(this.transport);
            const traceContext = this.options.traceContextProvider(transportContext, request);
            const baseLogger = this.logger; // Use registrar's logger
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

            try {
                requestLogger.debug(`Pipeline request handler invoked for: ${method}`);
                return await this.pipeline.executeRequestPipeline(request, baseExtra, operationContext, auditRecord);
            } catch (error) {
                requestLogger.error(`Unhandled error in request pipeline execution for ${method}`, error);
                const payload = mapErrorToPayload(error, McpErrorCode.InternalError, "Internal governance pipeline error");
                throw new McpError(payload.code, payload.message, payload.data);
            }
        };
    }

    /** Creates the wrapper that calls the notification pipeline. */
    private _createPipelineNotificationHandler(method: string): (notif: JSONRPCNotification, baseExtra: BaseRequestHandlerExtra) => Promise<void> {
        return async (notification: JSONRPCNotification, baseExtra: BaseRequestHandlerExtra): Promise<void> => {
             if (!this.pipeline) { // Should not happen if constructed correctly
                this.logger.error(`Notification received for ${method} but pipeline is not available in registrar.`);
                return; // Don't throw for notifications
            }
             if (!this.transport) {
                this.logger.error(`Notification received for ${method} but transport is not set in registrar.`);
                 return; // Don't throw for notifications
            }

            const eventId = generateEventId();
            const startTime = Date.now();
             // Use the transport held by the registrar instance
            const transportContext = buildTransportContext(this.transport);
            const traceContext = this.options.traceContextProvider(transportContext, notification);
            const baseLogger = this.logger; // Use registrar's logger
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

            try {
                notificationLogger.debug(`Pipeline notification handler invoked for: ${method}`);
                await this.pipeline.executeNotificationPipeline(notification, baseExtra, operationContext, auditRecord);
            } catch (error) {
                notificationLogger.error(`Unhandled error in notification pipeline execution for ${method}`, error);
            }
        };
    }
} 