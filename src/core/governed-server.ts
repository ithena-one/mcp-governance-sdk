/* eslint-disable @typescript-eslint/no-explicit-any */
// src/core/governed-server.ts

import {
    Notification
    ,
} from '@modelcontextprotocol/sdk/types.js';

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import {
    
    AnyRequestSchema, AnyNotificationSchema,
    GovernedRequestHandler, GovernedNotificationHandler,
    GovernedServerOptions, ProcessedGovernedServerOptions
} from '../types.js';
import { GovernancePipeline } from './governance-pipeline.js'; // Import the new class
import { LifecycleManager } from './utils/lifecycle-manager.js'; // Import the new class
import { HandlerRegistry } from './utils/handler-registry.js'; // <-- Import HandlerRegistry
import { defaultLogger } from '../defaults/logger.js';
import { defaultAuditStore } from '../defaults/audit.js';
import { defaultTraceContextProvider } from '../defaults/tracing.js';
import { defaultDerivePermission } from '../defaults/permissions.js';
import { defaultSanitizeForAudit } from '../defaults/sanitization.js';
import { GovernedHandlerRegistrar } from './utils/governed-handler-registrar.js'; // <-- Import new class



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
    private handlerRegistrar?: GovernedHandlerRegistrar; // <-- Add registrar instance

    constructor(
        baseServer: Server,
        options: GovernedServerOptions = {}
    ) {
        this.baseServer = baseServer;
        this.options = {
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
                this.handlerRegistry.getRequestHandlers(),     
                this.handlerRegistry.getNotificationHandlers() 
            );

            // --- Instantiate and use the Handler Registrar ---
            this.handlerRegistrar = new GovernedHandlerRegistrar(
                this.baseServer,
                this.pipeline,      // Pass the pipeline instance
                this.handlerRegistry,
                this.options,
                this.transportInternal // Pass the transport
            );
            this.handlerRegistrar.registerBaseHandlers(); // <-- Use the registrar

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
                    this.pipeline = undefined;
                    this.handlerRegistrar = undefined; 
                    this.handlerRegistry.setDisconnected(); 
                    originalBaseOnClose?.();
                    logger.debug("Governed onclose handler finished.");
                });
            };

            logger.info("GovernedServer connected successfully.");

        } catch (error) {
            logger.error("GovernedServer connection failed during initialization", error);
            await this.lifecycleManager.shutdown(); 
            this.transportInternal = undefined;
            this.pipeline = undefined;
            this.handlerRegistrar = undefined;
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

        await this.lifecycleManager.shutdown();

        this.handlerRegistry.setDisconnected(); 

        if (this.baseServer) {
            try {
                await this.baseServer.close();
            } catch (err) {
                logger.error("Error during baseServer.close()", err);
                this.transportInternal = undefined;
                this.pipeline = undefined;
                this.handlerRegistrar = undefined; 
            }
        } else {
            this.transportInternal = undefined;
            this.pipeline = undefined;
            this.handlerRegistrar = undefined; 
            this.handlerRegistry.setDisconnected(); 
        }

        logger.info("GovernedServer closed.");
    }

    async notification(notification: Notification): Promise<void> {
        // Ensure baseServer exists before attempting to send notification
        if (!this.baseServer) {
            this.options.logger.warn("Cannot send notification, base server is not initialized.");
            return; 
        }

        await this.baseServer.notification(notification as any);
    }

    // --- Handler Registration ---
    setRequestHandler<T extends AnyRequestSchema>(
        requestSchema: T,
        handler: GovernedRequestHandler<T>
    ): void {
        const method = requestSchema.shape.method.value;
        if (this.transportInternal) {

            throw new Error(`Cannot register request handler for ${method} after connect() has been called.`);
        }
        this.handlerRegistry.registerRequestHandler(requestSchema, handler); // <-- Delegate

    }

    setNotificationHandler<T extends AnyNotificationSchema>(
        notificationSchema: T,
        handler: GovernedNotificationHandler<T>
    ): void {
        const method = notificationSchema.shape.method.value;
        if (this.transportInternal) {

            throw new Error(`Cannot register notification handler for ${method} after connect() has been called.`);
        }
        // Delegate registration to HandlerRegistry
        this.handlerRegistry.registerNotificationHandler(notificationSchema, handler); // <-- Delegate

    }


} 