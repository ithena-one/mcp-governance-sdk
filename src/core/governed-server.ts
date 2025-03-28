/* eslint-disable no-console */
/* eslint-disable @typescript-eslint/no-explicit-any */
// src/core/governed-server.ts

import {
    Request,
    Notification,
    Result,
    JSONRPCRequest,
    JSONRPCNotification,
    JSONRPCResponse,
    JSONRPCError,
    ErrorCode as McpErrorCode,
    McpError,
} from '@modelcontextprotocol/sdk/types.js'; 

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import { RequestHandlerExtra as BaseRequestHandlerExtra } from '@modelcontextprotocol/sdk/shared/protocol.js';
import { ZodObject, ZodLiteral, z, ZodTypeAny } from 'zod';
import {
    UserIdentity,
    ResolvedCredentials,
    // TraceContext is used internally but not explicitly needed for this file's public API
    TransportContext,
    OperationContext,
    GovernedRequestHandlerExtra,
    GovernedNotificationHandlerExtra,
    AuditRecord
} from '../types.js'; // Assuming types.ts is in the same directory level
import { IdentityResolver } from '../interfaces/identity.js';
import { RoleStore, PermissionStore } from '../interfaces/rbac.js';
import { CredentialResolver } from '../interfaces/credentials.js';
import { AuditLogStore } from '../interfaces/audit.js';
import { Logger } from '../interfaces/logger.js'; // Import LogContext here
import { TraceContextProvider } from '../interfaces/tracing.js';
import { AuthenticationError, AuthorizationError, CredentialResolutionError, HandlerError, GovernanceError } from '../errors/index.js';
import { defaultLogger } from '../defaults/logger.js';
import { defaultAuditStore } from '../defaults/audit.js';
import { defaultTraceContextProvider } from '../defaults/tracing.js';
import { defaultDerivePermission } from '../defaults/permissions.js';
import { defaultSanitizeForAudit } from '../defaults/sanitization.js';
import { generateEventId, buildTransportContext } from '../utils/helpers.js';


// Define handler types using generics and z.infer
type AnyRequestSchema = ZodObject<{ method: ZodLiteral<string>; [key: string]: ZodTypeAny }>;
type AnyNotificationSchema = ZodObject<{ method: ZodLiteral<string>; [key: string]: ZodTypeAny }>;

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

// Define a type for the processed options with defaults applied where needed
// Note: Optional properties remain optional here. Checks happen during runtime.
type ProcessedGovernedServerOptions = Required<Pick<GovernedServerOptions,
    // Defaults provided for these
    | 'auditStore'
    | 'logger'
    | 'traceContextProvider'
    | 'enableRbac'
    | 'failOnCredentialResolutionError'
    | 'auditDeniedRequests'
    | 'auditNotifications'
    | 'derivePermission'
    | 'sanitizeForAudit'
>> & GovernedServerOptions; // Include all original optional properties


// Type alias for components with potential lifecycle methods
type LifecycleComponent =
    | IdentityResolver
    | RoleStore
    | PermissionStore
    | CredentialResolver
    | AuditLogStore
    | Logger;

/**
 * Wraps a base Model Context Protocol (MCP) Server to add a governance layer,
 * including identity resolution, role-based access control (RBAC), credential
 * resolution, structured logging, auditing, and trace context propagation.
 */
export class GovernedServer {
    private readonly baseServer: Server;
    // Store processed options (with defaults) but keep type as GovernedServerOptions for flexibility
    private readonly options: ProcessedGovernedServerOptions;
    private transportInternal?: Transport;

    // Store schema along with handler
    private requestHandlers: Map<string, { handler: GovernedRequestHandler<any>, schema: AnyRequestSchema }> = new Map();
    private notificationHandlers: Map<string, { handler: GovernedNotificationHandler<any>, schema: AnyNotificationSchema }> = new Map();

    // Keep track of components that were successfully initialized for cleanup on error/close
    private initializedComponents: LifecycleComponent[] = [];

    constructor(
        baseServer: Server,
        options: GovernedServerOptions = {}
    ) {
        this.baseServer = baseServer;

        // --- Apply Defaults ---
        this.options = {
            // Components that *might* be undefined
            identityResolver: options.identityResolver,
            roleStore: options.roleStore,
            permissionStore: options.permissionStore,
            credentialResolver: options.credentialResolver,
            postAuthorizationHook: options.postAuthorizationHook, // Keep optional
            serviceIdentifier: options.serviceIdentifier,       // Keep optional
            // Components/options with definite defaults
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

        // --- Validation ---
        if (this.options.enableRbac && (!this.options.roleStore || !this.options.permissionStore)) {
            throw new Error("RoleStore and PermissionStore must be provided when RBAC is enabled.");
        }
    }

    /**
     * Provides access to the underlying transport used by the base server, once connected.
     */
    public get transport(): Transport | undefined {
        return this.transportInternal;
    }

    /**
     * Initializes governance components, connects the server to a transport, and starts it.
     * This wraps the base server's message handling to inject the governance pipeline.
     * @param transport - The MCP transport to connect to.
     */
    async connect(transport: Transport): Promise<void> {
        if (this.transportInternal) {
            throw new Error("GovernedServer is already connected.");
        }
        const logger = this.options.logger; // Use configured logger
        logger.info("GovernedServer connecting...");
        this.transportInternal = transport;
        this.initializedComponents = []; // Reset on new connect attempt

        // Explicitly type the array to ensure filter works correctly
        const componentsToInitialize: Array<LifecycleComponent | undefined> = [
            this.options.logger, // Initialize logger first
            this.options.auditStore,
            this.options.identityResolver,
            this.options.roleStore,
            this.options.permissionStore,
            this.options.credentialResolver,
        ];

        try {
            // --- Initialize Governance Components ---
            logger.debug("Initializing governance components...");
            for (const component of componentsToInitialize) {
                // Check if component exists and has initialize method
                if (component?.initialize) {
                    const componentName = component.constructor?.name || 'Unnamed Component';
                    logger.debug(`Initializing ${componentName}...`);
                    await component.initialize();
                    this.initializedComponents.push(component); // Track successful initialization
                    logger.debug(`${componentName} initialized successfully.`);
                }
            }
            logger.info("All applicable governance components initialized successfully.");

            // --- Connect Base Server ---
            // Register our wrapper handlers *before* connecting the base server
            this._registerBaseHandlers();

            // Connect the base server, which will set up its own transport listeners
            await this.baseServer.connect(transport);

            // --- Setup Governed Close Handling ---
            const originalBaseOnClose = this.baseServer.onclose;
            this.baseServer.onclose = () => {
                // Use Promise.resolve().then() to avoid making onclose async directly
                Promise.resolve().then(async () => {
                    logger.info("Base server connection closed, running governed cleanup...");
                    await this._shutdownComponents(); // Call our component shutdown logic
                }).catch(err => {
                    logger.error("Error during component shutdown on close", err);
                }).finally(() => {
                    this.transportInternal = undefined; // Clear transport ref
                    this.initializedComponents = []; // Clear initialized list
                    originalBaseOnClose?.(); // Call original base onclose if it existed
                    logger.debug("Governed onclose handler finished.");
                });
            };

            logger.info("GovernedServer connected successfully.");

        } catch (error) {
            logger.error("GovernedServer connection failed during initialization", error);
            // --- Cleanup Partially Initialized Components ---
            logger.warn("Attempting to shut down components due to initialization failure...");
            // Use await here as shutdown needs to complete before throwing
            await this._shutdownComponents();
            this.transportInternal = undefined; // Ensure transport is cleared on failure
            this.initializedComponents = [];
            throw error; // Re-throw the original initialization error
        }
    }

    /**
     * Closes the connection and performs cleanup for the governance layer and base server.
     */
    async close(): Promise<void> {
        const logger = this.options.logger;
        if (!this.transportInternal) {
            logger.info("GovernedServer close called, but already closed or not connected.");
            return;
        }
        logger.info("GovernedServer closing...");

        // 1. Shutdown Governance Components (Await this)
        await this._shutdownComponents();

        // 2. Close Base Server (this should trigger the onclose handler we set)
        if (this.baseServer) {
             try {
                 await this.baseServer.close(); // Await base server close
             } catch (err) {
                 logger.error("Error during baseServer.close()", err);
                 // Ensure cleanup still happens even if baseServer.close fails
                 this.transportInternal = undefined;
                 this.initializedComponents = [];
             }
        } else {
            // If baseServer somehow doesn't exist, ensure state is cleared
             this.transportInternal = undefined;
             this.initializedComponents = [];
        }
        // Note: this.transportInternal and this.initializedComponents are cleared
        // by the onclose handler triggered by baseServer.close() if it succeeds.
        // If baseServer.close() fails, we clear them in the catch block above.

        logger.info("GovernedServer closed.");
    }

    /** Helper method to shut down initialized components gracefully. */
    private async _shutdownComponents(): Promise<void> {
        const logger = this.options.logger;
        if (this.initializedComponents.length === 0) {
            logger.debug("No initialized components to shut down.");
            return;
        }
        logger.debug(`Shutting down ${this.initializedComponents.length} governance components...`);

        // Create promises for shutdown operations
        const shutdownPromises = this.initializedComponents
            .filter(component => component.shutdown) // Only components with shutdown
            .map(component => {
                const componentName = component.constructor?.name || 'Unnamed Component';
                logger.debug(`Calling shutdown for ${componentName}...`);
                // Wrap in a promise to handle potential errors during the call itself
                return Promise.resolve()
                    .then(() => component.shutdown!()) // Call shutdown
                    .then(() => ({ status: 'fulfilled', componentName }))
                    .catch(err => ({ status: 'rejected', reason: err, componentName })); // Capture errors
            });

        // Await all shutdown attempts
        const results = await Promise.all(shutdownPromises);

        // Log outcomes
        results.forEach(result => {
            if (result.status === 'rejected') {
                logger.error(`Error during ${result.componentName}.shutdown()`, result.reason);
            } else {
                logger.debug(`${result.componentName} shut down successfully.`);
            }
        });

        this.initializedComponents = []; // Clear the list after attempting shutdown
        logger.debug("Component shutdown process complete.");
    }

    /**
     * Sends a notification through the underlying base server.
     * NOTE: Governance checks do NOT apply to outgoing notifications.
     * @param notification - The notification to send.
     */
    async notification(notification: Notification): Promise<void> {
        // Type assertion needed because base Server expects ServerNotification
        await this.baseServer.notification(notification as any);
    }

    // --- Handler Registration ---

    /** Internal method to register wrappers with the base server */
    private _registerBaseHandlers(): void {
        this.options.logger.debug("Registering base server handlers for governed methods...");
        // Register wrappers for all handlers defined via setRequestHandler
        this.requestHandlers.forEach((_handlerInfo, method) => {
            const handler = this._createPipelineRequestHandler(method);
            // Use a generic schema literal for registration with base server.
            // Base server validation isn't the primary goal here; our pipeline handles specific parsing.
            this.baseServer.setRequestHandler({ shape: { method: z.literal(method) } } as any, handler as any);
            this.options.logger.debug(`Registered base request handler wrapper for: ${method}`);
        });

        // Register wrappers for all handlers defined via setNotificationHandler
        this.notificationHandlers.forEach((_handlerInfo, method) => {
             const handler = this._createPipelineNotificationHandler(method);
             this.baseServer.setNotificationHandler({ shape: { method: z.literal(method) } } as any, handler as any);
             this.options.logger.debug(`Registered base notification handler wrapper for: ${method}`);
        });
         this.options.logger.debug("Base handler registration complete.");
    }

    /** Creates the actual handler passed to baseServer.setRequestHandler */
    private _createPipelineRequestHandler(method: string): (req: JSONRPCRequest, baseExtra: BaseRequestHandlerExtra) => Promise<Result> {
        // Return an async function that matches the base server's expected signature
        return async (request: JSONRPCRequest, baseExtra: BaseRequestHandlerExtra): Promise<Result> => {
            // This wrapper IS the entry point from the base server into our pipeline.
            try {
                // Execute the full pipeline logic, which eventually calls the user's governed handler.
                // The pipeline needs to return the result or throw an error that maps to a JSONRPCError.
                this.options.logger.debug(`Pipeline request handler invoked for: ${method}`);
                return await this._executeRequestPipeline(request, baseExtra);
            } catch (error) {
                // Catch errors that occurred *during* the pipeline execution
                // and map them to a structure the base server expects for its error response.
                const logger = this.options.logger;
                 logger.error(`Unhandled error in request pipeline wrapper for ${method}`, error);
                 // Re-map to McpError or a simple error object for the base server
                 const payload = this._mapErrorToPayload(error, McpErrorCode.InternalError, "Internal governance pipeline error");
                 // Base server expects a thrown error to construct JSONRPCError
                 throw new McpError(payload.code, payload.message, payload.data);
            }
        };
    }

     /** Creates the actual handler passed to baseServer.setNotificationHandler */
     private _createPipelineNotificationHandler(method: string): (notif: JSONRPCNotification, baseExtra: BaseRequestHandlerExtra) => Promise<void> {
         return async (notification: JSONRPCNotification, baseExtra: BaseRequestHandlerExtra): Promise<void> => {
             try {
                 this.options.logger.debug(`Pipeline notification handler invoked for: ${method}`);
                 // Execute the notification pipeline logic. It doesn't return anything.
                 await this._executeNotificationPipeline(notification, baseExtra);
             } catch (error) {
                 // Log errors during notification processing, but don't throw back to base server
                 // as notifications don't have responses.
                 const logger = this.options.logger;
                 logger.error(`Unhandled error in notification pipeline wrapper for ${method}`, error);
             }
         };
     }

    /**
     * Registers a handler for a specific MCP request method.
     * Must be called *before* `connect()`.
     * This handler will be executed *after* governance checks pass.
     * @param requestSchema - Zod schema defining the request structure.
     * @param handler - The async function to handle the request.
     */
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
          // Store the schema along with the handler
         this.requestHandlers.set(method, { handler: handler as any, schema: requestSchema });
         this.options.logger.debug(`Stored governed request handler for: ${method}`);
     }

    /**
     * Registers a handler for a specific MCP notification method.
     * Must be called *before* `connect()`.
     * @param notificationSchema - Zod schema defining the notification structure.
     * @param handler - The async function to handle the notification.
     */
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
           // Store schema with handler
           this.notificationHandlers.set(method, { handler: handler as any, schema: notificationSchema });
           this.options.logger.debug(`Stored governed notification handler for: ${method}`);
       }


    // --- Pipeline Execution Logic ---

    /** Executes the governance pipeline for a request. Called by the wrapper in baseServer. */
    private async _executeRequestPipeline(
        request: JSONRPCRequest,
        baseExtra: BaseRequestHandlerExtra // Extra provided by the base SDK's call
    ): Promise<Result> {
         const eventId = generateEventId();
         const startTime = Date.now();
         const transportContext = buildTransportContext(this.transportInternal); // Use internal ref
         const traceContext = this.options.traceContextProvider(transportContext, request);
         const baseLogger = this.options.logger;
         const requestLogger = baseLogger.child ? baseLogger.child({
             eventId,
             requestId: request.id,
             method: request.method,
             ...(traceContext?.traceId && { traceId: traceContext.traceId }),
             ...(traceContext?.spanId && { spanId: traceContext.spanId }),
             ...(transportContext.sessionId && { sessionId: transportContext.sessionId }),
         }) : baseLogger;

         const auditRecord: Partial<AuditRecord> = {
            eventId,
            timestamp: new Date(startTime).toISOString(), // Start time initially
            serviceIdentifier: this.options.serviceIdentifier,
            transport: transportContext,
            // Note: We sanitize params *before* adding to audit record in finally block
            mcp: { type: "request", method: request.method, id: request.id },
            trace: traceContext,
            identity: null, // Initialize
            // other fields populated later
        };

         let operationContext: OperationContext | undefined = undefined; // Initialize as undefined
         let outcomeStatus: AuditRecord['outcome']['status'] = 'failure'; // Default to failure
         let pipelineError: Error | unknown | null = null; // Error occurred during pipeline steps
         let handlerResult: Result | undefined = undefined; // Result from successful handler execution
         let finalErrorPayload: JSONRPCError['error'] | undefined = undefined; // Error payload to return

         try {
             requestLogger.debug("Executing request pipeline");
             operationContext = { // Now guaranteed to be defined within try block
                eventId,
                timestamp: new Date(startTime),
                transportContext,
                traceContext,
                logger: requestLogger,
                mcpMessage: request,
                serviceIdentifier: this.options.serviceIdentifier,
                // identity, roles, derivedPermission added later
             };

             // --- Steps 2-5: Identity, RBAC, PostAuth Hook, Credentials ---
             let identity: UserIdentity | null = null;
             let roles: string[] | undefined = undefined;
             let derivedPermission: string | null = null;
             let resolvedCredentials: ResolvedCredentials | null | undefined = null;

             // 2. Identity
             if (this.options.identityResolver) {
                try {
                    identity = await this.options.identityResolver.resolveIdentity(operationContext);
                    operationContext.identity = identity; // Update context
                    auditRecord.identity = identity; // Add raw identity to audit record
                    requestLogger.debug("Identity resolved", { identity: identity }); // Log potentially sensitive info carefully
                } catch (err) {
                    requestLogger.error("Identity resolution failed", err);
                    if (err instanceof GovernanceError) throw err;
                    throw new AuthenticationError("Identity resolution failed", err);
                }
             } else {
                 requestLogger.debug("No identity resolver configured");
             }

             // 3. RBAC
             const authzResult: AuditRecord['authorization'] = { decision: 'not_applicable' };
             auditRecord.authorization = authzResult;
             if (this.options.enableRbac) {
                 authzResult.decision = 'denied'; // Default to denied
                 if (identity === null) { // Use resolved identity directly
                     authzResult.denialReason = 'identity';
                     throw new AuthorizationError('identity', "Identity required for authorization but none was resolved.");
                 }
                 // Ensure stores exist (already checked in constructor, but good practice)
                 if (!this.options.roleStore || !this.options.permissionStore) {
                    throw new GovernanceError("RBAC enabled but RoleStore or PermissionStore is missing.");
                 }

                 derivedPermission = this.options.derivePermission(request, transportContext);
                 operationContext.derivedPermission = derivedPermission; // Update context
                 authzResult.permissionAttempted = derivedPermission;

                 if (derivedPermission === null) {
                     authzResult.decision = 'granted'; // Treat null permission as implicitly granted
                     requestLogger.debug("Permission check not applicable (null permission derived)", { method: request.method });
                 } else {
                     requestLogger.debug("Checking permission", { permission: derivedPermission });
                     try {
                         roles = await this.options.roleStore.getRoles(identity, operationContext);
                         operationContext.roles = roles; // Update context
                         authzResult.roles = roles;

                         let hasPermission = false;
                         if (roles.length > 0) {
                             const checks = await Promise.all(roles.map(role => this.options.permissionStore!.hasPermission(role, derivedPermission!, operationContext!)));
                             hasPermission = checks.some(allowed => allowed);
                         }

                         if (hasPermission) {
                             authzResult.decision = 'granted';
                             requestLogger.debug("Authorization granted", { permission: derivedPermission, roles });
                         } else {
                             authzResult.denialReason = 'permission';
                             requestLogger.warn("Authorization denied", { permission: derivedPermission, roles });
                             throw new AuthorizationError('permission', `Missing required permission: ${derivedPermission}`);
                         }
                     } catch (err) {
                         requestLogger.error("Error during role/permission check", err);
                          if (err instanceof AuthorizationError) throw err;
                          if (err instanceof GovernanceError) throw err;
                         throw new GovernanceError("Error checking permissions", err);
                     }
                 }
             } else {
                 requestLogger.debug("RBAC not enabled");
             }

             // 4. Post-Authorization Hook
             if (this.options.postAuthorizationHook && identity &&
                 (authzResult.decision === 'granted' || authzResult.decision === 'not_applicable')) {
                  try {
                      requestLogger.debug("Executing post-authorization hook");
                      await this.options.postAuthorizationHook(identity, operationContext);
                  } catch (err) {
                      requestLogger.error("Post-authorization hook failed", err);
                      if (err instanceof GovernanceError) throw err;
                      throw new GovernanceError("Post-authorization hook failed", err);
                  }
             }

             // 5. Credentials
             const credResult: AuditRecord['credentialResolution'] = { status: 'not_configured' };
             auditRecord.credentialResolution = credResult;
             if (this.options.credentialResolver) {
                 try {
                     requestLogger.debug("Resolving credentials");
                     // Pass identity ?? null to satisfy the interface type
                     resolvedCredentials = await this.options.credentialResolver.resolveCredentials(identity ?? null, operationContext);
                     credResult.status = 'success';
                     requestLogger.debug("Credentials resolved successfully");
                 } catch (err) {
                     credResult.status = 'failure';
                     credResult.error = { message: err instanceof Error ? err.message : String(err), type: err?.constructor?.name };
                     requestLogger.error("Credential resolution failed", err);
                     if (this.options.failOnCredentialResolutionError) {
                          if (err instanceof GovernanceError) throw err;
                         throw new CredentialResolutionError("Credential resolution failed", err);
                     } else {
                         requestLogger.warn("Credential resolution failed, but proceeding as failOnCredentialResolutionError=false");
                     }
                 }
             } else {
                 requestLogger.debug("No credential resolver configured");
             }

             // --- 6. Execute User Handler ---
             const handlerInfo = this.requestHandlers.get(request.method);
             if (!handlerInfo) {
                 requestLogger.warn(`Pipeline reached handler execution, but no governed handler found for ${request.method}.`);
                 throw new McpError(McpErrorCode.MethodNotFound, `Method not found: ${request.method}`);
             }
             const { handler: userHandler, schema: requestSchema } = handlerInfo;

             // Parse request using stored schema
             const parseResult = requestSchema.safeParse(request);
             if (!parseResult.success) {
                  requestLogger.error("Request failed schema validation before handler execution", parseResult.error);
                  throw new McpError(McpErrorCode.InvalidParams, `Invalid request structure: ${parseResult.error.message}`);
              }
             const parsedRequest = parseResult.data;

             const extra: GovernedRequestHandlerExtra = {
                 eventId,
                 logger: requestLogger,
                 identity: identity ?? null,
                 roles: roles,
                 resolvedCredentials: resolvedCredentials,
                 traceContext: traceContext,
                 transportContext: transportContext,
                 signal: baseExtra.signal, // Use signal from base server
                 sessionId: baseExtra.sessionId,
             };

             try {
                 handlerResult = await userHandler(parsedRequest, extra);
                 outcomeStatus = 'success';
                 requestLogger.info("Request processed successfully by user handler");
             } catch (handlerErr) {
                 pipelineError = handlerErr;
                 outcomeStatus = 'failure';
                 requestLogger.error("User handler execution failed", handlerErr);
                 // Error mapped later
             }

         } catch (pipelineErr) {
             pipelineError = pipelineErr;
             outcomeStatus = (pipelineErr instanceof AuthorizationError) ? 'denied' : 'failure';
             requestLogger.warn(`Governance pipeline failed for request ${request.id}`, pipelineErr);
             // Error mapped later
         } finally {
              // --- 7/8. Build Audit Record & Outcome ---
             const endTime = Date.now();
             auditRecord.timestamp = new Date(endTime).toISOString(); // Use end time
             auditRecord.durationMs = endTime - startTime;

              let responseForAudit: JSONRPCResponse | JSONRPCError | null = null;
              if (outcomeStatus === 'success' && handlerResult !== undefined) {
                  responseForAudit = { jsonrpc: "2.0", id: request.id, result: handlerResult };
              } else if (pipelineError) {
                  // Use the error caught during pipeline execution
                  finalErrorPayload = this._mapErrorToPayload(pipelineError, McpErrorCode.InternalError, "Pipeline error");
                  responseForAudit = { jsonrpc: "2.0", id: request.id, error: finalErrorPayload };
              }
              // Ensure auditRecord.mcp.params are added *after* potential sanitization
              // Note: Sanitization happens *before* logging the record.
              const finalAuditRecord = {
                  ...auditRecord,
                  // Add params here just before sanitization/logging
                   mcp: { ...auditRecord.mcp, params: request.params },
                   outcome: this._buildAuditOutcome(outcomeStatus, pipelineError, responseForAudit)
                };


              // --- Auditing ---
              const shouldAudit = outcomeStatus !== 'denied' || this.options.auditDeniedRequests;
              if (shouldAudit) {
                  try {
                      const sanitizedRecord = this.options.sanitizeForAudit(finalAuditRecord as AuditRecord);
                      requestLogger.debug("Logging audit record", { eventId: finalAuditRecord.eventId });
                      this.options.auditStore.log(sanitizedRecord as AuditRecord).catch(auditErr => {
                          // Log the audit logging error itself using the request logger
                           requestLogger.error("Audit logging failed", auditErr, { auditEventId: finalAuditRecord.eventId });
                      });
                  } catch (sanitizeErr) {
                      requestLogger.error("Audit record sanitization failed", sanitizeErr, { auditEventId: finalAuditRecord.eventId });
                      console.error(`!!! FAILED TO SANITIZE AUDIT RECORD ${finalAuditRecord.eventId} !!!`, finalAuditRecord, sanitizeErr);
                  }
              } else {
                  requestLogger.debug("Skipping audit log based on configuration", { eventId: finalAuditRecord.eventId, outcome: outcomeStatus });
              }
         }

         // --- Return Result or Throw Mapped Error for Base Server ---
         if (outcomeStatus === 'success' && handlerResult !== undefined) {
             return handlerResult;
         } else {
              // If finalErrorPayload wasn't built (should have been in finally), build it now.
              if (!finalErrorPayload) {
                  finalErrorPayload = this._mapErrorToPayload(pipelineError ?? new Error("Unknown processing error"), McpErrorCode.InternalError, "Unknown error");
              }
              // Throw the specific error type baseServer expects
             throw new McpError(finalErrorPayload.code, finalErrorPayload.message, finalErrorPayload.data);
         }
     }

     /** Executes the governance pipeline for a notification. Called by the wrapper in baseServer. */
     private async _executeNotificationPipeline(
         notification: JSONRPCNotification,
         baseExtra: BaseRequestHandlerExtra // Contains signal from base server
     ): Promise<void> {
         const eventId = generateEventId();
         const startTime = Date.now();
         const transportContext = buildTransportContext(this.transportInternal);
         const traceContext = this.options.traceContextProvider(transportContext, notification);
         const baseLogger = this.options.logger;
         const notificationLogger = baseLogger.child ? baseLogger.child({
             eventId,
             method: notification.method,
             ...(traceContext?.traceId && { traceId: traceContext.traceId }),
             ...(traceContext?.spanId && { spanId: traceContext.spanId }),
             ...(transportContext.sessionId && { sessionId: transportContext.sessionId }),
         }) : baseLogger;

         const auditRecord: Partial<AuditRecord> = {
            eventId,
            timestamp: new Date(startTime).toISOString(),
            serviceIdentifier: this.options.serviceIdentifier,
            transport: transportContext,
            mcp: { type: "notification", method: notification.method }, // Params added later
            trace: traceContext,
            identity: null, // Initialize
         };

         let operationContext: OperationContext | undefined = undefined; // Init as undefined
         let outcomeStatus: AuditRecord['outcome']['status'] = 'failure';
         let handlerError: Error | unknown | null = null;

         try {
             notificationLogger.debug("Executing notification pipeline");
             operationContext = { // Now defined within try block
                eventId,
                timestamp: new Date(startTime),
                transportContext,
                traceContext,
                logger: notificationLogger,
                mcpMessage: notification,
                serviceIdentifier: this.options.serviceIdentifier,
            };


             // --- Identity (Optional) ---
             let identity: UserIdentity | null = null;
             if (this.options.identityResolver) {
                 try {
                     identity = await this.options.identityResolver.resolveIdentity(operationContext);
                     operationContext.identity = identity; // Update context
                     auditRecord.identity = identity;
                     notificationLogger.debug("Identity resolved for notification", { identity });
                 } catch (err) {
                     notificationLogger.warn("Identity resolution failed during notification processing", err);
                     // Don't fail pipeline for identity error on notification
                 }
             }

             // --- Execute User Handler ---
             const handlerInfo = this.notificationHandlers.get(notification.method);
             if (handlerInfo) {
                 const { handler: userHandler, schema: notificationSchema } = handlerInfo;

                 const parseResult = notificationSchema.safeParse(notification);
                  if (!parseResult.success) {
                      // Log error but don't stop pipeline for invalid notification structure? Or should we?
                      // Let's log and proceed, treating it like no handler was found.
                      notificationLogger.error("Notification failed schema validation", parseResult.error);
                      outcomeStatus = 'success'; // Treat as success (ignored)
                  } else {
                     const parsedNotification = parseResult.data;
                     const extra: GovernedNotificationHandlerExtra = {
                         eventId,
                         logger: notificationLogger,
                         identity: identity ?? null,
                         traceContext: traceContext,
                         transportContext: transportContext,
                         signal: baseExtra.signal, // Use signal from base server
                         sessionId: baseExtra.sessionId,
                     };
                     try {
                         await userHandler(parsedNotification, extra);
                         outcomeStatus = 'success';
                         notificationLogger.info("Notification processed successfully by user handler");
                     } catch (err) {
                         handlerError = err;
                         outcomeStatus = 'failure';
                         notificationLogger.error("User notification handler failed", err);
                     }
                  }
             } else {
                 outcomeStatus = 'success'; // Ignored notification is considered success
                 notificationLogger.debug(`No governed handler for notification ${notification.method}, ignoring.`);
             }
         } catch (err) {
             // Catch errors from context setup (less likely now context is built first)
             handlerError = err;
             outcomeStatus = 'failure';
             notificationLogger.error("Error in notification pipeline setup", err);
         } finally {
             // --- Auditing ---
             const endTime = Date.now();
             auditRecord.timestamp = new Date(endTime).toISOString();
             auditRecord.durationMs = endTime - startTime;
             // Add params before sanitization/logging
             const finalAuditRecord = {
                 ...auditRecord,
                 mcp: { ...auditRecord.mcp, params: notification.params },
                 outcome: {
                     status: outcomeStatus,
                     ...(handlerError && { error: this._mapErrorToAuditPayload(handlerError) })
                 }
            };


             if (this.options.auditNotifications) {
                  try {
                     const sanitizedRecord = this.options.sanitizeForAudit(finalAuditRecord as AuditRecord);
                     notificationLogger.debug("Logging notification audit record", { eventId: finalAuditRecord.eventId });
                     this.options.auditStore.log(sanitizedRecord as AuditRecord).catch(auditErr => {
                          notificationLogger.error("Audit logging failed for notification", auditErr, { auditEventId: finalAuditRecord.eventId });
                     });
                 } catch (sanitizeErr) {
                     notificationLogger.error("Audit record sanitization failed for notification", sanitizeErr, { auditEventId: finalAuditRecord.eventId });
                     console.error(`!!! FAILED TO SANITIZE NOTIFICATION AUDIT RECORD ${finalAuditRecord.eventId} !!!`, finalAuditRecord, sanitizeErr);
                 }
             } else {
                 notificationLogger.debug("Skipping notification audit log based on configuration", { eventId: finalAuditRecord.eventId });
             }
         }
         // No return or throw needed for notifications
     }

    // --- Helper Methods ---

    /** Maps internal errors to JSON-RPC error payloads */
    private _mapErrorToPayload(error: Error | unknown, defaultCode: number, defaultMessage: string): JSONRPCError['error'] {
        if (error instanceof McpError) {
            return { code: error.code, message: error.message, data: error.data };
        }
        // Order matters: check specific governance errors before generic GovernanceError
        if (error instanceof AuthorizationError) {
            // Using a custom code like -32000 (reserved range) or a specific app code
            return { code: -32001, message: error.message, data: { reason: error.reason, details: error.details } };
        }
        if (error instanceof AuthenticationError) {
            return { code: McpErrorCode.InvalidRequest, message: error.message, data: error.details };
        }
         if (error instanceof CredentialResolutionError) {
             return { code: McpErrorCode.InternalError, message: error.message, data: error.details };
         }
         if (error instanceof HandlerError) {
             return { code: McpErrorCode.InternalError, message: "Handler execution failed", data: error.details };
         }
         if (error instanceof GovernanceError) { // Catch-all for other governance errors
             return { code: McpErrorCode.InternalError, message: error.message, data: error.details };
         }
        if (error instanceof Error) {
            return { code: defaultCode, message: error.message || defaultMessage };
        }
        // Handle non-Error types
        return { code: defaultCode, message: defaultMessage, data: String(error) };
    }

    /** Maps internal errors to the AuditRecord['outcome']['error'] structure */
     private _mapErrorToAuditPayload(error: Error | unknown): NonNullable<AuditRecord['outcome']['error']> {
         if (error instanceof GovernanceError) { // Includes AuthN/AuthZ/Creds/Handler errors
             return {
                 type: error.constructor.name,
                 message: error.message,
                 // Safely spread details only if it's an object
                 details: typeof error.details === 'object' && error.details !== null ? { ...error.details } : error.details,
                 ...(error instanceof AuthorizationError && { code: "ACCESS_DENIED", reason: error.reason }),
                 ...(error instanceof AuthenticationError && { code: "AUTHENTICATION_FAILED" }),
                 ...(error instanceof CredentialResolutionError && { code: "CREDENTIAL_RESOLUTION_FAILED" }),
                 ...(error instanceof HandlerError && { code: "HANDLER_EXECUTION_FAILED" }),
             };
         }
         if (error instanceof McpError) {
             return {
                 type: "McpError",
                 message: error.message,
                 code: error.code,
                 details: error.data,
             };
         }
         if (error instanceof Error) {
             return {
                 type: error.constructor.name,
                 message: error.message,
                 // Optionally include sanitized stack in details?
                 // details: { stack: error.stack?.split('\n').slice(0, 5).join('\n') } // Example: limited stack
             };
         }
         return {
             type: "UnknownError",
             message: String(error),
         };
     }

     /** Builds the complete AuditRecord['outcome'] object */
     private _buildAuditOutcome(
         status: AuditRecord['outcome']['status'],
         error: Error | unknown | null,
         response: JSONRPCResponse | JSONRPCError | null
     ): AuditRecord['outcome'] {
         const outcome: AuditRecord['outcome'] = { status };
         if ((status === 'failure' || status === 'denied') && error) { // Ensure error exists
             outcome.error = this._mapErrorToAuditPayload(error);
         }
         if (response) {
             outcome.mcpResponse = {};
             if ('result' in response && response.result !== undefined) { // Check result exists
                 outcome.mcpResponse.result = response.result; // Will be sanitized later
             } else if ('error' in response && response.error) { // Check error exists
                 outcome.mcpResponse.error = response.error; // Raw JSON-RPC error
             }
         }
         return outcome;
     }

} // End GovernedServer class