Okay, let's implement the **Enhanced Configuration & Initialization** feature.

This involves:

1.  Adding optional `initialize(): Promise<void>` and `shutdown(): Promise<void>` methods to the relevant governance component interfaces.
2.  Updating `GovernedServer`'s `connect` method to call `initialize` on components before connecting the base server.
3.  Updating `GovernedServer`'s `close` method to call `shutdown` on components before closing the base server.
4.  Ensuring error handling during initialization and shutdown is robust.

---

**1. Update Interfaces (`src/interfaces/`)**

Add the optional `initialize` and `shutdown` methods.

**`src/interfaces/identity.ts`**
```typescript
import { UserIdentity, OperationContext } from '../types.js';

/**
 * Interface for resolving the identity of the caller based on the operation context.
 */
export interface IdentityResolver {
    /**
     * Optional asynchronous initialization logic. Called once during GovernedServer.connect().
     * Useful for setting up connections, caches, etc.
     * Should throw an error if initialization fails.
     */
    initialize?(): Promise<void>;

    /**
     * Resolves the identity of the caller based on transport/message context.
     * @param opCtx - The context of the current operation.
     * @returns The resolved UserIdentity, or null if identity cannot be determined.
     * @throws {AuthenticationError} or other specific error on failure if necessary.
     */
    resolveIdentity(opCtx: OperationContext): Promise<UserIdentity | null>;

    /**
     * Optional asynchronous cleanup logic. Called once during GovernedServer.close().
     * Useful for closing connections, flushing buffers, etc.
     * Should handle errors gracefully and not prevent shutdown.
     */
    shutdown?(): Promise<void>;
}
```

**`src/interfaces/rbac.ts`**
```typescript
import { UserIdentity, OperationContext } from '../types.js';

/**
 * Interface for retrieving the roles associated with a user identity.
 */
export interface RoleStore {
    /** Optional initialization logic. */
    initialize?(): Promise<void>;
    /** Retrieves the roles for a given identity. */
    getRoles(identity: UserIdentity, opCtx: OperationContext): Promise<string[]>;
    /** Optional cleanup logic. */
    shutdown?(): Promise<void>;
}

/**
 * Interface for checking if a role possesses a specific permission.
 */
export interface PermissionStore {
    /** Optional initialization logic. */
    initialize?(): Promise<void>;
    /** Checks if a given role has the specified permission. */
    hasPermission(role: string, permission: string, opCtx: OperationContext): Promise<boolean>;
    /** Optional cleanup logic. */
    shutdown?(): Promise<void>;
}
```

**`src/interfaces/credentials.ts`**
```typescript
import { UserIdentity, ResolvedCredentials, OperationContext } from '../types.js';

/**
 * Interface for resolving credentials (secrets, API keys, etc.) needed for an operation.
 */
export interface CredentialResolver {
    /** Optional initialization logic. */
    initialize?(): Promise<void>;
    /** Resolves credentials needed for the operation. */
    resolveCredentials(identity: UserIdentity | null, opCtx: OperationContext): Promise<ResolvedCredentials | null | undefined>;
    /** Optional cleanup logic. */
    shutdown?(): Promise<void>;
}
```

**`src/interfaces/audit.ts`** (Already has `shutdown`, add `initialize`)
```typescript
import { AuditRecord } from '../types.js';

/**
 * Interface for logging audit records.
 */
export interface AuditLogStore {
    /** Optional initialization logic. */
    initialize?(): Promise<void>;
    /** Logs a completed audit record. */
    log(record: AuditRecord): Promise<void>;
    /** Optional: Performs graceful shutdown operations. */
    shutdown?: () => Promise<void>;
}
```

**`src/interfaces/logger.ts`** (Add lifecycle methods, though less common)
```typescript
/** Log severity levels. */
export type LogLevel = "debug" | "info" | "warn" | "error";

/** Context object for structured logging. */
export type LogContext = Record<string, any>;

/**
 * Interface for a structured logger used within the SDK and passed to handlers.
 */
export interface Logger {
    /** Optional initialization logic (e.g., setting up remote transport). */
    initialize?(): Promise<void>;

    /** Logs a debug message. */
    debug(message: string, context?: LogContext): void;
    /** Logs an informational message. */
    info(message: string, context?: LogContext): void;
    /** Logs a warning message. */
    warn(message: string, context?: LogContext): void;
    /** Logs an error message, optionally including an Error object. */
    error(message: string, error?: Error | unknown, context?: LogContext): void;

    /** Optional: Creates a child logger. */
    child?: (bindings: LogContext) => Logger;

    /** Optional cleanup logic (e.g., flushing buffers). */
    shutdown?(): Promise<void>;
}
```

---

**2. Update `GovernedServer` (`src/core/governed-server.ts`)**

Modify `connect` and `close` methods.

```typescript
// src/core/governed-server.ts
// ... (imports remain largely the same)
import { AuditLogStore } from '../interfaces/audit.js';
import { CredentialResolver } from '../interfaces/credentials.js';
import { IdentityResolver } from '../interfaces/identity.js';
import { Logger } from '../interfaces/logger.js';
import { PermissionStore, RoleStore } from '../interfaces/rbac.js';
// ... (other imports)

// Type alias for components with potential lifecycle methods
type LifecycleComponent =
    | IdentityResolver
    | RoleStore
    | PermissionStore
    | CredentialResolver
    | AuditLogStore
    | Logger;


export class GovernedServer {
    private readonly baseServer: Server;
    private readonly options: Required<GovernedServerOptions>;
    private transportInternal?: Transport;

    private requestHandlers: Map<string, GovernedRequestHandler<any>> = new Map();
    private notificationHandlers: Map<string, GovernedNotificationHandler<any>> = new Map();

    // Keep track of components that were successfully initialized for cleanup on error/close
    private initializedComponents: LifecycleComponent[] = [];

    constructor(
        baseServer: Server,
        options: GovernedServerOptions = {}
    ) {
        this.baseServer = baseServer;
        this.options = {
            // ... (same default assignments as before) ...
            identityResolver: options.identityResolver,
            roleStore: options.roleStore,
            permissionStore: options.permissionStore,
            credentialResolver: options.credentialResolver,
            auditStore: options.auditStore ?? defaultAuditStore,
            logger: options.logger ?? defaultLogger,
            traceContextProvider: options.traceContextProvider ?? defaultTraceContextProvider,
            enableRbac: options.enableRbac ?? false,
            failOnCredentialResolutionError: options.failOnCredentialResolutionError ?? true,
            auditDeniedRequests: options.auditDeniedRequests ?? true,
            auditNotifications: options.auditNotifications ?? false,
            derivePermission: options.derivePermission ?? defaultDerivePermission,
            sanitizeForAudit: options.sanitizeForAudit ?? defaultSanitizeForAudit,
            postAuthorizationHook: options.postAuthorizationHook,
            serviceIdentifier: options.serviceIdentifier,
        };

        if (this.options.enableRbac && (!this.options.roleStore || !this.options.permissionStore)) {
            throw new Error("RoleStore and PermissionStore must be provided when RBAC is enabled.");
        }
    }

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

        const componentsToInitialize: LifecycleComponent[] = [
            this.options.logger, // Initialize logger first
            this.options.auditStore,
            this.options.identityResolver,
            this.options.roleStore,
            this.options.permissionStore,
            this.options.credentialResolver,
        ].filter((c): c is LifecycleComponent => c !== undefined); // Filter out undefined options

        try {
            // --- Initialize Governance Components ---
            logger.debug("Initializing governance components...");
            for (const component of componentsToInitialize) {
                if (component.initialize) {
                    const componentName = component.constructor?.name || 'Unnamed Component';
                    logger.debug(`Initializing ${componentName}...`);
                    await component.initialize();
                    this.initializedComponents.push(component); // Track successful initialization
                    logger.debug(`${componentName} initialized successfully.`);
                }
            }
            logger.info("All governance components initialized successfully.");

            // --- Connect Base Server ---
            // Register our wrapper handlers *before* connecting the base server
            this._registerBaseHandlers();

            // Connect the base server, which will set up its own transport listeners
            await this.baseServer.connect(transport);

            // --- Setup Governed Close Handling ---
            const originalBaseOnClose = this.baseServer.onclose;
            this.baseServer.onclose = () => {
                logger.info("Base server connection closed, running governed cleanup...");
                // Use Promise.resolve to avoid making onclose itself async if not needed
                Promise.resolve().then(async () => {
                     await this._shutdownComponents(); // Call our component shutdown logic
                 }).catch(err => {
                     logger.error("Error during component shutdown on close", err);
                 }).finally(() => {
                     this.transportInternal = undefined; // Clear transport ref
                     this.initializedComponents = []; // Clear initialized list
                     originalBaseOnClose?.(); // Call original base onclose if it existed
                 });
            };

            logger.info("GovernedServer connected successfully.");

        } catch (error) {
            logger.error("GovernedServer connection failed during initialization", error);
            // --- Cleanup Partially Initialized Components ---
            logger.warn("Attempting to shut down components due to initialization failure...");
            await this._shutdownComponents(); // Attempt graceful shutdown of what was started
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

        // 1. Shutdown Governance Components
        await this._shutdownComponents();

        // 2. Close Base Server (this should trigger the onclose handler we set)
        if (this.baseServer) {
             try {
                 await this.baseServer.close();
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

        const shutdownPromises = this.initializedComponents
            .filter(component => component.shutdown) // Only components with shutdown
            .map(component => {
                const componentName = component.constructor?.name || 'Unnamed Component';
                logger.debug(`Calling shutdown for ${componentName}...`);
                // Wrap in a promise that resolves with potential error info
                return component.shutdown!()
                     .then(() => ({ status: 'fulfilled', componentName }))
                     .catch(err => ({ status: 'rejected', reason: err, componentName }));
            });

        const results = await Promise.allSettled(shutdownPromises); // Use allSettled to ensure all attempt

        results.forEach(result => {
            if (result.status === 'rejected') {
                // Log error from the wrapped promise's catch
                 const errorInfo = result.reason as { reason: any; componentName: string };
                logger.error(`Error during ${errorInfo.componentName}.shutdown()`, errorInfo.reason);
            } else if (result.value.status === 'rejected') {
                 // Log error from the component's shutdown method itself
                 const errorInfo = result.value as { reason: any; componentName: string };
                logger.error(`Error during ${errorInfo.componentName}.shutdown()`, errorInfo.reason);
             } else {
                 logger.debug(`${result.value.componentName} shut down successfully.`);
             }
        });

        this.initializedComponents = []; // Clear the list after attempting shutdown
        logger.debug("Component shutdown process complete.");
    }


    // --- Handler Registration ---

    /** Internal method to register wrappers with the base server */
    private _registerBaseHandlers(): void {
        // Register wrappers for all handlers defined via setRequestHandler
        for (const method of this.requestHandlers.keys()) {
            // Find the schema used during registration (requires modification to store schema)
            // For now, use a generic registration - this limits base server's ability
            // to validate incoming request structure before hitting our pipeline.
            // A better approach would be to pass the schema here.
            const handler = this._createPipelineRequestHandler(method);
            this.baseServer.setRequestHandler({ shape: { method: z.literal(method) } } as any, handler as any);
        }

        // Register wrappers for all handlers defined via setNotificationHandler
        for (const method of this.notificationHandlers.keys()) {
             const handler = this._createPipelineNotificationHandler(method);
             this.baseServer.setNotificationHandler({ shape: { method: z.literal(method) } } as any, handler as any);
        }
    }


    /** Creates the actual handler passed to baseServer.setRequestHandler */
    private _createPipelineRequestHandler(method: string): (req: JSONRPCRequest, baseExtra: BaseRequestHandlerExtra) => Promise<Result> {
        return async (request: JSONRPCRequest, baseExtra: BaseRequestHandlerExtra): Promise<Result> => {
            // This wrapper IS the entry point from the base server into our pipeline.
            try {
                // Execute the full pipeline logic, which eventually calls the user's governed handler.
                // The pipeline needs to return the result or throw an error that maps to a JSONRPCError.
                return await this._executeRequestPipeline(request, baseExtra);
            } catch (error) {
                // Catch errors that occurred *during* the pipeline execution
                // and map them to a structure the base server expects for its error response.
                const logger = this.options.logger;
                 logger.error(`Unhandled error in request pipeline for ${method}`, error);
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
                 // Execute the notification pipeline logic. It doesn't return anything.
                 await this._executeNotificationPipeline(notification, baseExtra);
             } catch (error) {
                 // Log errors during notification processing, but don't throw back to base server
                 // as notifications don't have responses.
                 const logger = this.options.logger;
                 logger.error(`Unhandled error in notification pipeline for ${method}`, error);
             }
         };
     }

    // Updated setRequestHandler to store schema for parsing later
     setRequestHandler<T extends AnyRequestSchema>(
         requestSchema: T,
         handler: GovernedRequestHandler<T>
     ): void {
         const method = requestSchema.shape.method.value;
         if (this.requestHandlers.has(method)) {
             this.options.logger.warn(`Overwriting request handler for method: ${method}`);
         }
          // Store the schema along with the handler
         this.requestHandlers.set(method, { handler: handler as any, schema: requestSchema } as any);

          // Register wrapper with base server ONLY if not already connected
          // If already connected, base server handlers can't be changed easily.
          // This implies registration must happen *before* connect. Add check?
          if (this.transportInternal) {
              this.options.logger.warn(`Cannot dynamically register base handler for ${method} after connect. Ensure handlers are set before connecting.`);
              // Or should we try to update? Base SDK doesn't support removing/updating handlers.
           }
           // Base handler registration is moved to _registerBaseHandlers called during connect.

         this.options.logger.debug(`Stored governed request handler for: ${method}`);
     }

      // Update internal storage type
      private requestHandlers: Map<string, { handler: GovernedRequestHandler<any>, schema: AnyRequestSchema }> = new Map();


       // Updated setNotificationHandler similarly
       setNotificationHandler<T extends AnyNotificationSchema>(
           notificationSchema: T,
           handler: GovernedNotificationHandler<T>
       ): void {
           const method = notificationSchema.shape.method.value;
           if (this.notificationHandlers.has(method)) {
               this.options.logger.warn(`Overwriting notification handler for method: ${method}`);
           }
           this.notificationHandlers.set(method, { handler: handler as any, schema: notificationSchema } as any);

           if (this.transportInternal) {
              this.options.logger.warn(`Cannot dynamically register base handler for notification ${method} after connect.`);
           }
           // Base handler registration moved to _registerBaseHandlers.

           this.options.logger.debug(`Stored governed notification handler for: ${method}`);
       }
       // Update internal storage type
       private notificationHandlers: Map<string, { handler: GovernedNotificationHandler<any>, schema: AnyNotificationSchema }> = new Map();


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

         const auditRecord: Partial<AuditRecord> = { /* ... */ }; // Initialize as before
         let operationContext: OperationContext | undefined;
         let outcomeStatus: AuditRecord['outcome']['status'] = 'failure';
         let pipelineError: Error | unknown | null = null; // Error occurred during pipeline steps
         let handlerResult: Result | undefined; // Result from successful handler execution
         let finalErrorPayload: JSONRPCError['error'] | undefined; // Error payload to return

         try {
             requestLogger.debug("Executing request pipeline");
             operationContext = { /* ... build context ... */
                eventId,
                timestamp: new Date(startTime),
                transportContext,
                traceContext,
                logger: requestLogger,
                mcpMessage: request,
                serviceIdentifier: this.options.serviceIdentifier,
             };
             auditRecord.identity = null; // Initialize

             // --- Steps 2-5: Identity, RBAC, PostAuth Hook, Credentials ---
             // ... (Implement steps as detailed in previous TS spec response) ...
             // ... Wrap each step in try/catch, log errors, potentially throw specific GovernanceErrors ...
             // ... Populate auditRecord.authorization, auditRecord.credentialResolution ...

              // 2. Identity
             if (this.options.identityResolver) {
                 operationContext.identity = await this.options.identityResolver.resolveIdentity(operationContext);
                 auditRecord.identity = operationContext.identity;
             }
              // 3. RBAC
             const authzResult: AuditRecord['authorization'] = { decision: 'not_applicable' };
             auditRecord.authorization = authzResult;
             if (this.options.enableRbac) {
                 authzResult.decision = 'denied';
                 if (!operationContext.identity) { /* throw AuthorizationError */ throw new AuthorizationError('identity'); }
                 const permission = this.options.derivePermission(request, transportContext);
                 if (permission !== null) {
                     const roles = await this.options.roleStore!.getRoles(operationContext.identity, operationContext);
                     let hasPermission = false;
                     if (roles.length > 0) { /* check permissions */
                        const checks = await Promise.all(roles.map(role => this.options.permissionStore!.hasPermission(role, permission, operationContext!)));
                        hasPermission = checks.some(allowed => allowed);
                     }
                     if (hasPermission) { authzResult.decision = 'granted'; }
                     else { /* throw AuthorizationError */ throw new AuthorizationError('permission'); }
                 } else {
                      authzResult.decision = 'granted'; // No permission needed
                  }
             }

              // 4. Post-Auth Hook (omitted for brevity - add try/catch)

              // 5. Credentials
             const credResult: AuditRecord['credentialResolution'] = { status: 'not_configured' };
             auditRecord.credentialResolution = credResult;
             let resolvedCredentials = null;
             if (this.options.credentialResolver) {
                 try {
                     resolvedCredentials = await this.options.credentialResolver.resolveCredentials(operationContext.identity, operationContext);
                     credResult.status = 'success';
                 } catch (err) {
                     credResult.status = 'failure'; /* ... record error ... */
                     if (this.options.failOnCredentialResolutionError) { /* throw CredentialResolutionError */ throw new CredentialResolutionError();}
                 }
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
                 identity: operationContext.identity ?? null,
                 roles: operationContext.roles,
                 resolvedCredentials,
                 traceContext,
                 transportContext,
                 signal: baseExtra.signal, // Use the signal from the base server!
                 sessionId: baseExtra.sessionId,
             };

             try {
                 handlerResult = await userHandler(parsedRequest, extra);
                 outcomeStatus = 'success';
                 requestLogger.info("Request processed successfully by user handler");
             } catch (handlerErr) {
                 pipelineError = handlerErr; // Store original handler error
                 outcomeStatus = 'failure';
                 requestLogger.error("User handler execution failed", handlerErr);
                 // Error will be mapped later for the response
             }

         } catch (pipelineErr) {
             pipelineError = pipelineErr; // Store original governance error
             outcomeStatus = (pipelineErr instanceof AuthorizationError) ? 'denied' : 'failure';
             requestLogger.warn(`Governance pipeline failed for request ${request.id}`, pipelineErr);
             // Error will be mapped later for the response
         } finally {
              // --- 7/8. Build Audit Record & Outcome ---
             const endTime = Date.now();
             auditRecord.timestamp = new Date(endTime).toISOString();
             auditRecord.durationMs = endTime - startTime;

              let responseForAudit: JSONRPCResponse | JSONRPCError | null = null;
              if (outcomeStatus === 'success' && handlerResult !== undefined) {
                  responseForAudit = { jsonrpc: "2.0", id: request.id, result: handlerResult };
              } else if (pipelineError) {
                  finalErrorPayload = this._mapErrorToPayload(pipelineError, McpErrorCode.InternalError, "Pipeline error");
                  responseForAudit = { jsonrpc: "2.0", id: request.id, error: finalErrorPayload };
              }
             auditRecord.outcome = this._buildAuditOutcome(outcomeStatus, pipelineError, responseForAudit);


              // --- Auditing ---
              const shouldAudit = outcomeStatus !== 'denied' || this.options.auditDeniedRequests;
              if (shouldAudit) {
                  try {
                      const sanitizedRecord = this.options.sanitizeForAudit(auditRecord as AuditRecord);
                      this.options.auditStore.log(sanitizedRecord as AuditRecord).catch(/* log audit log error */);
                  } catch (sanitizeErr) { /* log sanitization error */ }
              }
         }

         // --- Return Result or Throw Mapped Error for Base Server ---
         if (outcomeStatus === 'success' && handlerResult !== undefined) {
             return handlerResult;
         } else {
              // If finalErrorPayload wasn't built in finally (e.g., success but undefined result?), build it now.
              if (!finalErrorPayload) {
                  finalErrorPayload = this._mapErrorToPayload(pipelineError ?? new Error("Unknown processing error"), McpErrorCode.InternalError, "Unknown error");
              }
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
         const notificationLogger = baseLogger.child ? baseLogger.child({ /* ... context ... */ }) : baseLogger;

         const auditRecord: Partial<AuditRecord> = { /* ... */ };
         let operationContext: OperationContext | undefined;
         let outcomeStatus: AuditRecord['outcome']['status'] = 'failure';
         let handlerError: Error | unknown | null = null;

         try {
             notificationLogger.debug("Executing notification pipeline");
             operationContext = { /* ... build context ... */ };

             // --- Identity (Optional) ---
             // ... (resolve identity, store in auditRecord) ...

             // --- Execute User Handler ---
             const handlerInfo = this.notificationHandlers.get(notification.method);
             if (handlerInfo) {
                 const { handler: userHandler, schema: notificationSchema } = handlerInfo;
                 const parseResult = notificationSchema.safeParse(notification);
                 if (!parseResult.success) { throw new Error(`Invalid notification structure: ${parseResult.error.message}`); } // Log this better
                 const parsedNotification = parseResult.data;

                 const extra: GovernedNotificationHandlerExtra = {
                     eventId,
                     logger: notificationLogger,
                     identity: operationContext.identity ?? null,
                     traceContext,
                     transportContext,
                     signal: baseExtra.signal, // Use signal from base server
                     sessionId: baseExtra.sessionId,
                 };
                 try {
                     await userHandler(parsedNotification, extra);
                     outcomeStatus = 'success';
                 } catch (err) {
                     handlerError = err;
                     outcomeStatus = 'failure';
                     notificationLogger.error("User notification handler failed", err);
                 }
             } else {
                 outcomeStatus = 'success'; // Ignored notification
                 notificationLogger.debug(`No governed handler for notification ${notification.method}, ignoring.`);
             }
         } catch (err) {
             handlerError = err;
             outcomeStatus = 'failure';
             notificationLogger.error("Error in notification pipeline setup", err);
         } finally {
             // --- Auditing ---
             const endTime = Date.now();
             auditRecord.timestamp = new Date(endTime).toISOString();
             auditRecord.durationMs = endTime - startTime;
             auditRecord.outcome = {
                 status: outcomeStatus,
                 ...(handlerError && { error: this._mapErrorToAuditPayload(handlerError) })
             };

             if (this.options.auditNotifications) {
                  try {
                      const sanitizedRecord = this.options.sanitizeForAudit(auditRecord as AuditRecord);
                      this.options.auditStore.log(sanitizedRecord as AuditRecord).catch(/* log audit log error */);
                  } catch (sanitizeErr) { /* log sanitization error */ }
             }
         }
         // No return or throw needed for notifications
     }

    // --- _mapErrorToPayload, _mapErrorToAuditPayload, _buildAuditOutcome helpers ---
    // ... (Implement these helpers as defined in the previous TS spec response) ...
    private _mapErrorToPayload(error: Error | unknown, defaultCode: number, defaultMessage: string): JSONRPCError['error'] {
        // ... implementation from previous response ...
        if (error instanceof McpError) return { code: error.code, message: error.message, data: error.data };
        if (error instanceof AuthorizationError) return { code: -32000, message: error.message, data: { reason: error.reason, details: error.details } };
        if (error instanceof AuthenticationError) return { code: McpErrorCode.InvalidRequest, message: error.message, data: error.details };
        if (error instanceof CredentialResolutionError) return { code: McpErrorCode.InternalError, message: error.message, data: error.details };
        if (error instanceof HandlerError) return { code: McpErrorCode.InternalError, message: "Handler execution failed", data: error.details };
        if (error instanceof GovernanceError) return { code: McpErrorCode.InternalError, message: error.message, data: error.details };
        if (error instanceof Error) return { code: defaultCode, message: error.message || defaultMessage };
        return { code: defaultCode, message: defaultMessage };
    }

     private _mapErrorToAuditPayload(error: Error | unknown): NonNullable<AuditRecord['outcome']['error']> {
        // ... implementation from previous response ...
        if (error instanceof GovernanceError) return { type: error.constructor.name, message: error.message, details: error.details, ...(error instanceof AuthorizationError && { code: "ACCESS_DENIED" })};
        if (error instanceof McpError) return { type: "McpError", message: error.message, code: error.code, details: error.data };
        if (error instanceof Error) return { type: error.constructor.name, message: error.message };
        return { type: "UnknownError", message: String(error) };
     }

     private _buildAuditOutcome(
         status: AuditRecord['outcome']['status'],
         error: Error | unknown | null,
         response: JSONRPCResponse | JSONRPCError | null
     ): AuditRecord['outcome'] {
        // ... implementation from previous response ...
         const outcome: AuditRecord['outcome'] = { status };
         if (status === 'failure' || status === 'denied') outcome.error = this._mapErrorToAuditPayload(error);
         if (response) {
             outcome.mcpResponse = {};
             if ('result' in response) outcome.mcpResponse.result = response.result;
             else if ('error' in response) outcome.mcpResponse.error = response.error;
         }
         return outcome;
     }

} // End GovernedServer class
```

---

**3. Update Defaults (`src/defaults/`)**

The default implementations (`ConsoleLogger`, `NoOpAuditLogStore`, etc.) generally don't *need* `initialize` or `shutdown` for their basic operation. You *could* add empty implementations for completeness, but it's not strictly necessary since the methods are optional.

**Example (Optional addition to `ConsoleLogger`)**
```typescript
// src/defaults/logger.ts
export class ConsoleLogger implements Logger {
    // ... existing code ...

    async initialize(): Promise<void> {
        // console.log("ConsoleLogger initialized."); // Optional: log if needed
    }

    async shutdown(): Promise<void> {
        // console.log("ConsoleLogger shutting down."); // Optional: log if needed
        // No specific action needed for console
    }
    // ... rest of the class ...
}
```

---

**Summary of Changes:**

*   **Interfaces:** Added optional `initialize?(): Promise<void>` and `shutdown?(): Promise<void>` to `IdentityResolver`, `RoleStore`, `PermissionStore`, `CredentialResolver`, `AuditLogStore`, and `Logger`.
*   **`GovernedServer.connect()`:**
    *   Iterates through configured components and awaits `component.initialize()` if present.
    *   Tracks successfully initialized components.
    *   If initialization fails, it attempts to `shutdown` successfully initialized components before re-throwing the error.
    *   Registers wrapper handlers with the base server *before* connecting it.
    *   Sets up an `onclose` handler on the base server to trigger component shutdown.
*   **`GovernedServer.close()`:**
    *   Calls `_shutdownComponents()` helper first.
    *   Then calls `baseServer.close()`.
*   **`_shutdownComponents()`:** New private helper using `Promise.allSettled` to safely attempt shutdown on all initialized components, logging errors without stopping the overall shutdown.
*   **Handler Registration (`setRequestHandler`, `setNotificationHandler`):** Modified to store the schema alongside the handler and defer registering the *wrapper* with the base server until `connect` is called (via `_registerBaseHandlers`). This ensures handlers are set up before the base server starts listening.
*   **Pipeline Entry (`_createPipelineRequestHandler`, `_createPipelineNotificationHandler`):** These wrappers are now the entry points called by the base server, which then invoke the main pipeline logic (`_executeRequestPipeline`, `_executeNotificationPipeline`).
*   **Pipeline Execution (`_execute...Pipeline`):**
    *   Takes the `baseExtra` (including the crucial `signal`) from the base server call.
    *   Passes the correct `signal` to the `GovernedRequestHandlerExtra`/`GovernedNotificationHandlerExtra`.
    *   Parses the request/notification using the stored schema before calling the user handler.
    *   Returns the result or throws a mapped `McpError` for the base server to handle.

This implementation integrates the lifecycle management directly into the `connect` and `close` phases of the `GovernedServer`.