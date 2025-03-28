/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable no-console */
/* eslint-disable @typescript-eslint/no-explicit-any */
import {
    JSONRPCRequest,
    JSONRPCNotification,
    JSONRPCResponse,
    JSONRPCError,
    Result,
    ErrorCode as McpErrorCode,
    McpError,
} from '@modelcontextprotocol/sdk/types.js';
import { RequestHandlerExtra as BaseRequestHandlerExtra } from '@modelcontextprotocol/sdk/shared/protocol.js';

import { ZodObject, ZodLiteral, ZodTypeAny, z } from 'zod';
import {
    UserIdentity, ResolvedCredentials, TransportContext, OperationContext,
    GovernedRequestHandlerExtra, GovernedNotificationHandlerExtra, AuditRecord
} from '../types.js';
import { GovernedServerOptions } from './governed-server.js'; 
import { AuthenticationError, AuthorizationError, CredentialResolutionError, HandlerError, GovernanceError } from '../errors/index.js';
import { mapErrorToAuditPayload } from '../utils/error-mapper.js';

// Re-define handler map types locally or import if exported
type AnyRequestSchema = ZodObject<{ method: ZodLiteral<string>; [key: string]: ZodTypeAny }>;
type AnyNotificationSchema = ZodObject<{ method: ZodLiteral<string>; [key: string]: ZodTypeAny }>;
type InferRequest<T extends AnyRequestSchema> = z.infer<T>;
type InferNotification<T extends AnyNotificationSchema> = z.infer<T>;
type RequestHandlerMap = Map<string, { handler: (req: any, extra: GovernedRequestHandlerExtra) => Promise<Result>, schema: AnyRequestSchema }>;
type NotificationHandlerMap = Map<string, { handler: (notif: any, extra: GovernedNotificationHandlerExtra) => Promise<void>, schema: AnyNotificationSchema }>;

interface ErrorData {
    type?: string;
    reason?: string;
    originalError?: unknown;
}

/**
 * Contains the logic for executing the governance pipeline for requests and notifications.
 */
export class GovernancePipeline {
    // Make options readonly after constructor
    private readonly options: GovernedServerOptions;
    private readonly requestHandlers: RequestHandlerMap;
    private readonly notificationHandlers: NotificationHandlerMap;

    constructor(
        options: GovernedServerOptions, // Use Processed type here
        requestHandlers: RequestHandlerMap,
        notificationHandlers: NotificationHandlerMap
    ) {
        this.options = options;
        this.requestHandlers = requestHandlers;
        this.notificationHandlers = notificationHandlers;
    }

    /** Executes the governance pipeline for a request. */
    async executeRequestPipeline(
        request: JSONRPCRequest,
        baseExtra: BaseRequestHandlerExtra,
        operationContext: OperationContext,
        auditRecord: Partial<AuditRecord>
    ): Promise<Result> {
        const logger = operationContext.logger;
        const startTime = operationContext.timestamp.getTime();
        let outcomeStatus: AuditRecord['outcome']['status'] = 'failure';
        let pipelineError: Error | unknown | null = null;
        let handlerResult: Result | undefined = undefined;

        try {
            logger.debug("Executing request pipeline steps...");

            let identity: UserIdentity | null = null;
            let roles: string[] | undefined = undefined;
            let derivedPermission: string | null = null;
            let resolvedCredentials: ResolvedCredentials | null | undefined = undefined;

            // Initialize audit record structure
            auditRecord.outcome = { status: 'failure' };
            auditRecord.authorization = { decision: 'not_applicable' };
            auditRecord.credentialResolution = { status: 'not_configured' };

            // 2. Identity Resolution
            if (this.options.identityResolver) {
                try {
                    identity = await this.options.identityResolver.resolveIdentity(operationContext);
                    operationContext.identity = identity;
                    auditRecord.identity = identity;
                    logger.debug("Identity resolved", { hasIdentity: !!identity });
                } catch (err) {
                    logger.error("Identity resolution failed", { error: err });
                    const authError = err instanceof Error 
                        ? new AuthenticationError(err.message)
                        : new AuthenticationError("Identity resolution failed");
                    throw new McpError(McpErrorCode.InvalidRequest, authError.message, {
                        type: 'AuthenticationError',
                        originalError: err
                    });
                }
            } else {
                 logger.debug("No identity resolver configured");
            }

            // 3. RBAC
            if (this.options.enableRbac) {
                auditRecord.authorization!.decision = 'denied';
                if (identity === null) {
                    auditRecord.authorization!.denialReason = 'identity';
                    const authzError = new AuthorizationError('identity', "Identity required for authorization but none was resolved.");
                    throw new McpError(-32001, authzError.message, {
                        type: 'AuthorizationError',
                        reason: 'identity'
                    });
                }
                if (!this.options.roleStore || !this.options.permissionStore) {
                    const govError = new GovernanceError("RBAC enabled but RoleStore or PermissionStore is missing.");
                    throw new McpError(McpErrorCode.InternalError, govError.message, {
                        type: 'GovernanceError'
                    });
                }
                derivedPermission = this.options.derivePermission?.(request, operationContext.transportContext) ?? null;
                operationContext.derivedPermission = derivedPermission;
                auditRecord.authorization!.permissionAttempted = derivedPermission;

                if (derivedPermission === null) {
                    auditRecord.authorization!.decision = 'granted';
                    logger.debug("Permission check not applicable (null permission derived)");
                } else {
                    try {
                        roles = await this.options.roleStore.getRoles(identity, operationContext);
                        operationContext.roles = roles;
                        auditRecord.authorization!.roles = roles;
                        let hasPermission = false;
                        if (roles && roles.length > 0) {
                            const checks = await Promise.all(roles.map(role => 
                                this.options.permissionStore!.hasPermission(role, derivedPermission!, operationContext)
                            ));
                            hasPermission = checks.some(allowed => allowed);
                        }
                        if (!hasPermission) {
                            auditRecord.authorization!.denialReason = 'permission';
                            const authzError = new AuthorizationError('permission', `Missing required permission: ${derivedPermission}`);
                            throw new McpError(-32001, authzError.message, {
                                type: 'AuthorizationError',
                                reason: 'permission'
                            });
                        }
                        auditRecord.authorization!.decision = 'granted';
                        logger.debug("Authorization granted", { permission: derivedPermission, roles });
                    } catch (err) {
                        if (err instanceof McpError) throw err;
                        const govError = new GovernanceError("Error checking permissions", { originalError: err });
                        throw new McpError(McpErrorCode.InternalError, govError.message, {
                            type: 'GovernanceError',
                            originalError: err
                        });
                    }
                }
            }

            // 4. Post-Authorization Hook
            if (this.options.postAuthorizationHook && identity &&
                (auditRecord.authorization!.decision === 'granted' || auditRecord.authorization!.decision === 'not_applicable')) {
                try {
                    logger.debug("Executing post-authorization hook");
                    await this.options.postAuthorizationHook(identity, operationContext);
                } catch (err) {
                    const govError = new GovernanceError("Post-authorization hook failed", { originalError: err });
                    throw new McpError(McpErrorCode.InternalError, govError.message, {
                        type: 'GovernanceError',
                        originalError: err
                    });
                }
            }

            // 5. Credentials
            if (this.options.credentialResolver) {
                try {
                    logger.debug("Resolving credentials");
                    resolvedCredentials = await this.options.credentialResolver.resolveCredentials(identity ?? null, operationContext);
                    auditRecord.credentialResolution = { status: 'success' };
                    logger.debug("Credentials resolution successful");
                } catch (err) {
                    auditRecord.credentialResolution = {
                        status: 'failure',
                        error: { 
                            message: err instanceof Error ? err.message : String(err), 
                            type: err?.constructor?.name 
                        }
                    };
                    logger.error("Credential resolution failed", { error: err });
                    if (this.options.failOnCredentialResolutionError) {
                        const credError = err instanceof Error 
                            ? new CredentialResolutionError(err.message)
                            : new CredentialResolutionError("Credential resolution failed");
                        throw new McpError(McpErrorCode.InternalError, credError.message, {
                            type: 'CredentialResolutionError',
                            originalError: err
                        });
                    } else {
                        logger.warn("Credential resolution failed, but proceeding as failOnCredentialResolutionError=false");
                    }
                }
            } else {
                logger.debug("No credential resolver configured");
            }

            // 6. Execute User Handler
            const handlerInfo = this.requestHandlers.get(request.method);
            if (!handlerInfo) {
                 logger.warn(`No governed handler registered for method: ${request.method}`);
                throw new McpError(McpErrorCode.MethodNotFound, `Method not found: ${request.method}`);
            }
            const { handler: userHandler, schema: requestSchema } = handlerInfo;
            const parseResult = requestSchema.safeParse(request);
            if (!parseResult.success) {
                 logger.error("Request failed schema validation before handler execution", { error: parseResult.error, method: request.method });
                 throw new McpError(McpErrorCode.InvalidParams, `Invalid request structure: ${parseResult.error.message}`);
            }
            const parsedRequest = parseResult.data;
            const extra: GovernedRequestHandlerExtra = {
                signal: baseExtra.signal,
                sessionId: baseExtra.sessionId,
                eventId: operationContext.eventId,
                logger: operationContext.logger,
                identity: identity ?? null,
                roles: roles,
                resolvedCredentials: resolvedCredentials ?? undefined,
                traceContext: operationContext.traceContext,
                transportContext: operationContext.transportContext,
            };

            try {
                 logger.debug("Executing user request handler");
                handlerResult = await userHandler(parsedRequest, extra);
                outcomeStatus = 'success';
                auditRecord.outcome!.status = 'success';
                auditRecord.outcome!.mcpResponse = { result: handlerResult };
                logger.debug("User request handler completed successfully");
            } catch (handlerErr) {
                const handlerError = new HandlerError("Handler execution failed", handlerErr);
                throw new McpError(McpErrorCode.InternalError, handlerError.message, {
                    type: 'HandlerError',
                    originalError: handlerErr
                });
            }

            return handlerResult;

        } catch (pipeErr) {
            pipelineError = pipeErr;
            if (pipeErr instanceof AuthorizationError) {
                outcomeStatus = 'denied';
            } else if (pipeErr instanceof AuthenticationError || 
                       pipeErr instanceof CredentialResolutionError ||
                       pipeErr instanceof HandlerError ||
                       pipeErr instanceof GovernanceError) {
                outcomeStatus = 'failure';
            } else if (pipeErr instanceof McpError) {
                const errorData = pipeErr.data as ErrorData | undefined;
                outcomeStatus = (errorData?.type === 'AuthorizationError') ? 'denied' : 'failure';
            } else {
                outcomeStatus = 'failure';
            }
            auditRecord.outcome!.status = outcomeStatus;
            throw pipeErr;
        } finally {
            // --- Build Audit Record Outcome ---
            const endTime = Date.now();
            const durationMs = endTime - startTime;
            auditRecord.timestamp = new Date(endTime).toISOString();
            auditRecord.durationMs = durationMs;

            if (pipelineError) {
                auditRecord.outcome!.error = mapErrorToAuditPayload(pipelineError);
            }

            // Ensure MCP fields are present
            auditRecord.mcp = { 
                type: 'request' as const,
                method: request.method,
                id: request.id,
                params: request.params 
            };

            // --- Auditing ---
            const shouldAudit = outcomeStatus !== 'denied' || this.options.auditDeniedRequests;
            if (shouldAudit && this.options.auditStore && !auditRecord.logged) {
                // At this point, auditRecord should have all required fields
                const baseRecord = auditRecord as AuditRecord;
                let sanitizedRecord: AuditRecord = baseRecord;
                let sanitizationSucceeded = true;
                
                // Try to sanitize the record if a sanitizer is configured
                if (this.options.sanitizeForAudit) {
                    try {
                        const sanitized = this.options.sanitizeForAudit(baseRecord);
                        if (sanitized) {
                            sanitizedRecord = sanitized as AuditRecord;
                        }
                    } catch (sanitizeErr) {
                        sanitizationSucceeded = false;
                        logger.error("Audit record sanitization failed", { error: sanitizeErr, auditEventId: baseRecord.eventId });
                        console.error(`!!! FAILED TO SANITIZE AUDIT RECORD ${baseRecord.eventId} !!!`, baseRecord, sanitizeErr);
                    }
                }
                
                // Log the record (sanitized or original) if sanitization succeeded or no sanitizer configured
                if (sanitizationSucceeded || !this.options.sanitizeForAudit) {
                    logger.debug("Logging audit record", { eventId: baseRecord.eventId });
                    try {
                        await this.options.auditStore.log(sanitizedRecord);
                        auditRecord.logged = true;
                    } catch (auditErr) {
                        logger.error("Audit logging failed", { error: auditErr, auditEventId: baseRecord.eventId });
                    }
                }
            } else {
                logger.debug("Skipping audit log based on configuration", { eventId: auditRecord.eventId, outcome: outcomeStatus });
            }
        }
    }

     /** Executes the governance pipeline for a notification. */
     async executeNotificationPipeline(
         notification: JSONRPCNotification,
         baseExtra: BaseRequestHandlerExtra,
         operationContext: OperationContext, // Assume pre-built context passed in
         auditRecord: Partial<AuditRecord> // Assume pre-built base record passed in
     ): Promise<void> {
         const logger = operationContext.logger;
         const startTime = operationContext.timestamp.getTime(); // Get start time from context
         let outcomeStatus: AuditRecord['outcome']['status'] = 'failure';
         let handlerError: Error | unknown | null = null;
         let identity: UserIdentity | null = null;

         try {
             logger.debug("Executing notification pipeline steps...");

             // 1. Identity Resolution (Optional)
             if (this.options.identityResolver) {
                 try {
                     identity = await this.options.identityResolver.resolveIdentity(operationContext);
                     operationContext.identity = identity; // Update context for potential handler use
                     auditRecord.identity = identity;
                     logger.debug("Identity resolved for notification", { hasIdentity: !!identity });
                 } catch (err) {
                     logger.warn("Identity resolution failed during notification processing", { error: err });
                     // Do not fail pipeline
                 }
             }

             // 2. Execute User Handler
             const handlerInfo = this.notificationHandlers.get(notification.method);
             if (handlerInfo) {
                 const { handler: userHandler, schema: notificationSchema } = handlerInfo;
                 const parseResult = notificationSchema.safeParse(notification);
                 if (!parseResult.success) {
                     logger.error("Notification failed schema validation", { error: parseResult.error, method: notification.method });
                     outcomeStatus = 'success'; // Treat as ignored
                 } else {
                     const parsedNotification = parseResult.data;
                     const extra: GovernedNotificationHandlerExtra = {
                         // Spread baseExtra carefully
                         signal: baseExtra.signal,
                         sessionId: baseExtra.sessionId,
                         eventId: operationContext.eventId,
                         logger: operationContext.logger,
                         identity: identity ?? null,
                         traceContext: operationContext.traceContext,
                         transportContext: operationContext.transportContext,
                     };
                     try {
                         logger.debug("Executing user notification handler");
                         await userHandler(parsedNotification, extra);
                         outcomeStatus = 'success';
                         logger.debug("User notification handler completed successfully");
                     } catch (err) {
                         handlerError = new HandlerError("Notification handler failed", err);
                         outcomeStatus = 'failure';
                         logger.error("User notification handler failed", { error: err });
                     }
                 }
             } else {
                 outcomeStatus = 'success'; // Ignored
                 logger.debug(`No governed handler for notification ${notification.method}, ignoring.`);
             }
         } catch (err) { // Catch errors from context setup phase (less likely)
             handlerError = err;
             outcomeStatus = 'failure';
             logger.error("Error in notification pipeline setup", { error: err });
         } finally {
              // --- Auditing ---
             const endTime = Date.now();
             const durationMs = endTime - startTime;
             auditRecord.timestamp = new Date(endTime).toISOString();
             auditRecord.durationMs = durationMs;

             // Add params just before audit logging
             const finalAuditRecord: Partial<AuditRecord> = {
                 ...auditRecord,
                 // Ensure mcp is an object before spreading
                 mcp: { ...(auditRecord.mcp || { type: 'notification', method: notification.method }), params: notification.params },
                 outcome: {
                     status: outcomeStatus,
                     ...(handlerError ? { error: mapErrorToAuditPayload(handlerError) } : {})
                 }
             };

             if (this.options.auditNotifications) {
                 try {
                     let canProceedWithAudit = true;
                     // Check for required audit configuration
                     if (!this.options.sanitizeForAudit) {
                         logger.error("Cannot audit notification: sanitizeForAudit is not configured");
                         canProceedWithAudit = false;
                     }
                     if (!this.options.auditStore) {
                         logger.error("Cannot audit notification: auditStore is not configured");
                         canProceedWithAudit = false;
                     }

                     if (canProceedWithAudit) {
                         const sanitizedRecord = this.options.sanitizeForAudit!(finalAuditRecord as AuditRecord);
                         logger.debug("Logging notification audit record", { eventId: finalAuditRecord.eventId });
                         this.options.auditStore!.log(sanitizedRecord as AuditRecord).catch((auditErr: any) => {
                              logger.error("Audit logging failed for notification", { error: auditErr, auditEventId: finalAuditRecord.eventId });
                         });
                     }
                 } catch (sanitizeErr) {
                     logger.error("Audit record sanitization failed for notification", { error: sanitizeErr, auditEventId: finalAuditRecord.eventId });
                     console.error(`!!! FAILED TO SANITIZE NOTIFICATION AUDIT RECORD ${finalAuditRecord.eventId} !!!`, finalAuditRecord, sanitizeErr);
                 }
             } else {
                 logger.debug("Skipping notification audit log", { eventId: finalAuditRecord.eventId });
             }
         }
     }

} // End GovernancePipeline class