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
    Request, // Import Request type
} from '@modelcontextprotocol/sdk/types.js';
import { RequestHandlerExtra as BaseRequestHandlerExtra } from '@modelcontextprotocol/sdk/shared/protocol.js';

import { ZodObject, ZodLiteral, ZodTypeAny, z } from 'zod';
import {
    UserIdentity, ResolvedCredentials, TransportContext, OperationContext,
    GovernedRequestHandlerExtra, GovernedNotificationHandlerExtra, AuditRecord
} from '../types.js';
import { GovernedServerOptions } from './governed-server.js'; // Assuming type is exported from governed-server
import { AuthenticationError, AuthorizationError, CredentialResolutionError, HandlerError, GovernanceError } from '../errors/index.js';
// Removed unused Logger import: import { Logger } from '../interfaces/logger.js';
import { mapErrorToPayload, mapErrorToAuditPayload } from '../utils/error-mapper.js';
import { buildAuditOutcome } from '../utils/audit-helpers.js';

// Re-define handler map types locally or import if exported
type AnyRequestSchema = ZodObject<{ method: ZodLiteral<string>; [key: string]: ZodTypeAny }>;
type AnyNotificationSchema = ZodObject<{ method: ZodLiteral<string>; [key: string]: ZodTypeAny }>;
type InferRequest<T extends AnyRequestSchema> = z.infer<T>;
type InferNotification<T extends AnyNotificationSchema> = z.infer<T>;
type RequestHandlerMap = Map<string, { handler: (req: any, extra: GovernedRequestHandlerExtra) => Promise<Result>, schema: AnyRequestSchema }>;
type NotificationHandlerMap = Map<string, { handler: (notif: any, extra: GovernedNotificationHandlerExtra) => Promise<void>, schema: AnyNotificationSchema }>;

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
        baseExtra: BaseRequestHandlerExtra, // Includes signal, sessionId from base Server
        operationContext: OperationContext, // Pre-built context (eventId, transport, trace, logger...)
        auditRecord: Partial<AuditRecord> // Pre-built audit record base
    ): Promise<Result> {
        const logger = operationContext.logger;
        const startTime = operationContext.timestamp.getTime(); // Get start time from context
        let outcomeStatus: AuditRecord['outcome']['status'] = 'failure';
        let pipelineError: Error | unknown | null = null;
        let handlerResult: Result | undefined = undefined;
        let finalErrorPayload: JSONRPCError['error'] | undefined = undefined;

        try {
            logger.debug("Executing request pipeline steps...");

            let identity: UserIdentity | null = null;
            let roles: string[] | undefined = undefined;
            let derivedPermission: string | null = null;
            let resolvedCredentials: ResolvedCredentials | null | undefined = null;

            // 2. Identity Resolution
            if (this.options.identityResolver) {
                try {
                    identity = await this.options.identityResolver.resolveIdentity(operationContext);
                    operationContext.identity = identity;
                    auditRecord.identity = identity;
                    // Avoid logging raw identity object by default, consider structured logging context
                    logger.debug("Identity resolved", { hasIdentity: !!identity });
                } catch (err) {
                    logger.error("Identity resolution failed", { error: err });
                    if (err instanceof GovernanceError) throw err;
                    throw new AuthenticationError("Identity resolution failed", err);
                }
            } else {
                 logger.debug("No identity resolver configured");
            }

            // 3. RBAC
            const authzResult: AuditRecord['authorization'] = { decision: 'not_applicable' };
            auditRecord.authorization = authzResult;
            if (this.options.enableRbac) {
                authzResult.decision = 'denied';
                if (identity === null) {
                    authzResult.denialReason = 'identity';
                    throw new AuthorizationError('identity', "Identity required for authorization but none was resolved.");
                }
                if (!this.options.roleStore || !this.options.permissionStore) {
                    // This should be caught by GovernedServer constructor, but defensive check
                    throw new GovernanceError("RBAC enabled but RoleStore or PermissionStore is missing.");
                }
                // Safely handle derivePermission call with optional chaining
                derivedPermission = this.options.derivePermission?.(operationContext.mcpMessage, operationContext.transportContext) ?? null;
                operationContext.derivedPermission = derivedPermission;
                authzResult.permissionAttempted = derivedPermission;

                if (derivedPermission === null) {
                    authzResult.decision = 'granted';
                    logger.debug("Permission check not applicable (null permission derived)");
                } else {
                    try {
                        // Ensure roleStore and permissionStore are accessed safely if optional in options type
                        roles = await this.options.roleStore.getRoles(identity, operationContext);
                        operationContext.roles = roles;
                        authzResult.roles = roles;
                        let hasPermission = false;
                        if (roles && roles.length > 0) {
                            const checks = await Promise.all(roles.map(role => this.options.permissionStore!.hasPermission(role, derivedPermission!, operationContext)));
                            hasPermission = checks.some((allowed: boolean) => allowed);
                        }
                        if (!hasPermission) {
                            authzResult.denialReason = 'permission';
                            throw new AuthorizationError('permission', `Missing required permission: ${derivedPermission}`);
                        }
                        authzResult.decision = 'granted';
                        logger.debug("Authorization granted", { permission: derivedPermission, roles });
                    } catch (err) {
                        logger.error("Error during role/permission check", { error: err });
                        if (err instanceof AuthorizationError) throw err;
                        if (err instanceof GovernanceError) throw err;
                        throw new GovernanceError("Error checking permissions", err);
                    }
                }
            }

            // 4. Post-Authorization Hook
            if (this.options.postAuthorizationHook && identity &&
                (authzResult.decision === 'granted' || authzResult.decision === 'not_applicable')) {
                try {
                    logger.debug("Executing post-authorization hook");
                    // Check if postAuthorizationHook is defined before calling
                    await this.options.postAuthorizationHook(identity, operationContext);
                } catch (err) {
                    logger.error("Post-authorization hook failed", { error: err });
                    if (err instanceof GovernanceError) throw err;
                    throw new GovernanceError("Post-authorization hook failed", err);
                }
            }

            // 5. Credentials
            const credResult: AuditRecord['credentialResolution'] = { status: 'not_configured' };
            auditRecord.credentialResolution = credResult;
            if (this.options.credentialResolver) {
                try {
                    logger.debug("Resolving credentials");
                    // Check if credentialResolver is defined before calling
                    resolvedCredentials = await this.options.credentialResolver.resolveCredentials(identity ?? null, operationContext);
                    credResult.status = 'success';
                    logger.debug("Credentials resolution successful"); // Changed log message slightly
                } catch (err) {
                    credResult.status = 'failure';
                    credResult.error = { message: err instanceof Error ? err.message : String(err), type: err?.constructor?.name };
                    logger.error("Credential resolution failed", { error: err });
                    if (this.options.failOnCredentialResolutionError) {
                        if (err instanceof GovernanceError) throw err;
                        throw new CredentialResolutionError("Credential resolution failed", err);
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
                // Spread baseExtra carefully - ensure types align if modified
                signal: baseExtra.signal,
                sessionId: baseExtra.sessionId,
                eventId: operationContext.eventId,
                logger: operationContext.logger,
                identity: identity ?? null,
                roles: roles,
                resolvedCredentials: resolvedCredentials,
                traceContext: operationContext.traceContext,
                transportContext: operationContext.transportContext,
            };

            try {
                 logger.debug("Executing user request handler");
                handlerResult = await userHandler(parsedRequest, extra);
                outcomeStatus = 'success';
                logger.debug("User request handler completed successfully");
            } catch (handlerErr) {
                pipelineError = new HandlerError("User handler execution failed", handlerErr); // Wrap handler error
                outcomeStatus = 'failure';
                logger.error("User handler execution failed", { error: handlerErr });
            }

        } catch (pipeErr) {
            pipelineError = pipeErr;
            outcomeStatus = (pipeErr instanceof AuthorizationError) ? 'denied' : 'failure';
             // Log pipeline errors with more context
            logger.warn(`Governance pipeline step failed for request ${request.id}`, { error: pipeErr, eventId: operationContext?.eventId });
        } finally {
             // --- Build Audit Record Outcome ---
             const endTime = Date.now();
             // Ensure startTime is available - it should be from operationContext
             const durationMs = endTime - (operationContext?.timestamp.getTime() ?? startTime); // Fallback to outer startTime if context creation failed
             auditRecord.timestamp = new Date(endTime).toISOString();
             auditRecord.durationMs = durationMs;

             let responseForAudit: JSONRPCResponse | JSONRPCError | null = null;
             if (outcomeStatus === 'success' && handlerResult !== undefined) {
                 responseForAudit = { jsonrpc: "2.0", id: request.id, result: handlerResult };
             } else if (pipelineError) {
                 finalErrorPayload = mapErrorToPayload(pipelineError, McpErrorCode.InternalError, "Pipeline error");
                 responseForAudit = { jsonrpc: "2.0", id: request.id, error: finalErrorPayload };
             }

             // Add potentially missing fields (like mcp.params) before audit logging
             const finalAuditRecord = {
                ...auditRecord,
                // Ensure mcp is an object before spreading
                mcp: { ...(auditRecord.mcp || { type: 'request', method: request.method, id: request.id }), params: request.params },
                outcome: buildAuditOutcome(outcomeStatus, pipelineError, responseForAudit)
             };

             // --- Auditing ---
             const shouldAudit = outcomeStatus !== 'denied' || this.options.auditDeniedRequests;
             if (shouldAudit) {
                 try {
                     // Ensure sanitizeForAudit exists before calling
                     const sanitizedRecord = this.options.sanitizeForAudit?.(finalAuditRecord as AuditRecord);
                     logger.debug("Logging audit record", { eventId: finalAuditRecord.eventId });
                     // Ensure auditStore exists before logging
                     this.options.auditStore?.log(sanitizedRecord as AuditRecord)?.catch((auditErr: any) => {
                          logger.error("Audit logging failed", { error: auditErr, auditEventId: finalAuditRecord.eventId });
                     });
                 } catch (sanitizeErr) {
                     logger.error("Audit record sanitization failed", { error: sanitizeErr, auditEventId: finalAuditRecord.eventId });
                     console.error(`!!! FAILED TO SANITIZE AUDIT RECORD ${finalAuditRecord.eventId} !!!`, finalAuditRecord, sanitizeErr);
                 }
             } else {
                 logger.debug("Skipping audit log based on configuration", { eventId: finalAuditRecord.eventId, outcome: outcomeStatus });
             }
        }

        // --- Return Result or Throw Mapped Error ---
        if (outcomeStatus === 'success' && handlerResult !== undefined) {
            return handlerResult;
        } else {
             if (!finalErrorPayload) { // Should have been built in finally
                 finalErrorPayload = mapErrorToPayload(pipelineError ?? new Error("Unknown processing error"), McpErrorCode.InternalError, "Unknown error");
             }
            throw new McpError(finalErrorPayload.code, finalErrorPayload.message, finalErrorPayload.data);
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