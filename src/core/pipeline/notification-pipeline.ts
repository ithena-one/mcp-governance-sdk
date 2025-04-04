/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable no-console */
/* eslint-disable @typescript-eslint/no-explicit-any */
import {
    JSONRPCNotification
} from '@modelcontextprotocol/sdk/types.js';
import { RequestHandlerExtra as BaseRequestHandlerExtra } from '@modelcontextprotocol/sdk/shared/protocol.js';
import { ZodObject, ZodLiteral, ZodTypeAny, z } from 'zod';
import {
    UserIdentity, OperationContext,
    GovernedNotificationHandlerExtra, AuditRecord, GovernedServerOptions
} from '../../types.js'; // Adjusted path
import { HandlerError } from '../../errors/index.js'; // Adjusted path
import { GovernancePipeline } from '../governance-pipeline.js'; // Adjusted path for class import
import { mapErrorToAuditPayload } from '../../utils/error-mapper.js'; // Import error mapper
import { withPipelineSpan } from './tracing-utils.js'; // <-- Import the tracing utility

// Define handler map types (or import if refactored elsewhere)
type AnyNotificationSchema = ZodObject<{ method: ZodLiteral<string>; [key: string]: ZodTypeAny }>;
type NotificationHandlerMap = Map<string, { handler: (notif: any, extra: GovernedNotificationHandlerExtra) => Promise<void>, schema: AnyNotificationSchema }>;

/**
 * Processes a single JSON-RPC notification through the relevant governance steps.
 * This function handles optional identity resolution and handler execution.
 * It updates the auditRecord directly and catches handler errors.
 */
export async function processNotification(
    pipelineInstance: GovernancePipeline, // Pass the instance if needed
    options: GovernedServerOptions,
    notificationHandlers: NotificationHandlerMap,
    notification: JSONRPCNotification,
    baseExtra: BaseRequestHandlerExtra,
    operationContext: OperationContext, // Use the context with proxied transport
    auditRecord: Partial<AuditRecord>
): Promise<void> {
    const logger = operationContext.logger;
    let identity: UserIdentity | null = null;
    let handlerError: Error | unknown | null = null;
    let outcomeStatus: AuditRecord['outcome']['status'] = 'success'; // Default: success (ignored or processed)

    // Initialize outcome in audit record if not present
    if (!auditRecord.outcome) {
        auditRecord.outcome = { status: outcomeStatus };
    }

    try {
        // 1. Identity Resolution (Optional, but trace if performed)
        if (options.identityResolver) {
            identity = await withPipelineSpan(
                'Ithena: Identity Resolution (Notification)',
                options,
                operationContext, // Use the initial context
                {
                    'ithena.eventId': operationContext.eventId,
                    'mcp.method': notification.method,
                    // Notifications don't have IDs
                },
                async (span) => {
                    let resolvedIdentity: UserIdentity | null = null;
                    try {
                        resolvedIdentity = await options.identityResolver!.resolveIdentity(operationContext);
                        auditRecord.identity = resolvedIdentity;
                        logger.debug("Identity resolved for notification", { hasIdentity: !!resolvedIdentity });
                        span?.setAttribute('ithena.identity.resolved', !!resolvedIdentity);
                    } catch (err) {
                        logger.warn("Identity resolution failed during notification processing", { error: err });
                        span?.setStatus({ code: 1, message: (err as Error)?.message ?? 'Identity resolution failed' }); // Using code 1 (UNKNOWN) for non-fatal error
                        span?.setAttribute('ithena.identity.resolved', false);
                        span?.recordException(err as Error);
                        // Do not fail the pipeline, return null
                    }
                    return resolvedIdentity;
                }
            );
        } else {
            logger.debug("Identity resolution skipped for notification (no resolver configured)");
        }

        // Update operation context with resolved identity for the handler
        const handlerContext = { ...operationContext, identity: identity ?? null };

        // 2. Execute User Handler (if found)
        const handlerInfo = notificationHandlers.get(notification.method);
        if (handlerInfo) {
            await withPipelineSpan(
                'Ithena: Notification Handler Invocation',
                options,
                handlerContext, // Pass context possibly containing identity
                {
                    'ithena.eventId': operationContext.eventId,
                    'mcp.method': notification.method,
                    'ithena.handler.found': true,
                },
                async (span) => {
                    const { handler: userHandler, schema: notificationSchema } = handlerInfo;
                    const parseResult = notificationSchema.safeParse(notification);

                    if (!parseResult.success) {
                        logger.error("Notification failed schema validation", { error: parseResult.error, method: notification.method });
                        outcomeStatus = 'success'; // Treat schema validation failure as successfully ignored
                        auditRecord.outcome!.status = outcomeStatus;
                        span?.setAttribute('ithena.handler.schemaValid', false);
                        span?.setStatus({ code: 1, message: 'Schema validation failed'}); // Non-fatal error status
                        span?.recordException(parseResult.error);
                        // Do not execute handler
                        return;
                    }
                    span?.setAttribute('ithena.handler.schemaValid', true);
                    
                    const parsedNotification = parseResult.data;
                    const extra: GovernedNotificationHandlerExtra = {
                        signal: baseExtra.signal,
                        sessionId: baseExtra.sessionId,
                        eventId: handlerContext.eventId,
                        logger: handlerContext.logger,
                        identity: handlerContext.identity,
                        traceContext: handlerContext.traceContext,
                        transportContext: handlerContext.transportContext, // Pass the proxied context
                    };

                    try {
                        logger.debug("Executing user notification handler");
                        await userHandler(parsedNotification, extra);
                        outcomeStatus = 'success';
                        auditRecord.outcome!.status = outcomeStatus;
                        logger.debug("User notification handler completed successfully");
                        // Span status OK is handled by withPipelineSpan wrapper on success
                    } catch (err) {
                        handlerError = new HandlerError("Notification handler failed", err);
                        outcomeStatus = 'failure';
                        auditRecord.outcome!.status = outcomeStatus;
                        auditRecord.outcome!.error = mapErrorToAuditPayload(handlerError);
                        logger.error("User notification handler failed", { error: err });
                        // Let withPipelineSpan handle setting ERROR status and recording exception
                        throw handlerError; // Re-throw to be caught by withPipelineSpan
                    }
                }
            );
        } else {
            // Optional: Could add a span here for "Handler Skipped" if desired
            outcomeStatus = 'success'; // Ignored because no handler
            auditRecord.outcome!.status = outcomeStatus;
            logger.debug(`No governed handler for notification ${notification.method}, ignoring.`);
        }
    } catch (err) {
        // Catch unexpected errors during the setup/identity phase (less likely)
        handlerError = err;
        outcomeStatus = 'failure';
        auditRecord.outcome!.status = outcomeStatus;
        // Map the error immediately for the audit record
        auditRecord.outcome!.error = mapErrorToAuditPayload(handlerError);
        logger.error("Unexpected error in notification pipeline processing", { error: err });
        // Do not rethrow
    }
    // No return value, updates auditRecord directly and errors are logged/audited
} 