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
        // 1. Identity Resolution (Optional)
        if (options.identityResolver) {
            try {
                identity = await options.identityResolver.resolveIdentity(operationContext);
                // Update operationContext locally if needed for handler (though less common for notifications)
                // operationContext = { ...operationContext, identity };
                auditRecord.identity = identity;
                logger.debug("Identity resolved for notification", { hasIdentity: !!identity });
            } catch (err) {
                logger.warn("Identity resolution failed during notification processing", { error: err });
                // Do not fail the pipeline for identity errors in notifications
                // Audit record might capture identity as null or undefined here
            }
        }

        // 2. Execute User Handler
        const handlerInfo = notificationHandlers.get(notification.method);
        if (handlerInfo) {
            const { handler: userHandler, schema: notificationSchema } = handlerInfo;

            const parseResult = notificationSchema.safeParse(notification);
            if (!parseResult.success) {
                logger.error("Notification failed schema validation", { error: parseResult.error, method: notification.method });
                outcomeStatus = 'success'; // Treat schema validation failure as successfully ignored
                auditRecord.outcome.status = outcomeStatus;
                // Optionally log schema error details somewhere if needed
            } else {
                const parsedNotification = parseResult.data;
                const extra: GovernedNotificationHandlerExtra = {
                    signal: baseExtra.signal,
                    sessionId: baseExtra.sessionId,
                    eventId: operationContext.eventId,
                    logger: operationContext.logger,
                    identity: identity ?? null,
                    traceContext: operationContext.traceContext,
                    transportContext: operationContext.transportContext, // Pass the proxied context
                };
                try {
                    logger.debug("Executing user notification handler");
                    await userHandler(parsedNotification, extra);
                    outcomeStatus = 'success';
                    auditRecord.outcome.status = outcomeStatus;
                    logger.debug("User notification handler completed successfully");
                } catch (err) {
                    handlerError = new HandlerError("Notification handler failed", err);
                    outcomeStatus = 'failure';
                    auditRecord.outcome.status = outcomeStatus;
                    // Map the error immediately for the audit record
                    auditRecord.outcome.error = mapErrorToAuditPayload(handlerError);
                    logger.error("User notification handler failed", { error: err });
                    // Do not rethrow, allow finally block in executeNotificationPipeline to handle logging
                }
            }
        } else {
            outcomeStatus = 'success'; // Ignored because no handler
            auditRecord.outcome.status = outcomeStatus;
            logger.debug(`No governed handler for notification ${notification.method}, ignoring.`);
        }
    } catch (err) {
        // Catch unexpected errors during the setup/identity phase (less likely)
        handlerError = err;
        outcomeStatus = 'failure';
        auditRecord.outcome.status = outcomeStatus;
        // Map the error immediately for the audit record
        auditRecord.outcome.error = mapErrorToAuditPayload(handlerError);
        logger.error("Unexpected error in notification pipeline processing", { error: err });
        // Do not rethrow
    }
    // No return value, updates auditRecord directly and errors are logged/audited
} 