/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable no-console */
/* eslint-disable @typescript-eslint/no-explicit-any */
import {
    JSONRPCRequest,
    JSONRPCNotification,
    Result,
    McpError,
} from '@modelcontextprotocol/sdk/types.js';
import { RequestHandlerExtra as BaseRequestHandlerExtra } from '@modelcontextprotocol/sdk/shared/protocol.js';

import {
    TransportContext, OperationContext,
    AuditRecord,
    NotificationHandlerMap,
    RequestHandlerMap
} from '../types.js';
import { GovernedServerOptions } from '../types.js';
import { AuthorizationError } from '../errors/index.js';
import { createImmutableTransportContextProxy } from './pipeline/context.js';
import { processRequest } from './pipeline/request-pipeline.js';
import { processNotification } from './pipeline/notification-pipeline.js';
import { finalizeAndLogAuditRecord } from './pipeline/auditing.js';



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

        // Retain original headers for auditing
        const originalHeaders = Object.freeze({ ...(operationContext.transportContext.headers ?? {}) });
        // Create the proxied context *once* here
        const transportContextProxy = createImmutableTransportContextProxy(operationContext.transportContext);

        try {
            // Call the extracted request processing logic
            const handlerResult = await processRequest(
                this, // Pass the current instance
                this.options,
                this.requestHandlers,
                request,
                baseExtra,
                { // Pass a potentially modified operationContext (with proxied transport)
                    ...operationContext,
                    transportContext: transportContextProxy
                },
                auditRecord
            );
            // If processRequest completes without error, outcome is success
            outcomeStatus = 'success';
            // The auditRecord.outcome.status should already be set to 'success' by processRequest
            // along with auditRecord.outcome.mcpResponse
            return handlerResult;

        } catch (pipeErr) {
            pipelineError = pipeErr;
            // Determine outcome status based on the error caught here
            // (processRequest sets the auditRecord status, but we confirm/log final status here)
            if (pipeErr instanceof McpError) {
                const errorData = pipeErr.data as { type?: string } | undefined;
                if (errorData?.type === 'AuthorizationError') {
                    outcomeStatus = 'denied';
                } else {
                    outcomeStatus = 'failure';
                }
            } else if (pipeErr instanceof AuthorizationError) {
                outcomeStatus = 'denied';
            } else {
                outcomeStatus = 'failure';
            }
            // Ensure audit record status reflects the final outcome from this catch block
            if (auditRecord.outcome) {
                auditRecord.outcome.status = outcomeStatus;
            }
            logger.debug(`Request pipeline failed with status: ${outcomeStatus}`, { error: pipeErr });
            // Rethrow the error to be converted into a JSONRPCError by the caller
            throw pipeErr;
        } finally {
            // Call the centralized auditing function
            finalizeAndLogAuditRecord({
                auditRecord,
                outcomeStatus,
                pipelineError,
                startTime,
                operationContext, // Pass the original context
                transportContext: transportContextProxy, // Pass the proxied context
                originalHeaders,
                options: this.options, // Pass relevant options
                isNotification: false
            }).catch(auditFinalizeErr => {
                // Log errors during the finalization/logging itself, should be rare
                logger.error("Failed to finalize or log audit record for request", { error: auditFinalizeErr, eventId: auditRecord.eventId });
            });
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
        let outcomeStatus: AuditRecord['outcome']['status'] = 'success'; // Notifications default to success/ignored
        let pipelineError: Error | unknown | null = null;

        // Store original headers for audit log
        const originalHeaders = Object.freeze({ ...(operationContext.transportContext.headers ?? {}) });

        // Create immutable transport context with headers proxy
        const transportContextProxy = createImmutableTransportContextProxy(operationContext.transportContext);

        // Replace the transport context with the proxy for steps within processNotification
        const notificationOperationContext = {
            ...operationContext,
            transportContext: transportContextProxy
        };

        try {
            logger.debug("Executing notification pipeline steps...");
            // Call the extracted notification processing logic
            await processNotification(
                this, // Pass instance
                this.options,
                this.notificationHandlers,
                notification,
                baseExtra,
                notificationOperationContext,
                auditRecord // Pass the mutable audit record part
            );
            // If processNotification finishes without error, status is likely 'success'
            // The processNotification function itself will set the correct auditRecord.outcome.status
            // We retrieve it here for the final audit decision logic.
            outcomeStatus = auditRecord.outcome?.status ?? 'success'; // Default to success if somehow unset

        } catch (err) { // Catch errors from context setup or within processNotification
            pipelineError = err;
            outcomeStatus = 'failure';
            // Ensure audit record status reflects failure
            if (auditRecord.outcome) {
                auditRecord.outcome.status = outcomeStatus;
            }
            logger.error("Error during notification pipeline execution", { error: err });
            // We don't typically rethrow errors for notifications as there's no caller expecting a response
        } finally {
            // Call the centralized auditing function
            finalizeAndLogAuditRecord({
                auditRecord,
                outcomeStatus,
                pipelineError, // Use pipelineError captured in catch block
                startTime,
                operationContext, // Pass the original context
                transportContext: transportContextProxy, // Pass the proxied context
                originalHeaders,
                options: this.options, // Pass relevant options
                isNotification: true
            }).catch(auditFinalizeErr => {
                // Log errors during the finalization/logging itself
                logger.error("Failed to finalize or log audit record for notification", { error: auditFinalizeErr, eventId: auditRecord.eventId });
            });
        }
    }

} // End GovernancePipeline class