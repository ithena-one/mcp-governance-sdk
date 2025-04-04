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
import { AuditMetricAttributes, auditLogCounter } from './pipeline/metrics-utils.js';



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
        return this._executePipeline<JSONRPCRequest, Result>(
            request,
            baseExtra,
            operationContext,
            auditRecord,
            false // isNotification = false
        );
    }

    /** Executes the governance pipeline for a notification. */
    async executeNotificationPipeline(
        notification: JSONRPCNotification,
        baseExtra: BaseRequestHandlerExtra,
        operationContext: OperationContext,
        auditRecord: Partial<AuditRecord>
    ): Promise<void> {
        await this._executePipeline<JSONRPCNotification, void>(
            notification,
            baseExtra,
            operationContext,
            auditRecord,
            true // isNotification = true
        );
    }

    /** Private helper to execute the common pipeline logic. */
    private async _executePipeline<
        T extends JSONRPCRequest | JSONRPCNotification,
        R // R will be Result for requests, void for notifications
    >(
        payload: T,
        baseExtra: BaseRequestHandlerExtra,
        operationContext: OperationContext,
        auditRecord: Partial<AuditRecord>,
        isNotification: boolean
    ): Promise<R> {
        const logger = operationContext.logger;
        const startTime = operationContext.timestamp.getTime();
        let outcomeStatus: AuditRecord['outcome']['status'] = isNotification ? 'success' : 'failure'; // Default based on type
        let pipelineError: Error | unknown | null = null;

        // Retain original headers for auditing
        const originalHeaders = Object.freeze({ ...(operationContext.transportContext.headers ?? {}) });
        // Create the proxied context *once* here
        const transportContextProxy = createImmutableTransportContextProxy(operationContext.transportContext);

        // Create the operation context with the proxied transport context
        const pipelineOperationContext = {
            ...operationContext,
            transportContext: transportContextProxy
        };

        try {
            let handlerResult: R;
            if (isNotification) {
                // Type assertion needed because TS can't fully infer based on isNotification boolean alone here
                logger.debug("Executing notification pipeline steps...");
                await processNotification(
                    this,
                    this.options,
                    this.notificationHandlers,
                    payload as JSONRPCNotification, // Assert type
                    baseExtra,
                    pipelineOperationContext,
                    auditRecord
                );
                // Retrieve status set by processNotification, default to 'success'
                outcomeStatus = auditRecord.outcome?.status ?? 'success';
                handlerResult = undefined as R; // Notifications return void
            } else {
                // Type assertion needed
                logger.debug("Executing request pipeline steps...");
                 handlerResult = await processRequest(
                    this,
                    this.options,
                    this.requestHandlers,
                    payload as JSONRPCRequest, // Assert type
                    baseExtra,
                    pipelineOperationContext,
                    auditRecord
                ) as R; // Result type for requests
                // Retrieve status set by processRequest, default to 'success'
                // (processRequest should set status and response on success)
                 outcomeStatus = auditRecord.outcome?.status ?? 'success';
                 // Return early on success for requests
                 return handlerResult;
            }
        } catch (pipeErr) {
            pipelineError = pipeErr;
            // Determine outcome status based on the error
            if (isNotification) {
                outcomeStatus = 'failure';
                logger.error("Error during notification pipeline execution", { error: pipeErr });
                // Do not rethrow for notifications
            } else {
                // Request-specific error handling to determine status
                if (pipeErr instanceof McpError) {
                    const errorData = pipeErr.data as { type?: string } | undefined;
                    outcomeStatus = errorData?.type === 'AuthorizationError' ? 'denied' : 'failure';
                } else if (pipeErr instanceof AuthorizationError) {
                    outcomeStatus = 'denied';
                } else {
                    outcomeStatus = 'failure';
                }
                logger.debug(`Request pipeline failed with status: ${outcomeStatus}`, { error: pipeErr });
                // Rethrow for requests to be converted into JSONRPCError by the caller
                // Note: Ensure auditRecord status is set *before* rethrowing
                if (auditRecord.outcome) {
                    auditRecord.outcome.status = outcomeStatus;
                }
                throw pipeErr;
            }

            // Ensure audit record status reflects the final outcome determined in catch
            // (This is primarily for notifications, as request errors are rethrown above)
            if (auditRecord.outcome) {
                auditRecord.outcome.status = outcomeStatus;
            }

        } finally {
            // Call the centralized auditing function
            finalizeAndLogAuditRecord({
                auditRecord,
                // Use the outcomeStatus determined in try/catch
                outcomeStatus, // This holds the final calculated status
                pipelineError,
                startTime,
                operationContext, // Pass the original context
                transportContext: transportContextProxy, // Pass the proxied context
                originalHeaders,
                options: this.options,
                isNotification
            })
            .then(() => {
                // Record audit success metric
                const auditMetricAttributes: AuditMetricAttributes = { 'outcome.status': 'success' };
                auditLogCounter.add(1, auditMetricAttributes);
                logger.debug('Audit log succeeded', { eventId: auditRecord.eventId });
            })
            .catch(auditFinalizeErr => {
                // Record audit failure metric
                const auditMetricAttributes: AuditMetricAttributes = { 'outcome.status': 'failure' };
                auditLogCounter.add(1, auditMetricAttributes);
                logger.error(`Failed to finalize or log audit record for ${isNotification ? 'notification' : 'request'}`, { error: auditFinalizeErr, eventId: auditRecord.eventId });
            });
        }

        // This return is only relevant for the non-throwing notification path on success/failure
        // or potentially request path if we decided not to return early in try (but we do)
        // Needs a type assertion because TS struggles with the conditional return/throw/void paths
        return undefined as R;
    }

} // End GovernancePipeline class