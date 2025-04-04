/* eslint-disable no-console */
/* eslint-disable @typescript-eslint/no-explicit-any */
import {
    AuditRecord, GovernedServerOptions, OperationContext, TransportContext
} from '../../types.js'; // Adjust path
import { mapErrorToAuditPayload } from '../../utils/error-mapper.js'; // Adjust path

interface FinalizeAuditParams {
    auditRecord: Partial<AuditRecord>;
    outcomeStatus: AuditRecord['outcome']['status'];
    pipelineError: Error | unknown | null;
    startTime: number; // Pass start time to calculate duration
    operationContext: OperationContext; // Original context for params
    transportContext: TransportContext; // Proxied or base transport context
    originalHeaders: Record<string, any>; // Original, non-proxied headers
    options: Pick<GovernedServerOptions, 'auditStore' | 'sanitizeForAudit' | 'auditDeniedRequests' | 'auditNotifications'>;
    isNotification: boolean; // Flag to differentiate request/notification logic
}

/**
 * Finalizes the audit record (duration, timestamp, error, MCP/transport details)
 * and logs it according to the configuration.
 */
export async function finalizeAndLogAuditRecord({
    auditRecord,
    outcomeStatus,
    pipelineError,
    startTime,
    operationContext,
    transportContext,
    originalHeaders,
    options,
    isNotification
}: FinalizeAuditParams): Promise<void> {
    const logger = operationContext.logger;
    const endTime = Date.now();
    const durationMs = endTime - startTime;

    // Ensure core audit fields are present
    auditRecord.timestamp = new Date(endTime).toISOString();
    auditRecord.durationMs = durationMs;
    if (!auditRecord.eventId) {
        // Should ideally always be set earlier, but add fallback
        auditRecord.eventId = operationContext.eventId || crypto.randomUUID();
        logger.warn("Audit record eventId was missing, generated fallback.", { eventId: auditRecord.eventId });
    }
    
    // Initialize outcome if it wasn't set during pipeline execution (e.g., early error)
    if (!auditRecord.outcome) {
        auditRecord.outcome = { status: outcomeStatus };
    }
    // Ensure status matches the final determined status
    auditRecord.outcome.status = outcomeStatus;

    // Map error if a pipeline error occurred and wasn't already mapped by a step
    if (pipelineError && !auditRecord.outcome.error) {
        auditRecord.outcome.error = mapErrorToAuditPayload(pipelineError);
    }

    // Set MCP details (use original message from context for params)
    auditRecord.mcp = {
        type: isNotification ? 'notification' : 'request',
        method: operationContext.mcpMessage.method,
        // Only add ID for requests
        ...(!isNotification && { id: (operationContext.mcpMessage as any).id }), 
        params: operationContext.mcpMessage.params 
    };

    // Set Transport details (use original headers)
    auditRecord.transport = {
        ...transportContext,
        headers: { ...originalHeaders }
    };

    // --- Auditing Logic ---
    const shouldAuditBasedOnType = isNotification ? options.auditNotifications : true; // Requests audited by default unless denied
    const shouldAuditBasedOnOutcome = outcomeStatus !== 'denied' || (options.auditDeniedRequests && !isNotification);
    const shouldAudit = shouldAuditBasedOnType && shouldAuditBasedOnOutcome;

    // Check for missing configuration *if* auditing is expected for this type
    let configError = false;
    if (shouldAuditBasedOnType && !options.auditStore) {
        logger.error("Cannot audit: auditStore is not configured");
        configError = true;
    }
    if (shouldAuditBasedOnType && !options.sanitizeForAudit && isNotification) {
        // Only strictly require sanitizer for notifications, as requests might not need it
        logger.error("Cannot audit notification: sanitizeForAudit is not configured");
        configError = true;
    }

    // Proceed with audit attempt only if expected and config is present
    if (shouldAudit && !configError && !auditRecord.logged) {
        // Type assertion: At this point, it should be a complete AuditRecord
        const finalRecord = auditRecord as AuditRecord; 
        let sanitizedRecord: AuditRecord = finalRecord;
        let sanitizationSucceeded = true;

        // Sanitize if configured
        if (options.sanitizeForAudit) {
            try {
                const sanitized = options.sanitizeForAudit(finalRecord);
                if (sanitized) {
                    sanitizedRecord = sanitized as AuditRecord;
                } else {
                    // Handle case where sanitizer returns undefined/null intentionally?
                    // Maybe log a warning? For now, proceed with original.
                    logger.warn("Audit sanitizer returned null/undefined, logging original record.", { eventId: finalRecord.eventId });
                }
            } catch (sanitizeErr) {
                sanitizationSucceeded = false;
                logger.error("Audit record sanitization failed", { error: sanitizeErr, auditEventId: finalRecord.eventId });
                // Use console.error for high visibility
                console.error(`!!! FAILED TO SANITIZE AUDIT RECORD ${finalRecord.eventId} !!!`, finalRecord, sanitizeErr);
            }
        }

        // Log if sanitization worked or wasn't needed
        if (sanitizationSucceeded) {
            logger.debug(`Logging ${isNotification ? 'notification' : 'request'} audit record`, { eventId: finalRecord.eventId, outcome: outcomeStatus });
            // Add explicit check for auditStore before logging
            if (options.auditStore) {
                try {
                    await options.auditStore.log(sanitizedRecord);
                    auditRecord.logged = true; // Mark as logged
                } catch (auditErr) {
                    logger.error("Audit logging failed", { error: auditErr, auditEventId: finalRecord.eventId });
                }
            } else {
                // This case should logically not be hit due to earlier checks, but log defensively
                logger.error("Internal logic error: Attempted audit log, but auditStore is missing despite checks.", { eventId: finalRecord.eventId });
            }
        } else {
            logger.warn("Skipping audit log due to sanitization failure", { eventId: finalRecord.eventId });
        }
    } else {
        if (!auditRecord.logged) {
             logger.debug("Skipping audit log based on configuration or outcome", { 
                eventId: auditRecord.eventId, 
                outcome: outcomeStatus,
                shouldAudit,
                shouldAuditBasedOnType,
                shouldAuditBasedOnOutcome,
                hasAuditStore: !!options.auditStore,
                hasSanitizer: !!options.sanitizeForAudit,
                configError // Add the config error flag to the log context
             });
        }
    }
} 