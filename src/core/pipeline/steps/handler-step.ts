import {
    JSONRPCRequest,
    Result,
    McpError,
    ErrorCode as McpErrorCode
} from '@modelcontextprotocol/sdk/types.js';
import { RequestHandlerExtra as BaseRequestHandlerExtra } from '@modelcontextprotocol/sdk/shared/protocol.js';
import { ZodObject, ZodLiteral, ZodTypeAny, z } from 'zod';
import {
    UserIdentity, ResolvedCredentials, OperationContext,
    GovernedRequestHandlerExtra, AuditRecord, TransportContext
} from '../../../types.js'; // Adjust path
import { HandlerError } from '../../../errors/index.js'; // Adjust path

// Define types used within this step
type AnyRequestSchema = ZodObject<{ method: ZodLiteral<string>; [key: string]: ZodTypeAny }>;
type RequestHandlerMap = Map<string, { handler: (req: any, extra: GovernedRequestHandlerExtra) => Promise<Result>, schema: AnyRequestSchema }>;

// Define a type for the final context passed to the handler
interface HandlerContext extends OperationContext {
    identity: UserIdentity | null;
    roles?: string[];
    resolvedCredentials?: ResolvedCredentials | null | undefined;
    // TransportContext is accessed via the 'extra' object, not directly in this context type
}

/**
 * Pipeline Step: Handler Execution
 * Finds the appropriate handler for the request method, validates the schema, 
 * constructs the handler context ('extra'), and executes the handler.
 * Updates the audit record with the result or marks failure.
 * Returns the result from the handler.
 * Throws McpError for method not found, invalid params, or handler execution errors.
 */
export async function executeHandlerStep(
    requestHandlers: RequestHandlerMap,
    request: JSONRPCRequest,
    baseExtra: BaseRequestHandlerExtra, // Base extras like signal, sessionId
    finalContext: Readonly<HandlerContext>, // Context containing results of previous steps
    transportContext: Readonly<TransportContext>, // Pass the proxied transport context
    auditRecord: Partial<AuditRecord>
): Promise<Result> {
    const logger = finalContext.logger;
    const handlerInfo = requestHandlers.get(request.method);

    logger.debug("[Pipeline Step] Starting Handler Execution Lookup...");
    if (!handlerInfo) {
        logger.warn(`No governed handler registered for method: ${request.method}`);
        logger.debug("[Pipeline Step] Handler Execution failed: Method not found.", { method: request.method });
        auditRecord.outcome = { ...auditRecord.outcome, status: 'failure' }; // Ensure status reflects this
        throw new McpError(McpErrorCode.MethodNotFound, `Method not found: ${request.method}`);
    }

    const { handler: userHandler, schema: requestSchema } = handlerInfo;
    logger.debug("[Pipeline Step] Handler found, validating schema...", { method: request.method });

    const parseResult = requestSchema.safeParse(request);
    if (!parseResult.success) {
        logger.error("Request failed schema validation before handler execution", { error: parseResult.error, method: request.method });
        logger.debug("[Pipeline Step] Handler Execution failed: Invalid schema.", { method: request.method, error: parseResult.error });
        auditRecord.outcome = { ...auditRecord.outcome, status: 'failure' }; // Ensure status reflects this
        throw new McpError(McpErrorCode.InvalidParams, `Invalid request structure: ${parseResult.error.message}`);
    }

    const parsedRequest = parseResult.data;
    logger.debug("[Pipeline Step] Schema valid, preparing handler context...", { method: request.method });

    // Construct the 'extra' object for the handler
    const extra: GovernedRequestHandlerExtra = {
        signal: baseExtra.signal,
        sessionId: baseExtra.sessionId,
        eventId: finalContext.eventId,
        logger: finalContext.logger,
        identity: finalContext.identity ?? null, // Ensure null if undefined
        roles: finalContext.roles, // Roles are passed as is (usually undefined if no RBAC)
        resolvedCredentials: finalContext.resolvedCredentials, // Get from finalContext
        traceContext: finalContext.traceContext,
        transportContext: transportContext, // Use the passed proxied context
    };

    try {
        logger.debug("[Pipeline Step] Executing user handler...", { method: request.method });
        const handlerResult = await userHandler(parsedRequest, extra);
        // If handler succeeds, update audit record status and include result
        auditRecord.outcome = {
            ...auditRecord.outcome,
            status: 'success',
            mcpResponse: { result: handlerResult }
        };
        logger.debug("[Pipeline Step] Handler Execution completed successfully.", { method: request.method });
        return handlerResult;
    } catch (handlerErr) {
        logger.error("User request handler failed", { error: handlerErr, method: request.method });
        logger.debug("[Pipeline Step] Handler Execution failed.", { method: request.method, error: handlerErr });
        // Set audit status to failure, error details will be added later
        auditRecord.outcome = { ...auditRecord.outcome, status: 'failure' };
        if (handlerErr instanceof McpError) {
            throw handlerErr; // Rethrow known MCP errors
        }
        // Wrap unknown handler errors
        const handlerError = new HandlerError("Handler execution failed", handlerErr);
        throw new McpError(McpErrorCode.InternalError, handlerError.message, {
            type: 'HandlerError',
            originalError: handlerErr
        });
    }
} 