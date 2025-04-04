/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable no-console */
/* eslint-disable @typescript-eslint/no-explicit-any */
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
    GovernedRequestHandlerExtra, AuditRecord, GovernedServerOptions, TransportContext
} from '../../types.js'; // Adjusted path
import { AuthenticationError, AuthorizationError, CredentialResolutionError, HandlerError, GovernanceError } from '../../errors/index.js'; // Adjusted path
import { GovernancePipeline } from '../governance-pipeline.js'; // Adjusted path for class import

// Import step functions
import { resolveIdentityStep } from './steps/identity-step.js';
import { checkRbacStep } from './steps/rbac-step.js';
import { resolveCredentialsStep } from './steps/credentials-step.js';
import { executePostAuthHookStep } from './steps/post-auth-hook-step.js';
import { executeHandlerStep } from './steps/handler-step.js';

// Define handler map types (or import if refactored elsewhere)
type AnyRequestSchema = ZodObject<{ method: ZodLiteral<string>; [key: string]: ZodTypeAny }>;
type RequestHandlerMap = Map<string, { handler: (req: any, extra: GovernedRequestHandlerExtra) => Promise<Result>, schema: AnyRequestSchema }>;

/**
 * Processes a single JSON-RPC request through the governance pipeline steps.
 * Orchestrates calls to individual step functions.
 * Updates the auditRecord directly and throws errors for pipeline failures.
 */
export async function processRequest(
    pipelineInstance: GovernancePipeline, // Pass the instance to access methods/properties if needed
    options: GovernedServerOptions,
    requestHandlers: RequestHandlerMap,
    request: JSONRPCRequest,
    baseExtra: BaseRequestHandlerExtra,
    operationContext: OperationContext, // Use the potentially modified context
    auditRecord: Partial<AuditRecord>
): Promise<Result> {
    const logger = operationContext.logger;
    // Transport context proxy is already in operationContext
    const transportContextProxy = operationContext.transportContext as Readonly<TransportContext>; 
    
    // Base context remains the same throughout
    const baseContext = Object.freeze({ ...operationContext });

    logger.debug("Executing request pipeline steps via individual modules...");

    // Initialize results from steps
    let identity: UserIdentity | null = null;
    let roles: string[] | undefined = undefined;
    let derivedPermission: string | null = null;
    let resolvedCredentials: ResolvedCredentials | null | undefined = undefined;

    // Initialize audit record parts needed by steps
    auditRecord.outcome = { status: 'failure' }; // Default status
    auditRecord.authorization = { decision: 'not_applicable' };
    auditRecord.credentialResolution = { status: 'not_configured' };

    try {
        // 1. Identity Resolution
        identity = await resolveIdentityStep(options, baseContext, auditRecord);
        const identityContext = Object.freeze({ ...baseContext, ...(identity && { identity }) });

        // 2. RBAC
        const rbacResult = await checkRbacStep(
            options, 
            identity, 
            baseContext, 
            identityContext, 
            transportContextProxy, 
            auditRecord
        );
        derivedPermission = rbacResult.derivedPermission;
        roles = rbacResult.roles;
        const rbacContext = Object.freeze({ ...identityContext, ...(derivedPermission !== undefined && { derivedPermission }), ...(roles && { roles }) });

        // 3. Credentials
        resolvedCredentials = await resolveCredentialsStep(options, identity, rbacContext, auditRecord);
        const finalContext = Object.freeze({ ...rbacContext, ...(resolvedCredentials !== undefined && { resolvedCredentials }) });

        // 4. Post-Authorization Hook
        await executePostAuthHookStep(
            options, 
            identity, 
            baseContext, // Pass the original base context
            roles, 
            resolvedCredentials, 
            auditRecord
        );

        // 5. Execute User Handler
        // Cast finalContext to the expected type for the handler step
        const handlerStepContext = finalContext as Readonly<OperationContext & {
            identity: UserIdentity | null;
            roles?: string[];
            resolvedCredentials?: ResolvedCredentials | null | undefined;
        }>;
        
        const handlerResult = await executeHandlerStep(
            requestHandlers, 
            request, 
            baseExtra, 
            handlerStepContext, 
            transportContextProxy,
            auditRecord
        );

        // If handler step succeeded, the auditRecord.outcome.status is already 'success'
        return handlerResult;

    } catch (pipelineStepError) {
        // Errors thrown by individual steps should already be McpError
        // We just need to ensure the audit record status reflects the outcome correctly
        // (especially for AuthorizationError vs other failures)
        if (!auditRecord.outcome) auditRecord.outcome = { status: 'failure' }; // Ensure outcome exists

        if (pipelineStepError instanceof McpError) {
            const errorData = pipelineStepError.data as { type?: string } | undefined;
            if (errorData?.type === 'AuthorizationError') {
                auditRecord.outcome.status = 'denied';
            } else {
                // For Authentication, Credential, Governance, Handler errors, status is failure
                auditRecord.outcome.status = 'failure';
            }
        } else {
            // Should ideally not happen if steps wrap errors, but handle defensively
            auditRecord.outcome.status = 'failure';
        }
        
        logger.debug("Request pipeline step failed.", { error: pipelineStepError, finalAuditStatus: auditRecord.outcome.status });
        // Rethrow the error to be caught by the main executeRequestPipeline method
        // which handles the final audit logging and error response generation.
        throw pipelineStepError;
    }
}