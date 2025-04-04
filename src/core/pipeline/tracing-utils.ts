/* eslint-disable @typescript-eslint/no-explicit-any */
import {
    context,
    trace,
    Span,
    SpanStatusCode,
    Attributes} from '@opentelemetry/api';
import { getTracer } from '../governed-server.js'; // Import the exported tracer getter
import { GovernedServerOptions, OperationContext } from '../../types.js';
import { TraceState } from '@opentelemetry/core'; // Keep TraceState, remove parseTraceState
import { Logger } from '../../interfaces/logger.js'; // Added missing import
import { pipelineStepDurationHistogram, StepMetricAttributes } from './metrics-utils.js';

export async function withPipelineSpan<
T>(
    name: string,
    options: Pick<GovernedServerOptions, 'enablePipelineTracing'>,
    opContext: OperationContext, // Contains traceContext and logger
    attributes: Attributes,
    fn: (span?: Span) => Promise<T>
): Promise<T> {
    if (!options.enablePipelineTracing) {
        return fn(); // Execute function directly if tracing is disabled
    }

    const logger = opContext.logger ?? console; // Fallback logger
    const tracer = getTracer();
    
    // Try to extract parent context from OperationContext
    // This relies on TraceContextProvider populating opContext.traceContext
    const parentCtx = opContext.traceContext 
        ? trace.setSpan(context.active(), trace.wrapSpanContext({
              traceId: opContext.traceContext.traceId || '',
              spanId: opContext.traceContext.spanId || '',
              traceFlags: parseInt(opContext.traceContext.traceFlags || '0', 16),
              isRemote: true, // Assume incoming context is remote
              traceState: opContext.traceContext.traceState ? new TraceState(opContext.traceContext.traceState) : undefined
          }))
        : context.active(); // Use current active context if no parent info

    return tracer.startActiveSpan(name, { attributes }, parentCtx, async (span: Span) => {
        logger.debug(`Starting OTel span: ${name}`, { spanId: span.spanContext().spanId, traceId: span.spanContext().traceId });
        const stepStartTime = Date.now(); // <-- Start timer for metric
        let stepOutcomeStatus: 'success' | 'failure' = 'failure'; // <-- Track step outcome for metric
        
        try {
            // Execute the actual pipeline step logic
            const result = await fn(span);
            span.setStatus({ code: SpanStatusCode.OK });
            stepOutcomeStatus = 'success'; // <-- Set outcome on success
            logger.debug(`Ending OTel span: ${name} - OK`, { spanId: span.spanContext().spanId });
            return result;
        } catch (error: any) {
            span.setStatus({ 
                code: SpanStatusCode.ERROR,
                message: error?.message ?? 'Pipeline step failed' 
            });
            // Record error details, avoiding overly sensitive info by default
            span.recordException(error); 
            // Optionally add non-sensitive error attributes based on type?
            if (error.name) {
                span.setAttribute('error.type', error.name);
            }
            // stepOutcomeStatus remains 'failure'
            logger.debug(`Ending OTel span: ${name} - ERROR`, { spanId: span.spanContext().spanId, error: error?.message });
            throw error; // Re-throw the error to maintain pipeline flow
        } finally {
            const stepEndTime = Date.now();
            const stepDurationSeconds = (stepEndTime - stepStartTime) / 1000;
            const metricAttributes: StepMetricAttributes = {
                'ithena.step.name': name, // Use the span name as the step name
                // Add outcome status based on try/catch result
                'outcome.status': stepOutcomeStatus 
            };
            pipelineStepDurationHistogram.record(stepDurationSeconds, metricAttributes); // <-- Record metric
            logger.debug('Recorded step duration metric', { name, durationSeconds: stepDurationSeconds, attributes: metricAttributes });

            span.end(); // End the span (existing code)
        }
    });
} 