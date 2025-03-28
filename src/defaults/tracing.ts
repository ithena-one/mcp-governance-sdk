import { TraceContextProvider } from '../interfaces/tracing.js';
import { TraceContext, TransportContext } from '../types.js';
import { Request, Notification } from '@modelcontextprotocol/sdk';

const W3C_TRACEPARENT_HEADER = 'traceparent';
const W3C_TRACESTATE_HEADER = 'tracestate';
// Regex based on W3C Trace Context spec: https://www.w3.org/TR/trace-context/#traceparent-header-field-values
const TRACEPARENT_REGEX = /^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/;

/**
 * Parses the W3C `traceparent` header.
 * @param traceparent - The value of the `traceparent` header.
 * @returns Extracted trace context or undefined if invalid.
 */
function parseTraceparent(traceparent: string): Omit<TraceContext, 'traceState'> | undefined {
    const match = traceparent.match(TRACEPARENT_REGEX);
    if (!match) {
        return undefined;
    }
    // version [0], traceId [1], parentSpanId [2], traceFlags [3]
    const [, version, traceId, parentSpanId, traceFlags] = match;

    // Currently only version 00 is supported in most systems
    if (version !== '00') {
        return undefined;
    }

    return {
        traceId,
        parentSpanId, // This is the parent's span ID according to the header
        spanId: undefined, // We don't know *our* span ID yet
        traceFlags,
    };
}

/**
 * Default TraceContextProvider that extracts context from W3C Trace Context headers (`traceparent`, `tracestate`).
 */
export const defaultTraceContextProvider: TraceContextProvider = (
    transportContext: TransportContext,
    _mcpMessage: Request | Notification
): TraceContext | undefined => {
    const headers = transportContext.headers;
    if (!headers) {
        return undefined;
    }

    const traceparentHeader = headers[W3C_TRACEPARENT_HEADER];
    const tracestateHeader = headers[W3C_TRACESTATE_HEADER];

    let traceparentValue: string | undefined;

    if (Array.isArray(traceparentHeader)) {
        // Per spec, use the first valid one if multiple exist
        traceparentValue = traceparentHeader[0];
    } else {
        traceparentValue = traceparentHeader;
    }

    if (!traceparentValue) {
        return undefined;
    }

    const parsedParent = parseTraceparent(traceparentValue);
    if (!parsedParent) {
        return undefined; // Invalid traceparent header
    }

    let tracestateValue: string | undefined;
    if (Array.isArray(tracestateHeader)) {
        // Per spec, concatenate if multiple exist (though often discouraged)
        tracestateValue = tracestateHeader.join(',');
    } else {
        tracestateValue = tracestateHeader;
    }

    return {
        ...parsedParent,
        traceState: tracestateValue,
    };
}; 