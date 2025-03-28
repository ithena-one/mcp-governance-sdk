import { v4 as uuidv4 } from 'uuid';
import { Transport } from '@modelcontextprotocol/sdk';
import { TransportContext } from '../types.js';

/** Generates a unique event ID. */
export function generateEventId(): string {
    return uuidv4();
}

/** Builds the TransportContext from a Transport instance. */
export function buildTransportContext(transport: Transport | undefined): TransportContext {
    // This is a basic implementation. Real transports might need specific handling.
    // Assuming base SDK or transports provide necessary info.
    let transportType = 'unknown';
    if (transport) {
        // Heuristic based on class name - replace with a better mechanism if available
        const className = transport.constructor?.name;
        if (className?.includes('Stdio')) transportType = 'stdio';
        else if (className?.includes('SSE')) transportType = 'sse';
        else if (className?.includes('WebSocket')) transportType = 'websocket';
        else if (className?.includes('InMemory')) transportType = 'in-memory';
    }

    // Headers and remoteAddress are typically only available for HTTP-like transports.
    // This requires the actual transport implementation to expose these,
    // which the base SDK's Transport interface doesn't guarantee.
    // We leave them undefined here as a placeholder.
    const headers = (transport as any)?.headers; // Example: Access non-standard property
    const remoteAddress = (transport as any)?.remoteAddress; // Example

    return {
        transportType,
        sessionId: transport?.sessionId,
        headers: headers, // Placeholder
        remoteAddress: remoteAddress, // Placeholder
    };
}

/** Creates a simple AbortSignal that's already aborted. */
export function createAbortedSignal(reason?: any): AbortSignal {
    const controller = new AbortController();
    controller.abort(reason);
    return controller.signal;
} 