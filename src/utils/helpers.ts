/* eslint-disable @typescript-eslint/no-explicit-any */
import { v4 as uuidv4 } from 'uuid';
import { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import { TransportContext } from '../types.js';

/** Generates a unique event ID. */
export function generateEventId(): string {
    return uuidv4();
}

/** Builds the TransportContext from a Transport instance. */
export function buildTransportContext(transport: Transport | undefined): TransportContext {
    let transportType = 'unknown';
    if (transport) {
        // Try different ways to get the transport class name
        const className = 
            (transport as any).__className || // Check custom property first
            (transport as any)[Symbol.toStringTag] || // Then check Symbol.toStringTag 
            transport.constructor?.name; // Finally check constructor name
            
        if (className?.includes('Stdio')) transportType = 'stdio';
        else if (className?.includes('SSE')) transportType = 'sse';
        else if (className?.includes('WebSocket')) transportType = 'websocket';
        else if (className?.includes('InMemory')) transportType = 'in-memory';
    }

    // Attempt to access potential non-standard properties, default to undefined
    const headers = (transport as any)?.headers;
    const remoteAddress = (transport as any)?.remoteAddress;

    return {
        transportType,
        sessionId: transport?.sessionId,
        headers: headers,
        remoteAddress: remoteAddress,
    };
}