/* eslint-disable @typescript-eslint/no-explicit-any */
import { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import { TransportContext } from '../types.js';

/** Builds the TransportContext from a Transport instance. */
export function buildTransportContext(transport: Transport | undefined): TransportContext {
    let transportType = 'unknown';
    if (transport) {
        const className = transport.constructor?.name;
        if (className?.includes('Stdio')) transportType = 'stdio';
        else if (className?.includes('SSE')) transportType = 'sse';
        else if (className?.includes('WebSocket')) transportType = 'websocket';
        else if (className?.includes('InMemory')) transportType = 'in-memory';
    }

    const headers = (transport as any)?.headers;
    const remoteAddress = (transport as any)?.remoteAddress;

    return {
        transportType,
        sessionId: transport?.sessionId,
        headers: headers,
        remoteAddress: remoteAddress,
    };
}

// Could add createOperationContext helper here if needed