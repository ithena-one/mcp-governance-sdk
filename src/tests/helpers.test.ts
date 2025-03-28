/* eslint-disable @typescript-eslint/no-explicit-any */
// src/utils/helpers.test.ts

import { generateEventId, buildTransportContext } from '../utils/helpers.js';
import { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';

// Basic mock transport implementation for testing context building
class MockTransport implements Transport {
    public __className = 'UnknownTransport'; // Helper for testing
    public headers?: Record<string, string | string[] | undefined>;
    public remoteAddress?: string;
    public sessionId?: string;

    constructor(config: { className?: string; headers?: any; remoteAddress?: string; sessionId?: string }) {
        this.__className = config.className ?? 'UnknownTransport';
        this.headers = config.headers;
        this.remoteAddress = config.remoteAddress;
        this.sessionId = config.sessionId;
    }

    // Mock implementations for Transport interface methods
    async start(): Promise<void> {}
    async close(): Promise<void> {}
    async send(): Promise<void> {}
    // Return the constructor name for type checking
    get [Symbol.toStringTag]() {
        return this.__className;
    }
}

describe('Utility Helpers', () => {
    describe('generateEventId', () => {
        it('should generate a string that looks like a UUID v4', () => {
            const eventId = generateEventId();
            expect(typeof eventId).toBe('string');
            // Regex for UUID v4
            const uuidV4Regex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
            expect(eventId).toMatch(uuidV4Regex);
        });
    });

    describe('buildTransportContext', () => {
        it('should return default values for undefined transport', () => {
            const context = buildTransportContext(undefined);
            expect(context).toEqual({
                transportType: 'unknown',
                sessionId: undefined,
                headers: undefined,
                remoteAddress: undefined,
            });
        });

        it('should detect stdio transport type', () => {
            const transport = new MockTransport({ className: 'StdioClientTransport' });
            const context = buildTransportContext(transport as any); // Use 'as any' due to mock structure
            expect(context.transportType).toBe('stdio');
        });

        it('should detect sse transport type', () => {
            const transport = new MockTransport({ className: 'SSEServerTransport' });
            const context = buildTransportContext(transport as any);
            expect(context.transportType).toBe('sse');
        });

        it('should detect websocket transport type', () => {
             const transport = new MockTransport({ className: 'WebSocketClientTransport' });
             const context = buildTransportContext(transport as any);
             expect(context.transportType).toBe('websocket');
         });

         it('should detect in-memory transport type', () => {
             const transport = new MockTransport({ className: 'InMemoryTransport' });
             const context = buildTransportContext(transport as any);
             expect(context.transportType).toBe('in-memory');
         });

         it('should return unknown for unrecognized class names', () => {
             const transport = new MockTransport({ className: 'MyCustomTransport' });
             const context = buildTransportContext(transport as any);
             expect(context.transportType).toBe('unknown');
         });

        it('should include headers if present on transport', () => {
            const headers = { 'X-Test': 'value', 'Authorization': 'Bearer token' };
            const transport = new MockTransport({ className: 'SSEClientTransport', headers });
            const context = buildTransportContext(transport as any);
            expect(context.headers).toEqual(headers);
        });

        it('should include remoteAddress if present on transport', () => {
            const remoteAddress = '192.168.1.100';
            const transport = new MockTransport({ className: 'SSEClientTransport', remoteAddress });
            const context = buildTransportContext(transport as any);
            expect(context.remoteAddress).toBe(remoteAddress);
        });

        it('should include sessionId if present on transport', () => {
            const sessionId = 'session-xyz';
            const transport = new MockTransport({ className: 'SSEClientTransport', sessionId });
            const context = buildTransportContext(transport as any);
            expect(context.sessionId).toBe(sessionId);
        });

         it('should handle missing optional properties gracefully', () => {
             const transport = new MockTransport({ className: 'StdioServerTransport' }); // Stdio typically lacks headers/IP
             const context = buildTransportContext(transport as any);
             expect(context.headers).toBeUndefined();
             expect(context.remoteAddress).toBeUndefined();
             expect(context.sessionId).toBeUndefined();
         });
    });
});