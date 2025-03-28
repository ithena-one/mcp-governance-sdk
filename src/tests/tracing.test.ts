// src/defaults/tracing.test.ts
import { defaultTraceContextProvider } from '../defaults/tracing.js';
import { Request } from '@modelcontextprotocol/sdk/types.js';

describe('Default Trace Context Provider', () => {
    const mockMessage: Request = { method: 'test' }; // Message content doesn't matter for default provider

    it('should return undefined if no headers are present', () => {
        const transportContext: TransportContext = { transportType: 'http', headers: undefined };
        expect(defaultTraceContextProvider(transportContext, mockMessage)).toBeUndefined();
    });

     it('should return undefined if traceparent header is missing', () => {
         const transportContext: TransportContext = { transportType: 'http', headers: { 'other': 'value' } };
         expect(defaultTraceContextProvider(transportContext, mockMessage)).toBeUndefined();
     });

    it('should parse valid traceparent header correctly', () => {
        const traceparent = '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01';
        const transportContext: TransportContext = { transportType: 'http', headers: { 'traceparent': traceparent } };
        const traceContext = defaultTraceContextProvider(transportContext, mockMessage);
        expect(traceContext).toEqual({
            traceId: '0af7651916cd43dd8448eb211c80319c',
            parentSpanId: 'b7ad6b7169203331',
            spanId: undefined, // Not derived from traceparent
            traceFlags: '01',
            traceState: undefined, // No tracestate header provided
        });
    });

    it('should include tracestate if present', () => {
        const traceparent = '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01';
        const tracestate = 'rojo=00f067aa0ba902b7,congo=t61rcWkgMzE';
        const transportContext: TransportContext = {
            transportType: 'http',
            headers: { 'traceparent': traceparent, 'tracestate': tracestate }
        };
        const traceContext = defaultTraceContextProvider(transportContext, mockMessage);
        expect(traceContext).toEqual(expect.objectContaining({
            traceState: tracestate,
        }));
    });

    it('should return undefined for invalid traceparent format', () => {
        const invalidTraceparents = [
            'invalid-string',
            '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331', // Missing flags
            '00-shorttraceid-shortspanid-01',
            '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01-extra',
        ];
        for (const tp of invalidTraceparents) {
            const transportContext: TransportContext = { transportType: 'http', headers: { 'traceparent': tp } };
            expect(defaultTraceContextProvider(transportContext, mockMessage)).toBeUndefined();
        }
    });

    it('should return undefined for unsupported traceparent version', () => {
        const traceparent = '01-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01'; // Version 01
        const transportContext: TransportContext = { transportType: 'http', headers: { 'traceparent': traceparent } };
        expect(defaultTraceContextProvider(transportContext, mockMessage)).toBeUndefined();
    });

     it('should handle array headers (using first traceparent)', () => {
        const traceparent1 = '00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01';
         const traceparent2 = '00-cccccccccccccccccccccccccccccccc-dddddddddddddddd-00';
         const transportContext: TransportContext = {
             transportType: 'http',
             headers: { 'traceparent': [traceparent1, traceparent2] }
         };
         const traceContext = defaultTraceContextProvider(transportContext, mockMessage);
         expect(traceContext).toEqual(expect.objectContaining({
             traceId: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
             parentSpanId: 'bbbbbbbbbbbbbbbb',
             traceFlags: '01',
         }));
     });

    it('should handle array headers (concatenating tracestate)', () => {
        const traceparent = '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01';
        const tracestate1 = 'foo=bar';
        const tracestate2 = 'baz=qux';
        const transportContext: TransportContext = {
            transportType: 'http',
            headers: { 'traceparent': traceparent, 'tracestate': [tracestate1, tracestate2] }
        };
        const traceContext = defaultTraceContextProvider(transportContext, mockMessage);
        expect(traceContext).toEqual(expect.objectContaining({
            traceState: `${tracestate1},${tracestate2}`,
        }));
    });
});
import { TransportContext } from '../types.js';
