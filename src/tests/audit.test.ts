/* eslint-disable @typescript-eslint/no-explicit-any */
// src/defaults/audit.test.ts
/* eslint-disable no-console */
import { NoOpAuditLogStore, ConsoleAuditLogStore, defaultAuditStore } from '../defaults/audit.js';
import { AuditRecord } from '../types.js'; // Adjust path as needed

describe('Default Audit Stores', () => {

    describe('NoOpAuditLogStore', () => {
        let store: NoOpAuditLogStore;

        beforeEach(() => {
            store = new NoOpAuditLogStore();
        });

        it('should have an initialize method that does nothing', async () => {
            await expect(store.initialize()).resolves.toBeUndefined();
        });

        it('should have a log method that does nothing', async () => {
            const record: AuditRecord = { eventId: '1', timestamp: '', transport: {transportType: 'test'}, mcp:{type:'request', method:'m'}, outcome: {status:'success'}, durationMs: 0 };
            await expect(store.log(record)).resolves.toBeUndefined();
        });

        it('should have a shutdown method that does nothing', async () => {
            await expect(store.shutdown()).resolves.toBeUndefined();
        });

        it('defaultAuditStore should be an instance of NoOpAuditLogStore', () => {
             expect(defaultAuditStore).toBeInstanceOf(NoOpAuditLogStore);
        });
    });

    describe('ConsoleAuditLogStore', () => {
        let store: ConsoleAuditLogStore;
        let logSpy: jest.SpyInstance;
        let errorSpy: jest.SpyInstance;

        beforeEach(() => {
            store = new ConsoleAuditLogStore();
            logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
            errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
        });

        afterEach(() => {
            logSpy.mockRestore();
            errorSpy.mockRestore();
        });

        it('should log initialization message', async () => {
            await store.initialize();
            expect(logSpy).toHaveBeenCalledWith("ConsoleAuditLogStore initialized");
        });

        it('should log the record as JSON string', async () => {
            const record: AuditRecord = {
                eventId: 'evt-123',
                timestamp: '2025-03-28T18:00:00Z',
                transport: { transportType: 'stdio' },
                mcp: { type: 'request', method: 'test/method', id: 1, params: { key: 'value' } },
                identity: 'user-abc',
                outcome: { status: 'success', mcpResponse: { result: { ok: true } } },
                durationMs: 123,
            };
            await store.log(record);

            expect(logSpy).toHaveBeenCalledTimes(1);
            expect(logSpy).toHaveBeenCalledWith(JSON.stringify(record));
        });

        it('should handle JSON stringify errors gracefully', async () => {
            const circularObj: any = { name: 'circular' };
            circularObj.self = circularObj; // Create circular reference
            const record: AuditRecord = {
                eventId: 'evt-err', timestamp: '', transport: {transportType: 'test'},
                mcp: { type: 'request', method: 'err', params: circularObj },
                outcome: { status: 'failure' }, durationMs: 0
            };

            await store.log(record);

            expect(logSpy).not.toHaveBeenCalled(); // Should not succeed logging
            expect(errorSpy).toHaveBeenCalledTimes(1); // Should call console.error
            expect(errorSpy).toHaveBeenCalledWith(
                "Failed to serialize or log audit record:",
                expect.any(TypeError), // The stringify error
                record // The original record
            );
        });

        it('should log shutdown message', async () => {
            await store.shutdown();
            expect(logSpy).toHaveBeenCalledWith("ConsoleAuditLogStore shutting down");
        });
    });
});