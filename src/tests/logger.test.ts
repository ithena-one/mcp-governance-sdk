// src/defaults/logger.test.ts
/* eslint-disable no-console */
import { ConsoleLogger, defaultLogger } from '../defaults/logger.js';
import { LogContext } from '../interfaces/logger.js';

describe('ConsoleLogger', () => {
    let logger: ConsoleLogger;
    let logSpy: jest.SpyInstance;
    let warnSpy: jest.SpyInstance;
    let errorSpy: jest.SpyInstance;
    let debugSpy: jest.SpyInstance;
    let infoSpy: jest.SpyInstance;

    beforeEach(() => {
        // Spy on console methods before each test
        logSpy = jest.spyOn(console, 'log').mockImplementation(() => {}); // Suppress actual output
        warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
        errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
        debugSpy = jest.spyOn(console, 'debug').mockImplementation(() => {});
        infoSpy = jest.spyOn(console, 'info').mockImplementation(() => {});
    });

    afterEach(() => {
        // Restore original console methods after each test
        logSpy.mockRestore();
        warnSpy.mockRestore();
        errorSpy.mockRestore();
        debugSpy.mockRestore();
        infoSpy.mockRestore();
    });

    it('should initialize with default level info', () => {
        logger = new ConsoleLogger();
        // Use infoSpy for initialize message check
        logger.initialize(); // Call initialize after spies are set up
        expect(infoSpy).toHaveBeenCalledWith(expect.stringContaining("ConsoleLogger initialized"));
    });

    it('should respect minLevel setting', () => {
        logger = new ConsoleLogger({}, 'warn'); // Only log warn and error
        logger.debug('Debug message');
        logger.info('Info message');
        logger.warn('Warn message');
        logger.error('Error message');

        expect(debugSpy).not.toHaveBeenCalled();
        expect(infoSpy).not.toHaveBeenCalled();
        expect(warnSpy).toHaveBeenCalledTimes(1); // Called once for the warn message
        expect(errorSpy).toHaveBeenCalledTimes(1); // Called once for the error message
    });

    it('should log messages at or above minLevel (debug)', () => {
         logger = new ConsoleLogger({}, 'debug'); // Log everything
         logger.debug('Debug message');
         logger.info('Info message');
         logger.warn('Warn message');
         logger.error('Error message');

         expect(debugSpy).toHaveBeenCalledTimes(1);
         expect(infoSpy).toHaveBeenCalledTimes(1);
         expect(warnSpy).toHaveBeenCalledTimes(1);
         expect(errorSpy).toHaveBeenCalledTimes(1);
     });


    it('should log structured JSON with context', () => {
        logger = new ConsoleLogger({ base: 'ctx' }, 'info');
        const context: LogContext = { reqId: '123', user: 'test' };
        logger.info('User action', context);

        expect(infoSpy).toHaveBeenCalledTimes(1);
        const logArg = infoSpy.mock.calls[0][0];
        expect(() => JSON.parse(logArg)).not.toThrow(); // Check if it's valid JSON
        const logEntry = JSON.parse(logArg);

        expect(logEntry).toMatchObject({
            level: 'info',
            message: 'User action',
            base: 'ctx',
            reqId: '123',
            user: 'test',
        });
        expect(logEntry.timestamp).toBeDefined();
    });

    it('should log error object correctly', () => {
        logger = new ConsoleLogger({}, 'error');
        const error = new Error('Something failed');
        error.stack = 'mock stack trace'; // Mock stack for consistency
        logger.error('Operation failed', error, { op: 'testOp' });

        expect(errorSpy).toHaveBeenCalledTimes(1);
        const logArg = errorSpy.mock.calls[0][0];
        const logEntry = JSON.parse(logArg);

        expect(logEntry).toMatchObject({
            level: 'error',
            message: 'Operation failed',
            op: 'testOp',
            error: {
                message: 'Something failed',
                name: 'Error',
                stack: 'mock stack trace',
            },
        });
    });

     it('should log non-Error objects in error field', () => {
        logger = new ConsoleLogger({}, 'error');
        const nonError = { code: 500, detail: 'details' };
        logger.error('Non-error thrown', nonError);

        expect(errorSpy).toHaveBeenCalledTimes(1);
        const logArg = errorSpy.mock.calls[0][0];
        const logEntry = JSON.parse(logArg);

        expect(logEntry.error).toEqual(nonError);
    });


    it('should create child logger with inherited and new context', () => {
        logger = new ConsoleLogger({ base: 'ctx' }, 'info');
        const childLogger = logger.child({ reqId: '456' });
        childLogger.info('Child log', { extra: 'data' });

        expect(infoSpy).toHaveBeenCalledTimes(1);
        const logArg = infoSpy.mock.calls[0][0];
        const logEntry = JSON.parse(logArg);

        expect(logEntry).toMatchObject({
            level: 'info',
            message: 'Child log',
            base: 'ctx', // Inherited
            reqId: '456', // From child
            extra: 'data', // From call
        });
        expect(logEntry.timestamp).toBeDefined();
    });

    it('should handle console logging function potentially missing (fallback to console.log)', () => {
         // Temporarily remove console.debug
         const originalDebug = console.debug;
         // @ts-expect-error: Intentionally modifying console for test
         console.debug = undefined; // Instead of delete

         logger = new ConsoleLogger({}, 'debug');
         logger.debug('Debug message - fallback');

         expect(logSpy).toHaveBeenCalledTimes(1);
         const logArg = logSpy.mock.calls[0][0];
         const logEntry = JSON.parse(logArg);
         expect(logEntry.level).toBe('debug');
         expect(logEntry.message).toBe('Debug message - fallback');

         // Restore
         console.debug = originalDebug;
     });

    it('should call shutdown and log message', async () => {
        logger = new ConsoleLogger();
        await logger.shutdown();
        expect(infoSpy).toHaveBeenCalledWith(expect.stringContaining("ConsoleLogger shutting down"));
    });

    it('defaultLogger should be an instance of ConsoleLogger', () => {
        expect(defaultLogger).toBeInstanceOf(ConsoleLogger);
    });
});