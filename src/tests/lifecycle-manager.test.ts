// src/core/lifecycle-manager.test.ts
import { LifecycleManager } from '../core/utils/lifecycle-manager.js';
import { Logger } from '../interfaces/logger.js';
import type { LifecycleComponent } from '../core/utils/lifecycle-manager.js';

// --- Mock Components ---

// Mock Logger (simple version for lifecycle tests)
const mockLogger: Logger = {
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    // No child needed for these tests
};

// Mock Component with Lifecycle methods
class MockLifecycleComponent implements Logger {
    name: string;
    initialize = jest.fn();
    shutdown = jest.fn();
    debug = jest.fn();
    info = jest.fn();
    warn = jest.fn();
    error = jest.fn();

    constructor(name: string) {
        this.name = name;
        // Default mock implementations (can be overridden in tests)
        this.initialize.mockResolvedValue(undefined);
        this.shutdown.mockResolvedValue(undefined);
    }
    // Helper to simulate initialization failure
    failInitialize(error = new Error('Init failed')) {
        this.initialize.mockRejectedValue(error);
    }
     // Helper to simulate shutdown failure
     failShutdown(error = new Error('Shutdown failed')) {
        this.shutdown.mockRejectedValue(error);
    }
}

// Mock Component without Lifecycle methods
class MockNonLifecycleComponent {
    name: string;
    constructor(name: string) { this.name = name; }
    // No initialize or shutdown
}


describe('LifecycleManager', () => {
    let mockComponent1: MockLifecycleComponent;
    let mockComponent2: MockLifecycleComponent;
    let mockComponent3: MockNonLifecycleComponent;
    let manager: LifecycleManager;

    beforeEach(() => {
        // Reset mocks before each test
        jest.clearAllMocks();

        mockComponent1 = new MockLifecycleComponent('Comp1');
        mockComponent2 = new MockLifecycleComponent('Comp2');
        mockComponent3 = new MockNonLifecycleComponent('Comp3'); // No lifecycle methods

    });

    it('should filter out undefined components during construction', () => {
        const components = [mockComponent1, undefined, mockComponent2] as (LifecycleComponent | undefined)[];
        manager = new LifecycleManager(mockLogger, components);
        // Internal check - not directly testable, but initialize/shutdown tests verify it
        expect(manager['components'].length).toBe(2);
    });

    it('should ignore components without lifecycle methods', () => {
        const components = [mockComponent1, mockComponent3, mockComponent2] as (LifecycleComponent | undefined)[];
        manager = new LifecycleManager(mockLogger, components);
        expect(manager['components'].length).toBe(2);
    });

    describe('initialize', () => {
        it('should call initialize() on components that have it', async () => {
            const components = [mockComponent1, mockComponent2] as LifecycleComponent[];
            manager = new LifecycleManager(mockLogger, components);

            await manager.initialize();

            expect(mockComponent1.initialize).toHaveBeenCalledTimes(1);
            expect(mockComponent2.initialize).toHaveBeenCalledTimes(1);
            expect(mockLogger.debug).toHaveBeenCalledWith(expect.stringContaining('Initializing Comp1'));
            expect(mockLogger.debug).toHaveBeenCalledWith(expect.stringContaining('Initializing Comp2'));
        });

        it('should call initialize() methods sequentially', async () => {
             const callOrder: string[] = [];
             mockComponent1.initialize.mockImplementation(async () => { callOrder.push('comp1'); });
             mockComponent2.initialize.mockImplementation(async () => { callOrder.push('comp2'); });

             const components = [mockComponent1, mockComponent2];
             manager = new LifecycleManager(mockLogger, components);
             await manager.initialize();

             expect(callOrder).toEqual(['comp1', 'comp2']);
        });


        it('should throw and stop initialization if a component fails to initialize', async () => {
            const initError = new Error('Component 1 failed');
            mockComponent1.failInitialize(initError);

            const components = [mockComponent1, mockComponent2];
            manager = new LifecycleManager(mockLogger, components);

            await expect(manager.initialize()).rejects.toThrow(`Failed to initialize component Comp1: ${initError.message}`);

            expect(mockComponent1.initialize).toHaveBeenCalledTimes(1);
            expect(mockComponent2.initialize).not.toHaveBeenCalled(); // Should stop after failure
            expect(mockLogger.error).toHaveBeenCalledWith('Failed to initialize Comp1', initError);
            expect(manager.getInitializedComponents()).toEqual([]); // Nothing should be tracked as initialized
        });

        it('should track successfully initialized components', async () => {
            const components = [mockComponent1, mockComponent2] as LifecycleComponent[];
            manager = new LifecycleManager(mockLogger, components);

            const initialized = await manager.initialize();

            // Check returned array and internal state
            expect(initialized).toHaveLength(2);
            expect(initialized).toContain(mockComponent1);
            expect(initialized).toContain(mockComponent2);
            expect(manager.getInitializedComponents()).toEqual(initialized);
        });
    });

    describe('shutdown', () => {
        beforeEach(async () => {
             // Initialize successfully before shutdown tests
             const components = [mockComponent1, mockComponent2] as LifecycleComponent[];
             manager = new LifecycleManager(mockLogger, components);
             await manager.initialize();
             // Clear initialize mocks if needed, or reset all mocks
             jest.clearAllMocks(); // Reset mocks after successful init
         });

        it('should call shutdown() only on successfully initialized components that have it', async () => {
            await manager.shutdown();

            expect(mockComponent1.shutdown).toHaveBeenCalledTimes(1);
            expect(mockComponent2.shutdown).toHaveBeenCalledTimes(1);
            // mockComponent3 has no shutdown
            expect(mockLogger.debug).toHaveBeenCalledWith(expect.stringContaining('Calling shutdown for Comp1'));
            expect(mockLogger.debug).toHaveBeenCalledWith(expect.stringContaining('Calling shutdown for Comp2'));
        });

        it('should call shutdown() methods in parallel (mocked verification)', async () => {
            // Hard to test true parallelism precisely, but ensure both are called
            // before the main shutdown promise resolves.
            let comp1ShutdownFinished = false;
            let comp2CalledBeforeComp1Finished = false;

            mockComponent1.shutdown.mockImplementation(async () => {
                 await new Promise(res => setTimeout(res, 50)); // Simulate delay
                 comp1ShutdownFinished = true;
            });
            mockComponent2.shutdown.mockImplementation(async () => {
                if (!comp1ShutdownFinished) {
                     comp2CalledBeforeComp1Finished = true;
                }
            });

            await manager.shutdown();

            expect(mockComponent1.shutdown).toHaveBeenCalled();
            expect(mockComponent2.shutdown).toHaveBeenCalled();
            // This assertion verifies parallel execution
            expect(comp2CalledBeforeComp1Finished).toBe(true);
        });


        it('should log errors during shutdown but not throw', async () => {
            const shutdownError = new Error('Component 2 failed shutdown');
            mockComponent2.failShutdown(shutdownError);

            await expect(manager.shutdown()).resolves.toBeUndefined(); // Should still resolve

            expect(mockComponent1.shutdown).toHaveBeenCalledTimes(1);
            expect(mockComponent2.shutdown).toHaveBeenCalledTimes(1);
            expect(mockLogger.error).toHaveBeenCalledWith('Error during Comp2.shutdown()', { error: shutdownError });
            expect(mockLogger.debug).toHaveBeenCalledWith(expect.stringContaining('Comp1 shut down successfully')); // Comp1 should still finish
        });

        it('should clear the list of initialized components after shutdown', async () => {
            expect(manager.getInitializedComponents()).toHaveLength(2); // Before shutdown
            await manager.shutdown();
            expect(manager.getInitializedComponents()).toHaveLength(0); // After shutdown
        });

         it('should do nothing if no components were initialized', async () => {
             const emptyManager = new LifecycleManager(mockLogger, []);
             await emptyManager.initialize(); // Initialize with empty list
             jest.clearAllMocks();

             await emptyManager.shutdown();

             expect(mockLogger.debug).toHaveBeenCalledWith("No initialized components to shut down.");
             expect(mockComponent1.shutdown).not.toHaveBeenCalled();
             expect(mockComponent2.shutdown).not.toHaveBeenCalled();
         });
    });
});