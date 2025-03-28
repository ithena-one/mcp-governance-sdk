/* eslint-disable no-console */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { Logger, LogLevel, LogContext } from '../interfaces/logger.js';

/**
 * A simple logger implementation that writes structured JSON to the console.
 */
export class ConsoleLogger implements Logger {
    private baseContext: LogContext;
    private minLevel: LogLevel;

    private levelMap: Record<LogLevel, number> = {
        debug: 10,
        info: 20,
        warn: 30,
        error: 40,
    };

    constructor(baseContext: LogContext = {}, minLevel: LogLevel = 'info') {
        this.baseContext = baseContext;
        this.minLevel = minLevel;
    }

    async initialize(): Promise<void> {
        // Optional: Log initialization
        this.info("ConsoleLogger initialized");
    }

    private shouldLog(level: LogLevel): boolean {
        return this.levelMap[level] >= this.levelMap[this.minLevel];
    }

    private log(level: LogLevel, message: string, context?: LogContext, error?: Error | unknown): void {
        if (!this.shouldLog(level)) {
            return;
        }

        const logEntry: Record<string, any> = {
            level,
            timestamp: new Date().toISOString(),
            message,
            ...this.baseContext,
            ...context,
        };

        if (error) {
            if (error instanceof Error) {
                logEntry.error = {
                    message: error.message,
                    name: error.name,
                    stack: error.stack, // Consider if stack is too verbose for prod
                };
            } else {
                logEntry.error = error; // Log non-Error types as is
            }
        }

        // Use console[level] if it exists and is a function, otherwise fallback to console.log
        let logFn: (...data: any[]) => void = console.log;
        if (level in console && typeof console[level as keyof Console] === 'function') {
             // eslint-disable-next-line @typescript-eslint/ban-types
             logFn = console[level as keyof Console] as Function as (...data: any[]) => void;
        }

        try {
            logFn(JSON.stringify(logEntry));
        } catch (stringifyError) {
            // Fallback if stringify fails (e.g., circular reference)
            console.error("Failed to stringify log entry, logging raw:", stringifyError, logEntry);
        }
    }

    debug(message: string, context?: LogContext): void {
        this.log('debug', message, context);
    }

    info(message: string, context?: LogContext): void {
        this.log('info', message, context);
    }

    warn(message: string, context?: LogContext): void {
        this.log('warn', message, context);
    }

    error(message: string, error?: Error | unknown, context?: LogContext): void {
        this.log('error', message, context, error);
    }

    child(bindings: LogContext): Logger {
        // Create a new logger instance with merged context
        return new ConsoleLogger({ ...this.baseContext, ...bindings }, this.minLevel);
    }

    async shutdown(): Promise<void> {
        // Optional: Log shutdown
        this.info("ConsoleLogger shutting down");
        // No specific action needed for console
    }
}

/** Default logger instance */
export const defaultLogger: Logger = new ConsoleLogger();