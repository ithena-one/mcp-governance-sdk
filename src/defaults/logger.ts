/* eslint-disable no-console */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { Logger, LogLevel, LogContext } from '../interfaces/logger.js';

type ConsoleMethod = (message?: any, ...args: any[]) => void;

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

    private getConsoleMethod(level: LogLevel): ConsoleMethod {
        let method: ConsoleMethod;
        switch (level) {
            case 'debug':
                method = typeof console.debug === 'function' ? console.debug : console.log;
                break;
            case 'info':
                method = typeof console.info === 'function' ? console.info : console.log;
                break;
            case 'warn':
                method = typeof console.warn === 'function' ? console.warn : console.log;
                break;
            case 'error':
                method = typeof console.error === 'function' ? console.error : console.log;
                break;
            default:
                method = console.log;
        }
        if (typeof method !== 'function') {
            method = console.log;
        }
        return method.bind(console);
    }

    log(level: LogLevel, message: string, context?: LogContext, error?: Error | unknown): void {
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
                    stack: error.stack,
                };
            } else {
                logEntry.error = error;
            }
        }

        const jsonString = JSON.stringify(logEntry);
        const consoleMethod = this.getConsoleMethod(level);

        try {
            consoleMethod(jsonString);
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