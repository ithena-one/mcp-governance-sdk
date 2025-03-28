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
                logEntry.error = error;
            }
        }

        // Use console[level] if it exists, otherwise fallback to console.log
        const logFn = console[level as keyof Console] || console.log;
        logFn(JSON.stringify(logEntry));
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
}

/** Default logger instance */
export const defaultLogger: Logger = new ConsoleLogger(); 