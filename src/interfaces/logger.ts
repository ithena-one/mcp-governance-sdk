/** Log severity levels. */
export type LogLevel = "debug" | "info" | "warn" | "error";

/** Context object for structured logging. */
export type LogContext = Record<string, any>;

/**
 * Interface for a structured logger used within the SDK and passed to handlers.
 */
export interface Logger {
    /** Optional initialization logic (e.g., setting up remote transport). */
    initialize?(): Promise<void>;

    /** Logs a debug message. */
    debug(message: string, context?: LogContext): void;
    /** Logs an informational message. */
    info(message: string, context?: LogContext): void;
    /** Logs a warning message. */
    warn(message: string, context?: LogContext): void;
    /** Logs an error message, optionally including an Error object. */
    error(message: string, error?: Error | unknown, context?: LogContext): void;

    /**
     * Optional: Creates a child logger. Required for request scoping.
     * If not provided, the same logger instance will be used everywhere.
     * @param bindings - Context key-value pairs to add to the child logger.
     * @returns A new Logger instance.
     */
    child?: (bindings: LogContext) => Logger;

    /** Optional cleanup logic (e.g., flushing buffers). */
    shutdown?(): Promise<void>;
} 