import { Logger, LogLevel, TraceContext } from '../interfaces.js'; // Adjust path

// Helper to get log level from environment variable or default
function getLogLevel(): LogLevel {
    const envLevel = process.env.MCP_GOVERNANCE_LOG_LEVEL?.toUpperCase();
    switch (envLevel) {
        case 'DEBUG':
            return LogLevel.DEBUG;
        case 'INFO':
            return LogLevel.INFO;
        case 'WARN':
            return LogLevel.WARN;
        case 'ERROR':
            return LogLevel.ERROR;
        default:
            return LogLevel.INFO; // Default log level
    }
}

/**
 * Default logger implementation that writes structured JSON to the console.
 * Supports log levels settable via `MCP_GOVERNANCE_LOG_LEVEL` environment variable
 * (DEBUG, INFO, WARN, ERROR - defaults to INFO).
 * Includes trace context and supports child loggers with merged context.
 */
export class ConsoleLogger implements Logger {
    private readonly minLevel: LogLevel;
    private readonly baseContext: Record<string, any>;

    /**
     * Creates a ConsoleLogger instance.
     * @param minLevel Minimum log level to output. Defaults to `INFO` or `MCP_GOVERNANCE_LOG_LEVEL` env var.
     * @param baseContext Optional base context to include in all log entries.
     */
    constructor(minLevel?: LogLevel, baseContext: Record<string, any> = {}) {
        this.minLevel = minLevel ?? getLogLevel();
        this.baseContext = baseContext;
    }

    /** Logs a message if its level meets the configured minimum. */
    log(
        level: LogLevel,
        message: string,
        data?: Record<string, any>,
        traceContext?: TraceContext
    ): void {
        if (level < this.minLevel) {
            return;
        }

        const levelString = LogLevel[level]?.toUpperCase() || 'UNKNOWN';

        const logEntry: Record<string, any> = {
            level: levelString,
            message,
            timestamp: new Date().toISOString(),
            ...this.baseContext, // Include base context from constructor
        };

        // Add trace context if available
        if (traceContext?.traceId) logEntry.traceId = traceContext.traceId;
        if (traceContext?.spanId) logEntry.spanId = traceContext.spanId;

        // Merge provided data, ensuring core fields aren't easily overwritten
        if (data) {
            for (const key in data) {
                if (
                    !['level', 'message', 'timestamp', 'traceId', 'spanId'].includes(key) &&
                    !(key in this.baseContext) // Allow baseContext to override data
                ) {
                    logEntry[key] = data[key];
                } else if (!(key in this.baseContext)) {
                    // Only warn if data tries to overwrite a core field *not* already in baseContext
                    console.warn(`[ConsoleLogger] Attempted to overwrite core log field '${key}' in log data`);
                }
            }
        }

        const output = JSON.stringify(logEntry);

        // Use appropriate console method
        switch (level) {
            case LogLevel.ERROR:
                console.error(output);
                break;
            case LogLevel.WARN:
                console.warn(output);
                break;
            case LogLevel.INFO:
                console.info(output);
                break;
            case LogLevel.DEBUG:
                // Fallback to console.log if console.debug is not available/visible
                console.debug ? console.debug(output) : console.log(output);
                break;
            default:
                console.log(output);
        }
    }

    // --- Convenience Methods ---
    debug(
        message: string,
        data?: Record<string, any>,
        traceContext?: TraceContext
    ): void {
        this.log(LogLevel.DEBUG, message, data, traceContext);
    }
    info(
        message: string,
        data?: Record<string, any>,
        traceContext?: TraceContext
    ): void {
        this.log(LogLevel.INFO, message, data, traceContext);
    }
    warn(
        message: string,
        data?: Record<string, any>,
        traceContext?: TraceContext
    ): void {
        this.log(LogLevel.WARN, message, data, traceContext);
    }
    error(
        message: string,
        error?: Error,
        data?: Record<string, any>,
        traceContext?: TraceContext
    ): void {
        const errorData: Record<string, any> = {};
        if (error) {
             errorData.errorMessage = error.message;
             errorData.errorName = error.name;
             // Optionally include error code if it exists (e.g., from McpError)
             if ((error as any).code !== undefined) {
                 errorData.errorCode = (error as any).code;
             }
             // Avoid including full stack traces in structured logs by default
             // errorData.errorStack = error.stack;
        }
        this.log(LogLevel.ERROR, message, { ...errorData, ...data }, traceContext);
    }

    /** Creates a child logger instance with additional context merged in. */
    child(context: Record<string, any>): Logger {
        const newBaseContext = { ...this.baseContext, ...context };
        return new ConsoleLogger(this.minLevel, newBaseContext);
    }
} 