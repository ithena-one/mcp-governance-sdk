import { AuditRecord } from '../types.js';

// Basic regex patterns for common secrets (adjust as needed for robustness)
const SECRET_PATTERNS = [
    /([a-z0-9]{_})?(key|token|secret|password|auth|credential)[a-z0-9_]*\s*[:=]\s*['"]?([a-zA-Z0-9_\-.~!*'();:@&=+$,/?%#[\]]+)['"]?/gi, // key=value, key: value
    /"(key|token|secret|password|auth|credential)":\s*"([^"]+)"/gi, // "key": "value"
    /Bearer\s+([a-zA-Z0-9_\-.~+/]+=*)/gi, // Bearer token
    /api[_-]?key/i, // Common key names
    /secret[_-]?key/i,
];
const MASK_STRING = '***MASKED***';
const MAX_STRING_LENGTH = 1024; // Max length before truncating values

function sanitizeValue(value: any): any {
    if (typeof value === 'string') {
        let sanitized = value;
        for (const pattern of SECRET_PATTERNS) {
            // Reset lastIndex for global regexes
            pattern.lastIndex = 0;
            sanitized = sanitized.replace(pattern, (match, _p1, _p2, p3) => {
                // Try to replace only the value part if capture groups are present
                if (p3) return match.replace(p3, MASK_STRING);
                // Otherwise, mask the whole match (less precise but safer)
                return MASK_STRING;
            });
        }
        // Simple check for Bearer tokens if not caught by regex
        if (sanitized.toLowerCase().startsWith('bearer ')) {
            sanitized = `Bearer ${MASK_STRING}`;
        }

        // Truncate long strings
        if (sanitized.length > MAX_STRING_LENGTH) {
            return sanitized.substring(0, MAX_STRING_LENGTH) + '...[TRUNCATED]';
        }
        return sanitized;
    } else if (Array.isArray(value)) {
        return value.map(sanitizeValue);
    } else if (value !== null && typeof value === 'object') {
        const sanitizedObj: Record<string, any> = {};
        for (const key in value) {
            if (Object.prototype.hasOwnProperty.call(value, key)) {
                // Also sanitize keys that look like secrets
                const lowerKey = key.toLowerCase();
                if (SECRET_PATTERNS.some(p => p.test(lowerKey))) {
                    sanitizedObj[key] = MASK_STRING;
                } else {
                    sanitizedObj[key] = sanitizeValue(value[key]);
                }
            }
        }
        return sanitizedObj;
    }
    return value; // Return primitives and null/undefined as is
}

/**
 * Default function to sanitize sensitive information from an AuditRecord
 * before logging. Masks common secret patterns and truncates long strings.
 * This is a basic implementation and may need enhancement for specific needs.
 * @param record - The partial or complete audit record.
 * @returns A sanitized version of the audit record.
 */
export function defaultSanitizeForAudit(record: Partial<AuditRecord>): Partial<AuditRecord> {
    const sanitized: Partial<AuditRecord> = { ...record };

    // Sanitize Headers (common place for Authorization tokens)
    if (sanitized.transport?.headers) {
        sanitized.transport.headers = sanitizeValue(sanitized.transport.headers);
    }

    // Sanitize MCP Params
    if (sanitized.mcp?.params) {
        sanitized.mcp.params = sanitizeValue(sanitized.mcp.params);
    }

    // Sanitize MCP Result (in case it contains sensitive data)
    if (sanitized.outcome?.mcpResponse?.result) {
        sanitized.outcome.mcpResponse.result = sanitizeValue(sanitized.outcome.mcpResponse.result);
    }

    // Sanitize Identity (if it's an object with potentially sensitive fields)
    if (sanitized.identity && typeof sanitized.identity === 'object') {
        sanitized.identity = sanitizeValue(sanitized.identity);
    }

    // Sanitize Error Details
    if (sanitized.outcome?.error?.details) {
        sanitized.outcome.error.details = sanitizeValue(sanitized.outcome.error.details);
    }

    return sanitized;
} 