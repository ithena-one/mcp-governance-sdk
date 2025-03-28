// src/defaults/sanitization.ts
/* eslint-disable @typescript-eslint/no-explicit-any */
import { AuditRecord } from '../types.js';

// Patterns for field *keys* that strongly indicate sensitive data.
const SECRET_KEY_PATTERNS = [
    /(api[_-]?key|webhook[_-]?key)$/i,  // Ends with api_key, apiKey, webhook_key, webhookKey
    /(secret[_-]?key|user[_-]?key)$/i,  // Ends with secret_key, secretKey, user_key, userKey
    /secret$/i,             // Ends with secret
    /password$/i,           // Ends with password
    /token$/i,              // Ends with token
    /(credential|principal)s?$/i, // Ends with credential(s) or principal(s)
    /^private[_-]?key$/i,    // Exact match for private_key / privateKey
    /^client[_-]?secret$/i,  // Exact match
    /^auth[_-]?token$/i,     // Exact match
];

// Keywords that indicate sensitive data when part of a field name
const SENSITIVE_KEY_PARTS = [
    'key', 'secret', 'token', 'password', 'credential'
];

const MASK_STRING = '***MASKED***';
const MAX_STRING_LENGTH = 1024;

// Non-sensitive terms that might contain sensitive keywords
const NON_SENSITIVE_TERMS = new Set([
    'tokenizer', 'keyboard', 'passthrough', 'secretariat', 'keystone',
    'authorization', 'authentication', 'author', 'authenticated',
    'custom-auth', 'auth_method', 'auth-method'
]);

/** Checks if a field key indicates sensitive data. */
function isSecretKey(key: string): boolean {
    const lowerKey = key.toLowerCase();

    // 1. Check non-sensitive terms first
    if (NON_SENSITIVE_TERMS.has(lowerKey)) {
        return false;
    }

    // 2. Check specific patterns
    if (SECRET_KEY_PATTERNS.some(pattern => pattern.test(key))) {
        return true;
    }

    // 3. Check for sensitive parts in compound words
    // Only match if the sensitive part is a complete word
    const parts = key.split(/[_-]|(?=[A-Z])/).map(p => p.toLowerCase());
    return parts.some(part => 
        SENSITIVE_KEY_PARTS.includes(part) && 
        // Ensure it's not part of a larger word
        parts.every(otherPart => 
            otherPart === part || 
            !otherPart.includes(part)
        )
    );
}

/** Recursively checks if an object contains any sensitive keys. */
function containsSecretKey(obj: any): boolean {
    if (typeof obj !== 'object' || obj === null) return false;

    return Object.keys(obj).some(key => {
        // Skip checking known safe keys
        if (NON_SENSITIVE_TERMS.has(key.toLowerCase())) {
            return false;
        }

        if (isSecretKey(key)) return true;
        const value = obj[key];
        if (typeof value === 'object' && value !== null) {
            return containsSecretKey(value);
        }
        return false;
    });
}

function sanitizeValue(value: any, key?: string): any {
    // 1. Handle null/undefined
    if (value === null || value === undefined) {
        return value;
    }

    // 2. Handle non-string primitives
    if (typeof value !== 'object' && typeof value !== 'string') {
        return value;
    }

    // 3. Handle strings
    if (typeof value === 'string') {
        // Check if key indicates sensitive data
        if (key && isSecretKey(key)) {
            return value === '' ? '' : MASK_STRING;
        }

        // Special handling for Bearer tokens
        const bearerMatch = value.match(/^Bearer\s+(.+)$/i);
        if (bearerMatch && bearerMatch[1]) {
            return `Bearer ${MASK_STRING}`;
        }

        // Truncate long strings
        if (value.length > MAX_STRING_LENGTH) {
            return value.substring(0, MAX_STRING_LENGTH) + '...[TRUNCATED]';
        }

        return value;
    }

    // 4. Handle arrays
    if (Array.isArray(value)) {
        return value.map(item => sanitizeValue(item));
    }

    // 5. Handle objects
    const sanitizedObj: Record<string, any> = {};
    for (const k in value) {
        if (Object.prototype.hasOwnProperty.call(value, k)) {
            sanitizedObj[k] = sanitizeValue(value[k], k);
        }
    }
    return sanitizedObj;
}

/**
 * Default function to sanitize sensitive information from an AuditRecord
 * before logging. Masks common secret patterns and truncates long strings.
 */
export function defaultSanitizeForAudit(record: Partial<AuditRecord>): Partial<AuditRecord> {
    const sanitized: Partial<AuditRecord> = { ...record };

    // Sanitize Headers
    if (sanitized.transport?.headers) {
        sanitized.transport.headers = sanitizeValue(sanitized.transport.headers);
    }

    // Sanitize MCP Params
    if (sanitized.mcp?.params) {
        sanitized.mcp.params = sanitizeValue(sanitized.mcp.params);
    }

    // Sanitize MCP Result
    if (sanitized.outcome?.mcpResponse?.result) {
        sanitized.outcome.mcpResponse.result = sanitizeValue(sanitized.outcome.mcpResponse.result);
    }

    // Sanitize Identity Object
    if (sanitized.identity) {
        if (typeof sanitized.identity === 'object') {
            // Only mask if it contains actual secrets, not just auth_method etc.
            if (containsSecretKey(sanitized.identity)) {
                sanitized.identity = MASK_STRING;
            } else {
                sanitized.identity = sanitizeValue(sanitized.identity);
            }
        }
        // String identities remain unchanged
    }

    // Sanitize Error Details
    if (sanitized.outcome?.error?.details) {
        sanitized.outcome.error.details = sanitizeValue(sanitized.outcome.error.details);
    }

    return sanitized;
}