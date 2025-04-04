/* eslint-disable @typescript-eslint/no-explicit-any */
import { TransportContext } from '../../types.js';

/**
 * Creates an immutable proxy for headers that silently ignores all mutations.
 * @param headers - The original headers object.
 * @returns An immutable proxy for the headers.
 */
export function createImmutableHeadersProxy(headers: Record<string, any> = {}): Record<string, any> {
    const originalHeaders = { ...headers }; // Clone to avoid modifying the original object directly
    return new Proxy(originalHeaders, {
        get(obj: any, key: string | symbol) {
            return obj[key];
        },
        set() {
            // Silently ignore all mutations
            return true;
        },
        deleteProperty() {
            // Silently ignore all deletions
            return true;
        },
        defineProperty() {
            // Silently ignore property definitions
            return true;
        },
        setPrototypeOf() {
            // Silently ignore prototype changes
            return true;
        },
        isExtensible() {
            return false;
        },
        preventExtensions() {
            return true;
        }
    });
}

/**
 * Creates an immutable proxy for the transport context, using an immutable headers proxy.
 * @param transportContext - The original transport context.
 * @returns An immutable proxy for the transport context.
 */
export function createImmutableTransportContextProxy(transportContext: TransportContext): TransportContext {
    const headersProxy = createImmutableHeadersProxy(transportContext.headers);
    const proxiedContext = { ...transportContext, headers: headersProxy };

    return new Proxy(proxiedContext, {
        get(target: any, prop: string | symbol) {
            return target[prop];
        },
        set(target: any, prop: string | symbol, value: any) {
            if (prop !== 'headers') {
                // Allow setting non-headers properties (e.g., during pipeline processing if needed, though generally discouraged)
                target[prop] = value;
            }
            // Always return true to avoid throwing
            return true;
        },
        // Optionally make the outer context proxy immutable too
        deleteProperty() {
            return false; // Prevent deletion of properties
        },
        defineProperty() {
            return false; // Prevent adding new properties
        },
        setPrototypeOf() {
            return false; // Prevent changing prototype
        },
        isExtensible() {
            return false;
        },
        preventExtensions(target) {
            Object.preventExtensions(target); // Prevent extensions on the target itself
            return true;
        }
    });
}