/* eslint-disable @typescript-eslint/no-explicit-any */
import { McpError, ErrorCode as McpErrorCode } from '@modelcontextprotocol/sdk/types.js';
import { GovernedRequestHandlerExtra } from '../types.js';

/**
 * Wraps a handler function to ensure params are present before the handler is executed.
 * If params are missing, throws a standard MCP InvalidParams error.
 * 
 * @template T The expected type of the params object
 * @param handler A function that receives the params object as its first argument
 * @returns A wrapped handler that guarantees params exists
 * 
 * @example
 * const myHandler = withSafeParams<{ name: string }>(async (params, req, extra) => {
 *   // Safe to use params.name here without checking
 *   return { greeting: `Hello ${params.name}` };
 * });
 */
export function withSafeParams<T = Record<string, any>>(
  handler: (params: T, req: any, extra: GovernedRequestHandlerExtra) => Promise<any>
) {
  return async (req: any, extra: GovernedRequestHandlerExtra) => {
    if (!req.params) {
      throw new McpError(
        McpErrorCode.InvalidParams, 
        "Missing required parameters. The MCP protocol may have lost the params during transmission."
      );
    }
    return handler(req.params as T, req, extra);
  };
}

/**
 * Wraps a handler function to ensure params are present, or use a fallback value if missing.
 * Unlike withSafeParams, this never throws for missing params.
 * 
 * @template T The expected type of the params object
 * @param fallbackParams The fallback params object to use if params are missing
 * @param handler A function that receives the params object as its first argument
 * @returns A wrapped handler that guarantees params exists
 * 
 * @example
 * const myHandler = withFallbackParams<{ name: string }>(
 *   { name: "Anonymous" },
 *   async (params, req, extra) => {
 *     // params.name will be "Anonymous" if the client didn't provide it
 *     return { greeting: `Hello ${params.name}` };
 *   }
 * );
 */
export function withFallbackParams<T = Record<string, any>>(
  fallbackParams: T,
  handler: (params: T, req: any, extra: GovernedRequestHandlerExtra) => Promise<any>
) {
  return async (req: any, extra: GovernedRequestHandlerExtra) => {
    const params = req.params || fallbackParams;
    return handler(params as T, req, extra);
  };
}

/**
 * Attempts to recover params from the operation context if they're missing from the request.
 * This is a more advanced utility that tries to restore the original params that might have
 * been lost during transmission.
 * 
 * @template T The expected type of the params object
 * @param handler A function that receives the params object as its first argument
 * @returns A wrapped handler that attempts to recover params from context
 * 
 * @example
 * const myHandler = withRecoveredParams<{ name: string }>(async (params, req, extra) => {
 *   // params will be recovered from operationContext.mcpMessage if possible
 *   return { greeting: `Hello ${params.name}` };
 * });
 */
export function withRecoveredParams<T = Record<string, any>>(
  handler: (params: T | undefined, req: any, extra: GovernedRequestHandlerExtra) => Promise<any>
) {
  return async (req: any, extra: GovernedRequestHandlerExtra) => {
    // Attempt to recover params from mcpMessage if available in context and is exposed to handlers
    const operationContext = extra as any;
    const originalMessage = operationContext?.mcpMessage;
    const params = req.params || originalMessage?.params;
    
    return handler(params as T | undefined, req, extra);
  };
} 