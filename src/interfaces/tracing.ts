import { TransportContext, TraceContext } from '../types.js';
import { Request, Notification } from '@modelcontextprotocol/sdk/types.js';

/**
 * Function type for extracting distributed tracing context from incoming requests.
 * @param transportContext - Context about the transport layer.
 * @param mcpMessage - The raw incoming MCP Request or Notification.
 * @returns The extracted TraceContext, or undefined if none is found.
 */
export type TraceContextProvider = (
    transportContext: TransportContext,
    mcpMessage: Request | Notification
) => TraceContext | undefined; 