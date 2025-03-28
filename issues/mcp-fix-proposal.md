# MCP Protocol Fix Proposal: Preserving Request Parameters

This document outlines a proposed fix for the issue where request parameters are lost during transmission through the MCP protocol pipeline.

## Proposed Fix

The fix should be implemented in the base MCP SDK, specifically in the request processing pipeline. Based on our analysis, we believe the issue occurs during JSON-RPC message processing.

### Approach 1: Fix in Protocol.ts

The most likely location of the issue is in the `protocol.ts` file of the MCP SDK, which handles JSON-RPC message processing. The fix would involve ensuring that empty params objects are preserved rather than being stripped during serialization/deserialization.

```typescript
// Pseudocode for fixing in protocol.ts (request method)
export async function request<T>(this: Client, request: Request, responseSchema: z.ZodType<T>): Promise<T> {
  // Create a proper JSON-RPC message
  const message: JSONRPCRequest = {
    jsonrpc: '2.0',
    id: this._nextId++,
    method: request.method,
    // ISSUE: Ensure params is always included, even if it's an empty object
    params: request.params || {},  // <-- Fix: Always include params, don't omit if empty
  };
  
  // Rest of method remains the same...
}
```

### Approach 2: Fix in Request Handler Creation

Another possible location is when the request handler is created and dispatched:

```typescript
// Pseudocode for fixing in BaseServer's handler creation
private _createRequestHandler(method: string, handler: RequestHandler): (request: JSONRPCRequest) => Promise<Result> {
  return async (request: JSONRPCRequest): Promise<Result> => {
    // ISSUE: Ensure request.params exists before passing to handler
    const requestWithParams = {
      ...request,
      params: request.params || {},  // <-- Fix: Always include params, don't omit if empty
    };
    
    // Then use requestWithParams when calling the handler
    const result = await handler(requestWithParams, { signal, sessionId });
    return result;
  };
}
```

## Testing the Fix

To verify the fix works, we need to add a test that specifically checks for preservation of empty or missing params:

```typescript
// Test to verify params are preserved
it('should preserve empty params object during request processing', async () => {
  // Setup server and client
  const server = new Server({ name: 'TestServer', version: '1.0' });
  
  // Set up a handler that explicitly checks for params existence
  const handlerSpy = jest.fn().mockResolvedValue({ success: true });
  server.setRequestHandler('test/params', handlerSpy);
  
  // Connect server and client
  await Promise.all([
    server.connect(serverTransport),
    client.connect(clientTransport)
  ]);
  
  // Send a request with empty params
  await client.request({ method: 'test/params', params: {} });
  
  // Check that handler was called with params object (not undefined)
  expect(handlerSpy).toHaveBeenCalledWith(
    expect.objectContaining({
      method: 'test/params',
      params: {},  // Params should be an empty object, not undefined
    }),
    expect.anything()
  );
  
  // Send a request with undefined params
  await client.request({ method: 'test/params' });
  
  // Check that handler was called with params object (not undefined)
  expect(handlerSpy).toHaveBeenCalledWith(
    expect.objectContaining({
      method: 'test/params',
      params: {},  // Params should be an empty object, not undefined
    }),
    expect.anything()
  );
});
```

## Implementation Plan

1. **Locate the exact issue in the MCP SDK**:
   - Debug the request flow from client to server to identify where params are lost
   - Add diagnostic logging to the SDK to track request structure changes

2. **Implement and test the fix in MCP SDK**:
   - Make the suggested code changes in the appropriate location
   - Run tests to verify the fix works
   - Ensure backward compatibility with existing handlers

3. **Release an updated version of the MCP SDK**:
   - Submit a pull request with the fix
   - Document the issue and fix in the release notes
   - Update dependencies in the governance SDK

## Temporary Workaround (in SDK)

Until the MCP SDK is fixed, we can implement a workaround in the `GovernedServer` class that enhances requests before they reach handlers:

```typescript
// Proposed workaround in GovernedServer
private _createPipelineRequestHandler(method: string): (req: JSONRPCRequest, baseExtra: BaseRequestHandlerExtra) => Promise<Result> {
  return async (request: JSONRPCRequest, baseExtra: BaseRequestHandlerExtra): Promise<Result> => {
    // Create a new request with guaranteed params
    const enhancedRequest = {
      ...request,
      params: request.params || {},
    };
    
    // Then use enhancedRequest in the pipeline
    return await this.pipeline.executeRequestPipeline(enhancedRequest, baseExtra, operationContext, auditRecord);
  };
}
```

This workaround would fix the issue for all handlers registered with the `GovernedServer`, but would not affect handlers registered directly with the base `Server`. 