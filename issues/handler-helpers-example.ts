/* eslint-disable @typescript-eslint/no-unused-vars */
import { z } from 'zod';
import { GovernedServer } from '../src/core/governed-server.js';
import { withSafeParams, withFallbackParams, withRecoveredParams } from '../src/utils/handler-helpers.js';

// Define your request schema - note that params is optional to handle MCP protocol issue
const helloHandlerSchema = z.object({
  method: z.literal('example/hello'),
  params: z.object({
    name: z.string(),
    age: z.number().optional(),
  }).optional(), // Make params optional due to MCP protocol issue
  id: z.any(),
}).passthrough();

// Example 1: Using withSafeParams - Will throw an error if params is missing
const helloHandlerWithSafeParams = withSafeParams(async (params, req, extra) => {
  // This handler will never run with undefined params
  // We can safely use params.name without checking
  return {
    message: `Hello ${params.name}, from ${extra.identity || 'Unknown'}!`,
    age: params.age ? `You are ${params.age} years old.` : 'Age not provided.'
  };
});

// Example 2: Using withFallbackParams - Will use default values if params is missing
const helloHandlerWithFallback = withFallbackParams(
  { name: 'Guest', age: undefined },
  async (params, req, extra) => {
    // This handler will run with the default params if the originals are missing
    return {
      message: `Hello ${params.name}, from ${extra.identity || 'Unknown'}!`,
      age: params.age ? `You are ${params.age} years old.` : 'Age not provided.'
    };
  }
);

// Example 3: Using withRecoveredParams - Will attempt to recover params from context
const helloHandlerWithRecovery = withRecoveredParams(async (params, req, extra) => {
  // This handler attempts to recover params, but they might still be undefined
  if (!params || !params.name) {
    return {
      message: 'Hello anonymous user, please provide a name next time!',
      error: 'Missing name parameter'
    };
  }
  
  return {
    message: `Hello ${params.name}, from ${extra.identity || 'Unknown'}!`,
    age: params.age ? `You are ${params.age} years old.` : 'Age not provided.'
  };
});

// Register with your governed server
function configureServer(server: GovernedServer) {
  // Choose one of the handlers above based on your needs
  server.setRequestHandler(helloHandlerSchema, helloHandlerWithFallback);
  
  // You can register different handlers with different strategies
  // server.setRequestHandler(otherSchema, withSafeParams(otherHandler));
}

// How to use the handler in a client
async function clientExample() {
  // This code would be in your client application
  
  // Normal request (params may be lost in transmission)
  const response1 = await client.request(
    { method: 'example/hello', params: { name: 'Alice', age: 30 } },
    z.object({ message: z.string(), age: z.string() })
  );
  console.log(response1); // { message: "Hello Alice, from bob!", age: "You are 30 years old." }
  
  // Missing params (handler will use fallbacks)
  const response2 = await client.request(
    { method: 'example/hello' }, // No params!
    z.object({ message: z.string(), age: z.string() })
  );
  console.log(response2); // { message: "Hello Guest, from bob!", age: "Age not provided." }
} 