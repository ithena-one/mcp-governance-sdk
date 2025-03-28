/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unused-vars */
// src/core/__mocks__/@modelcontextprotocol/sdk/server/index.ts
import { jest } from '@jest/globals';
import { Request, Notification, Result, JSONRPCRequest, JSONRPCNotification, InitializeRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import { RequestHandlerExtra as BaseRequestHandlerExtra } from '@modelcontextprotocol/sdk/shared/protocol.js';
import { z } from 'zod';

// Mock implementation for the base Server class
const mockServerInstance = {
    connect: jest.fn<() => Promise<void>>().mockResolvedValue(undefined),
    close: jest.fn<() => Promise<void>>().mockResolvedValue(undefined),
    setRequestHandler: jest.fn<any>(), // Use 'any' for simplicity in mock
    setNotificationHandler: jest.fn<any>(),
    notification: jest.fn<() => Promise<void>>().mockResolvedValue(undefined),
    onclose: undefined as (() => void) | undefined, // Property to allow setting/spying
    onerror: undefined as ((error: Error) => void) | undefined,
    oninitialized: undefined as (() => void) | undefined,
    // Add any other methods/properties used by GovernedServer if necessary
};

// Mock the class constructor to return our mock instance
const Server = jest.fn().mockImplementation(() => {
    return mockServerInstance;
});

// Export other necessary types if GovernedServer imports them directly from this module
export { InitializeRequestSchema, Server, mockServerInstance }; 