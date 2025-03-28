/* eslint-disable @typescript-eslint/no-explicit-any */
// src/core/__mocks__/lifecycle-manager.ts
import { jest } from '@jest/globals';

export const mockLifecycleManagerInstance = {
  initialize: jest.fn<() => Promise<any[]>>().mockResolvedValue([]),
  shutdown: jest.fn<() => Promise<void>>().mockResolvedValue(undefined),
  getInitializedComponents: jest.fn<() => any[]>().mockReturnValue([]),
};

export const LifecycleManager = jest.fn().mockImplementation(() => {
  return mockLifecycleManagerInstance;
});