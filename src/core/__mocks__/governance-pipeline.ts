// src/core/__mocks__/governance-pipeline.ts
import { jest } from '@jest/globals';
import { Result } from '@modelcontextprotocol/sdk/types.js'; // Adjust path

const mockPipelineInstance = {
  executeRequestPipeline: jest.fn<() => Promise<Result>>().mockResolvedValue({ mockedResult: true }), // Default success
  executeNotificationPipeline: jest.fn<() => Promise<void>>().mockResolvedValue(undefined),
};

const GovernancePipeline = jest.fn().mockImplementation(() => {
  return mockPipelineInstance;
});

export { GovernancePipeline, mockPipelineInstance }; // Explicitly export both