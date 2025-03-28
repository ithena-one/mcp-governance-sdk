/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  preset: 'ts-jest/presets/default-esm', // Use ESM preset
  testEnvironment: 'node',
  moduleNameMapper: {
    // Handle ESM import paths with .js extension
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  transform: {
    '^.+\\.tsx?$': [
      'ts-jest',
      {
        useESM: true,
      },
    ],
  },
  extensionsToTreatAsEsm: ['.ts'],
  // If needed, specify extensions Jest should look for
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
  // Define roots for Jest to find source and test files
  roots: ['<rootDir>/src', '<rootDir>/tests'],
  // Test files matching pattern
  testMatch: ['**/tests/**/*.test.ts'],
  // Collect coverage from source files
  collectCoverageFrom: ['src/**/*.ts'],
  coverageDirectory: 'coverage',
  coverageProvider: 'v8', // Or 'babel'
}; 