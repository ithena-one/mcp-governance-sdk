module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  plugins: ['@typescript-eslint', 'jest'],
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:jest/recommended',
    'prettier', // Add prettier last to override formatting rules
  ],
  env: {
    node: true,
    es2022: true,
    'jest/globals': true,
  },
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module',
  },
  rules: {
    // Add specific project rules here if needed
    '@typescript-eslint/no-explicit-any': 'warn', // Allow 'any' with warning
    '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_' }], // Allow unused vars starting with _
  },
}; 