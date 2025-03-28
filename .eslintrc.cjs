module.exports = {
    root: true,
    parser: '@typescript-eslint/parser',
    plugins: [
      '@typescript-eslint',
    ],
    extends: [
      'eslint:recommended',
      'plugin:@typescript-eslint/recommended',
    ],
    rules: {
      // Add specific rules or overrides here
      '@typescript-eslint/no-explicit-any': 'warn', // Prefer specific types but allow any for flexibility initially
      '@typescript-eslint/no-unused-vars': ['warn', { 'argsIgnorePattern': '^_', 'varsIgnorePattern': '^_' }],
      '@typescript-eslint/explicit-module-boundary-types': 'off', // Can be enabled later for stricter typing
      'no-console': 'warn', // Discourage direct console logging in library code (prefer injected logger)
    },
    env: {
      node: true,
      es2021: true
    },
    parserOptions: {
      ecmaVersion: 2021,
      sourceType: 'module'
    },
  }; 