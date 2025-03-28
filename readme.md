# @ithena/mcp-governance

Enterprise Governance Layer for the Model Context Protocol SDK.

## Features

- 🔒 **Role-Based Access Control (RBAC)**: Fine-grained access control with roles and permissions
- 🔑 **Identity Resolution**: Flexible identity management with support for string IDs or structured objects
- 📝 **Audit Logging**: Comprehensive audit trails for all operations
- 🎯 **Credential Management**: Secure handling of external credentials and API keys
- 📊 **Observability**: Built-in logging and tracing support
- 🔌 **Pluggable Architecture**: Easy to extend with custom implementations

## Installation

```bash
npm install @ithena/mcp-governance
```

## Quick Start

```typescript
import { createGovernedServer } from '@ithena/mcp-governance';
import {
    InMemoryRoleStore,
    InMemoryPermissionStore,
    ConsoleLogger,
    ConsoleAuditLogStore,
} from '@ithena/mcp-governance/defaults';

// Create a governed server
const server = createGovernedServer({
    // Use console-based implementations for logging and auditing
    logger: new ConsoleLogger(),
    auditLogStore: new ConsoleAuditLogStore(),

    // Use in-memory stores for roles and permissions
    roleStore: new InMemoryRoleStore(),
    permissionStore: new InMemoryPermissionStore(),

    // Define your handlers
    handlers: {
        'echo': async (params, context) => {
            context.logger.info('Executing echo', { params });
            return params;
        },
    },
});

// Execute a method
const result = await server.execute('user-123', 'echo', {
    message: 'Hello, World!',
});
```

## Documentation

### Core Concepts

#### Identity Resolution

The SDK supports flexible identity resolution through the `IdentityResolver` interface:

```typescript
interface IdentityResolver {
    resolveIdentity(operationContext: OperationContext): Promise<UserIdentity | null>;
}
```

Built-in implementations:
- `PassThroughIdentityResolver`: Returns the identity unchanged
- `StrictIdentityResolver`: Validates identity format

#### Role-Based Access Control

RBAC is implemented through two main interfaces:

```typescript
interface RoleStore {
    getRoles(identity: UserIdentity, context?: OperationContext): Promise<string[]>;
}

interface PermissionStore {
    hasPermission(role: string, permission: string, context?: OperationContext): Promise<boolean>;
    getPermissions?(role: string, context?: OperationContext): Promise<string[]>;
}
```

Built-in implementations:
- `InMemoryRoleStore`: Simple in-memory role storage
- `InMemoryPermissionStore`: Simple in-memory permission storage

#### Credential Resolution

Secure credential management through the `CredentialResolver` interface:

```typescript
interface CredentialResolver {
    resolveCredentials(
        identity: UserIdentity | null,
        operationContext: OperationContext
    ): Promise<Record<string, any> | null>;
}
```

#### Audit Logging

Comprehensive audit trails through the `AuditLogStore` interface:

```typescript
interface AuditLogStore {
    log(record: AuditRecord): Promise<void>;
    shutdown?(): Promise<void>;
}
```

Built-in implementations:
- `ConsoleAuditLogStore`: Logs to console in JSON format
- `NoOpAuditLogStore`: Discards audit logs

### Examples

Check out the [examples](./examples) directory for more detailed examples:

- [Basic Usage](./examples/basic.ts): Simple example of creating and using a governed server
- [RBAC](./examples/rbac.ts): Complete example of role-based access control

### Configuration

The `createGovernedServer` function accepts a comprehensive set of options:

```typescript
interface GovernedServerOptions {
    // Core Components
    identityResolver?: IdentityResolver;
    roleStore?: RoleStore;
    permissionStore?: PermissionStore;
    credentialResolver?: CredentialResolver;
    auditStore?: AuditLogStore;
    logger?: Logger;

    // Feature Flags
    enableRbac?: boolean;
    failOnCredentialResolutionError?: boolean;
    auditDeniedRequests?: boolean;
    auditNotifications?: boolean;

    // Customization Hooks
    derivePermission?: (message: JSONRPCRequest | JSONRPCNotification) => string | null;
    sanitizeForAudit?: (key: string, value: any, record: Partial<AuditRecord>) => any;
    postAuthorizationHook?: (identity: UserIdentity | null, context: OperationContext) => Promise<void>;
}
```

## Development

### Prerequisites

- Node.js >= 18.0.0
- npm >= 7.0.0

### Setup

1. Clone the repository
2. Install dependencies:
   ```bash
   npm install
   ```

### Testing

Run the test suite:

```bash
npm test
```

Run with coverage:

```bash
npm run test:coverage
```

### Building

Build the package:

```bash
npm run build
```

### Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

Apache 2.0 - See [LICENSE](./LICENSE) for more information.