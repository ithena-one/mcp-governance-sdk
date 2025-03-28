# Configuration Options (`GovernedServerOptions`)

You configure the behavior of the `@ithena/mcp-governance` SDK by passing an options object to the `GovernedServer` constructor.

```typescript
import { GovernedServer, GovernedServerOptions } from '@ithena/mcp-governance';
import { Server as BaseServer } from '@modelcontextprotocol/sdk/server';

const baseServer = new BaseServer({ name: "MyServer", version: "1.0" });

const options: GovernedServerOptions = {
    // ... your configuration options ...
    logger: myCustomLogger,
    identityResolver: myIdentityResolver,
    enableRbac: true,
    // ... etc
};

const governedServer = new GovernedServer(baseServer, options);
```

Below are the available options:

| Option                          | Type                                                            | Default                     | Description                                                                                                                               | Required For |
| :------------------------------ | :-------------------------------------------------------------- | :-------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------- | :----------- |
| `identityResolver`              | `IdentityResolver`                                              | `undefined`                 | Your implementation to resolve the caller's identity from the request context (e.g., headers, tokens). See **[Interfaces](./interfaces.md#identityresolver)**. | RBAC         |
| `roleStore`                     | `RoleStore`                                                     | `undefined`                 | Your implementation to fetch the roles associated with a resolved identity. See **[Interfaces](./interfaces.md#rolestore)**.                  | RBAC         |
| `permissionStore`               | `PermissionStore`                                               | `undefined`                 | Your implementation to check if a role grants a specific permission string. See **[Interfaces](./interfaces.md#permissionstore)**.       | RBAC         |
| `credentialResolver`            | `CredentialResolver`                                            | `undefined`                 | Your implementation to securely fetch credentials (secrets, API keys) needed by handlers. See **[Interfaces](./interfaces.md#credentialresolver)**. | -            |
| `auditStore`                    | `AuditLogStore`                                                 | `NoOpAuditLogStore`         | Your implementation to log detailed audit records. Defaults to doing nothing. See **[Interfaces](./interfaces.md#auditlogstore)**.            | Auditing     |
| `logger`                        | `Logger`                                                        | `ConsoleLogger`             | A structured logger instance. Defaults to logging JSON to the console. See **[Interfaces](./interfaces.md#logger)**.                      | Logging      |
| `traceContextProvider`          | `TraceContextProvider`                                          | `defaultTraceContextProvider` | Extracts distributed tracing context (e.g., W3C `traceparent`). Defaults to checking headers. See **[Interfaces](./interfaces.md#tracecontextprovider)**. | Tracing      |
| `enableRbac`                    | `boolean`                                                       | `false`                     | Set to `true` to activate the RBAC checks in the pipeline. Requires `identityResolver`, `roleStore`, and `permissionStore` to be provided. | RBAC         |
| `failOnCredentialResolutionError` | `boolean`                                                       | `true`                      | If `true`, requests will fail if the `credentialResolver` throws an error. If `false`, errors are logged, and the pipeline continues.       | -            |
| `auditDeniedRequests`           | `boolean`                                                       | `true`                      | If `true`, audit records are generated and sent to the `auditStore` even for requests that were denied by RBAC.                         | Auditing     |
| `auditNotifications`            | `boolean`                                                       | `false`                     | If `true`, audit records are generated and sent to the `auditStore` for incoming MCP notifications. Requires `auditStore` and `sanitizeForAudit`. | Auditing     |
| `derivePermission`              | `(req: Request, transportCtx: TransportContext) => string \| null` | `defaultDerivePermission`   | A function that generates the permission string (e.g., `tool:call:my_tool`) needed for a specific request. Return `null` to skip the permission check for that request. See **[Authorization](./authorization.md)**. | RBAC         |
| `sanitizeForAudit`              | `(record: AuditRecord) => AuditRecord`                          | `defaultSanitizeForAudit`   | **CRITICAL:** A function to remove or mask sensitive data (PII, secrets) from the `AuditRecord` before it's logged. **Review the default implementation carefully.** See **[Auditing & Logging](./auditing-logging.md)**. | Auditing     |
| `postAuthorizationHook`         | `(identity: UserIdentity, opCtx: OperationContext) => Promise<void>` | `undefined`                 | An optional asynchronous function called after a request passes authorization checks (or if RBAC is disabled/not applicable). Can be used for secondary checks or setup based on identity. | -            |
| `serviceIdentifier`             | `string`                                                        | `undefined`                 | An optional string identifying this specific instance of your MCP server. Included in logs and audit records for easier correlation.       | -            |

**Important Notes:**

*   If `enableRbac` is `true`, you **must** provide implementations for `identityResolver`, `roleStore`, and `permissionStore`. Failure to do so will result in an error during `GovernedServer` instantiation.
*   Effective auditing requires providing an `auditStore` and carefully reviewing/customizing `sanitizeForAudit`.
*   Replace default in-memory stores and basic resolvers/loggers with production-grade implementations. See **[Defaults](./defaults.md)** and **[Security](./security.md)**. 