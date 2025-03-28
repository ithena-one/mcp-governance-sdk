// Core Class
export { GovernedServer } from './core/governed-server.js';
export type {
    GovernedServerOptions,
    GovernedRequestHandler,
    GovernedNotificationHandler
} from './core/governed-server.js';

// Interfaces
export type { IdentityResolver } from './interfaces/identity.js';
export type { RoleStore, PermissionStore } from './interfaces/rbac.js';
export type { CredentialResolver } from './interfaces/credentials.js';
export type { AuditLogStore } from './interfaces/audit.js';
export type { Logger, LogLevel, LogContext } from './interfaces/logger.js';
export type { TraceContextProvider } from './interfaces/tracing.js';

// Data Types
export type {
    UserIdentity,
    ResolvedCredentials,
    TransportContext,
    TraceContext,
    OperationContext,
    GovernedRequestHandlerExtra,
    GovernedNotificationHandlerExtra,
    AuditRecord
} from './types.js';

// Errors
export {
    GovernanceError,
    AuthenticationError,
    AuthorizationError,
    CredentialResolutionError,
    HandlerError
} from './errors/index.js';

// Default Implementations & Helpers
export { ConsoleLogger, defaultLogger } from './defaults/logger.js';
export { NoOpAuditLogStore, ConsoleAuditLogStore, defaultAuditStore } from './defaults/audit.js';
export { defaultTraceContextProvider } from './defaults/tracing.js';
export {
    defaultDerivePermission,
    InMemoryRoleStore,
    InMemoryPermissionStore
} from './defaults/permissions.js';
export { defaultSanitizeForAudit } from './defaults/sanitization.js';
export { generateEventId, buildTransportContext } from './utils/helpers.js'; 