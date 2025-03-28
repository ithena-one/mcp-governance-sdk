# Security Considerations

**Navigation:**
* [← Back to Default Implementations](./defaults.md)
* [Back to README →](../README.md)

The `@ithena/mcp-governance` SDK provides a framework for adding security and governance controls, but the overall security of your MCP server heavily depends on how you implement and configure its components. Please review these points carefully.

## 1. Authentication (`IdentityResolver`)

*   **SDK Role:** This SDK **facilitates** the use of identity but **does not perform authentication itself.**
*   **Your Responsibility:** Your `IdentityResolver` implementation is responsible for securely verifying the caller's identity based on credentials presented via the transport layer (e.g., HTTP headers, WebSocket context).
*   **Common Pitfalls:**
    *   **NEVER trust unvalidated headers** like `X-User-ID` or `X-API-Key` in production. Always validate tokens (JWT signature/expiry/issuer/audience), API keys (against a secure store), or session identifiers provided by a trusted authentication middleware/gateway.
    *   Ensure robust error handling during validation to prevent information leakage.
    *   Protect the communication channel (use TLS/HTTPS/WSS).
*   **Recommendations:** Integrate with standard authentication mechanisms like OAuth 2.0 / OpenID Connect (validating Bearer tokens), SAML, or use an API Gateway that handles authentication before forwarding requests to your MCP server.

## 2. Authorization (`RoleStore`, `PermissionStore`, `derivePermission`)

*   **Principle of Least Privilege:** Design your roles and permissions to grant only the minimum access necessary for users or systems to perform their tasks.
*   **Implementation Security:** Ensure your `RoleStore` and `PermissionStore` implementations securely fetch data and correctly enforce your access control rules. Protect the underlying data stores (databases, LDAP, etc.).
*   **Permission Granularity:** Review the `defaultDerivePermission` logic. If it's too coarse (e.g., `resource:read:*` grants too much), implement a custom `derivePermission` function that generates more specific permission strings based on request parameters (e.g., `resource:read:user_data/{userId}`). Be careful to validate parameters used in permission derivation.
*   **Complexity:** Complex authorization logic can be hard to reason about. Consider using established authorization models or integrating with dedicated policy engines (like Open Policy Agent - OPA) via your `PermissionStore`.

## 3. Credential Management (`CredentialResolver`)

*   **NEVER Hardcode Secrets:** Do not embed API keys, passwords, or other secrets directly in your code or configuration files.
*   **Secure Storage:** Your `CredentialResolver` must retrieve secrets from a secure, managed secrets store (e.g., HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager).
*   **Least Privilege:** Ensure the MCP server process itself has only the minimum necessary permissions to access the required secrets from the secrets manager.
*   **Rotation:** Implement regular rotation of secrets fetched by the `CredentialResolver`.
*   **Contextual Fetching:** Fetch credentials based on the specific needs of the operation (`opCtx.mcpMessage`) and potentially the identity (`identity`) to limit exposure.

## 4. Auditing and Logging (`AuditLogStore`, `Logger`, `sanitizeForAudit`)

*   **⚠️ Audit Sanitization is CRITICAL:** The most significant security risk with auditing is **logging sensitive data**.
    *   The `defaultSanitizeForAudit` provides **basic masking** but is likely **insufficient**. It may miss sensitive data specific to your application's request parameters, results, error details, or identity objects (e.g., PII like names, emails, addresses; financial data; proprietary business information; internal hostnames/IPs). It may also incorrectly mask non-sensitive data.
    *   **You MUST thoroughly review `defaultSanitizeForAudit` and implement a custom function tailored to your specific data structures and sensitivity requirements.**
    *   Test your sanitization logic rigorously with realistic data, including edge cases and error responses.
*   **Audit Log Storage:** Secure the storage location of your audit logs. Implement appropriate access controls and retention policies according to compliance requirements.
*   **Logging Sensitivity:** Be mindful of what you log via the `Logger`, even outside of formal auditing. Avoid logging full request/response payloads or sensitive data unless absolutely necessary and properly sanitized/masked. Use structured logging context wisely.

## 5. Input Validation

*   **Handler Schemas:** Always use Zod schemas (or equivalent validation) when registering handlers with `GovernedServer.setRequestHandler` and `GovernedServer.setNotificationHandler`. This ensures basic structure and type validation for incoming MCP messages *before* your handler code runs.
*   **Governance Component Inputs:** Validate any inputs used *within* your custom governance component implementations (e.g., parameters used in `derivePermission`, data queried by `RoleStore`). Do not implicitly trust data from the request or transport context without validation where necessary.

## 6. Error Handling

*   **Avoid Leaking Information:** Configure your MCP server and governance components to catch errors gracefully. Do not leak internal implementation details, stack traces, or sensitive data in error messages sent back to the client. Map internal errors to appropriate, generic JSON-RPC error responses.
*   **Monitor Errors:** Monitor audit logs and application logs for error patterns that might indicate security issues or attacks.

## 7. Dependencies

*   Keep `@ithena/mcp-governance`, `@modelcontextprotocol/sdk`, `zod`, and all other dependencies updated to patch potential security vulnerabilities. Use tools like `npm audit` or `yarn audit`.

## 8. Transport Security

*   Ensure the underlying MCP transport is secured using appropriate mechanisms like TLS (for SSE/WebSockets/HTTP) or other channel encryption methods, especially when transmitting sensitive data or authentication credentials.

By carefully implementing the governance components and following these security best practices, you can build robust and secure MCP applications using the `@ithena/mcp-governance` SDK.

**Navigation:**
* [← Back to Default Implementations](./defaults.md)
* [Back to README →](../README.md) 