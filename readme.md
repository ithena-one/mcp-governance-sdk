<p align="center">
  <img src="./public/logo-white.png" alt="Ithena Logo" width="200">
</p>

# MCP Governance SDK (@ithena-one/mcp-governance)

[![NPM Version](https://img.shields.io/npm/v/%40ithena-one%2Fmcp-governance)](https://www.npmjs.com/package/@ithena-one/mcp-governance)
[![NPM Downloads](https://img.shields.io/npm/dt/@ithena-one/mcp-governance)](https://www.npmjs.com/package/@ithena-one/mcp-governance)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![X Follow](https://img.shields.io/twitter/follow/andellvan?style=social)](https://x.com/andellvan)

<a href="https://www.producthunt.com/posts/ithena?embed=true&utm_source=badge-featured&utm_medium=badge&utm_souce=badge-ithena" target="_blank"><img src="https://api.producthunt.com/widgets/embed-image/v1/featured.svg?post_id=948880&theme=light&t=1743628801037" alt="Ithena - AuthN&#0044;&#0032;AuthZ&#0044;&#0032;RBAC&#0044;&#0032;Auditing&#0044;&#0032;&#0038;&#0032;Compliance&#0032;Framework&#0032;for&#0032;MCP | Product Hunt" style="width: 250px; height: 54px;" width="250" height="54" /></a>

<!-- [![Build Status](https://img.shields.io/github/actions/workflow/status/ithena-one/mcp-governance/ci.yml?branch=main)](https://github.com/ithena-one/mcp-governance/actions/workflows/ci.yml) -->
<!-- Add build status badge once CI is set up -->

**Website:** [ithena.one](https://ithena.one)

**The missing governance layer for your Model Context Protocol (MCP) servers.**

Build secure, compliant, and observable MCP applications with [Ithena](https://ithena.one). Easily add **Identity, Authorization (RBAC), Credential Management, Auditing, Logging, and Tracing** using our SDK for servers built with [`@modelcontextprotocol/typescript-sdk`](https://github.com/modelcontextprotocol/typescript-sdk), or leverage the upcoming **Ithena Managed Platform** (waitlist open!).

---

**📚 Documentation:**

*   **[Getting Started](./docs/getting-started.md)** - Quick start guide with a complete example
*   **[Tutorial: Identity & RBAC](./docs/tutorial.md)** - Step-by-step guide to implementing core governance features
*   **[Core Concepts](./docs/core-concepts.md)** - Understanding the SDK's architecture and pipeline
*   **[Configuration](./docs/configuration.md)** - All available options and their usage
*   **[Interfaces](./docs/interfaces.md)** - Extensibility points and custom implementations
*   **[Authorization](./docs/authorization.md)** - RBAC system and permission management
*   **[Auditing & Logging](./docs/auditing-logging.md)** - Observability and compliance features
*   **[Default Implementations](./docs/defaults.md)** - Built-in components (development only)
*   **[Security Considerations](./docs/security.md)** - Security best practices and warnings

---

## The Problem: Production MCP Needs More

The standard [`@modelcontextprotocol/sdk`](https://github.com/modelcontextprotocol/typescript-sdk) is excellent for implementing the core MCP communication protocol. However, deploying MCP servers in production, especially in enterprise environments, requires addressing critical governance questions:

*   ❓ **Who** is accessing data and tools? (Authentication)
*   🔒 Are they **allowed** to do that? (Authorization)
*   🔑 How do handlers securely access needed **secrets**? (Credentials)
*   📝 **What happened**? (Auditing & Compliance)
*   🩺 How do we **monitor and debug** effectively? (Logging & Tracing)

Implementing these consistently across every MCP server is complex and error-prone.

## The Solution: `@ithena-one/mcp-governance`

This SDK provides a standard, pluggable framework that wraps the base `Server` class, letting you integrate essential governance features without rewriting your core MCP logic.

Ithena offers two ways to achieve this: the **open-source SDK** (`@ithena-one/mcp-governance`) for self-hosting, and the upcoming **Ithena Managed Platform** (currently accepting users via a [waitlist](https://ithena.one#platform)) which provides hosted, production-ready backends for the SDK's interfaces, eliminating infrastructure management.

**Benefits:**

*   ✅ **Standardize Governance:** Consistent handling of identity, permissions, secrets, and auditing.
*   🔒 **Enhance Security:** Enforce access controls and securely manage credentials.
*   📝 **Meet Compliance:** Generate detailed audit trails for regulatory requirements.
*   🧩 **Pluggable Architecture:** Integrate easily with your existing enterprise systems (IDPs, Secret Managers, SIEMs) via well-defined interfaces. (See **[Interfaces](./docs/interfaces.md)**)
*   ⚙️ **Focus on Business Logic:** Let the SDK handle governance boilerplate, allowing your team to focus on building valuable MCP resources, tools, and prompts.
*   🚀 **Faster Development:** Get production-ready features out-of-the-box with sensible defaults for development and testing. (See **[Defaults](./docs/defaults.md)**)
*   ☁️ **Optional Managed Platform:** Skip infrastructure setup and management by using the Ithena Managed Platform (join the [waitlist](https://ithena.one#platform)!).

## Key Features

*   🆔 **Pluggable Identity Resolution** (`IdentityResolver`)
*   🛡️ **Flexible Role-Based Access Control** (`RoleStore`, `PermissionStore`)
*   🔑 **Secure Credential Injection** (`CredentialResolver`)
*   ✍️ **Comprehensive Auditing** (`AuditLogStore`)
*   🪵 **Structured, Request-Scoped Logging** (`Logger`)
*   🔗 **Trace Context Propagation** (W3C default via `TraceContextProvider`)
*   ⚙️ **Configurable Governance Pipeline** (See **[Core Concepts](./docs/core-concepts.md)**)
*   📦 **Minimal Intrusion** (Wraps the base SDK `Server`)

## Architecture Overview

`@ithena-one/mcp-governance` intercepts incoming MCP requests and notifications, processing them through a defined pipeline before (or during) the execution of your business logic handlers.

```mermaid
graph LR
    A[MCP Request In] --> B(Context Setup: EventID, Logger, TraceContext);
    B --> C{IdentityResolver?};
    C -- Yes --> D[Resolve Identity];
    C -- No --> E[Identity = null];
    D --> E;
    E --> F{RBAC Enabled?};
    F -- No --> K[Credential Resolution];
    F -- Yes --> G{Identity Resolved?};
    G -- No --> H(DENY: Identity Required);
    G -- Yes --> I[Derive Permission];
    I --> J{Permission Check Needed?};
    J -- No (null permission) --> L{Post-Auth Hook?};
    J -- Yes --> J1[Get Roles];
    J1 --> J2[Check Permissions];
    J2 -- Denied --> H2(DENY: Insufficient Permission);
    J2 -- Granted --> L;
    L -- Yes --> M[Execute Hook];
    L -- No --> K;
    M --> K;
    K -- Yes (Resolver Exists) --> N[Resolve Credentials];
    K -- No --> O[Credentials = null/undefined];
    N -- Error & failOnError=true --> P(FAIL: Credentials Error);
    N -- Error & failOnError=false --> O;
    N -- Success --> O;
    O --> Q[Execute Governed Handler];
    Q -- Success --> R[Result];
    Q -- Error --> S(FAIL: Handler Error);
    R --> T(Send Response);
    S --> T;
    P --> T;
    H --> T;
    H2 --> T;
    T --> U(Audit Log);

    style H fill:#f99,stroke:#333,stroke-width:2px;
    style H2 fill:#f99,stroke:#333,stroke-width:2px;
    style P fill:#f99,stroke:#333,stroke-width:2px;
    style S fill:#f99,stroke:#333,stroke-width:2px;
    style U fill:#ccf,stroke:#333,stroke-width:1px,stroke-dasharray: 5 5;
```

See **[Core Concepts](./docs/core-concepts.md)** for more details on the pipeline.

The SDK defines interfaces (like `IdentityResolver`, `AuditLogStore`, etc.). You can implement these yourself or use clients connecting to the **Ithena Managed Platform** (waitlist open) for a hosted solution.

## SDK vs. Managed Platform

Ithena offers flexibility in how you implement MCP governance:

1.  **`@ithena-one/mcp-governance` SDK (Open Source):**
    *   Provides the core `GovernedServer`, pipeline, and governance interfaces (`IdentityResolver`, `RoleStore`, `AuditLogStore`, etc.).
    *   You implement the backend logic for these interfaces, integrating with your existing systems (databases, secret managers, SIEMs).
    *   **Use Case:** Full control over infrastructure, integrating deeply with bespoke internal systems. Requires infrastructure management.

2.  **Ithena Managed Platform (Waitlist Open):**
    *   A hosted cloud service providing production-ready, scalable backend implementations for the SDK's interfaces via simple API clients.
    *   Use the same SDK, but configure it to point to the Ithena Platform APIs instead of your own backends.
    *   **Use Case:** Faster time-to-market, reduced operational burden, focus purely on MCP application logic.
    *   ➡️ **[Join the Waitlist](https://ithena.one#platform)**

You choose the approach that best fits your needs. The SDK seamlessly supports both self-hosted and platform-based backends.

## Installation

```bash
npm install @ithena-one/mcp-governance @modelcontextprotocol/sdk zod
# or
yarn add @ithena-one/mcp-governance @modelcontextprotocol/sdk zod
# or
pnpm add @ithena-one/mcp-governance @modelcontextprotocol/sdk zod
```

**Peer Dependencies:** Make sure you have compatible versions of `@modelcontextprotocol/sdk` (check `peerDependencies` in `package.json`) and `zod` installed.

## Quick Start

See the **[Getting Started Guide](./docs/getting-started.md)** for a runnable example.

## Next Steps

*   Understand the **[Core Concepts](./docs/core-concepts.md)** like `GovernedServer` and the pipeline.
*   Review the **[Configuration Options](./docs/configuration.md)** available.
*   Explore the **[Interfaces](./docs/interfaces.md)** to integrate with your systems.
*   Learn about **[Authorization](./docs/authorization.md)** and **[Auditing/Logging](./docs/auditing-logging.md)**.
*   Review the **[Security Considerations](./docs/security.md)** carefully.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on the [GitHub repository](https://github.com/ithena-one/mcp-governance-sdk).

## License

This project is licensed under the Apache-2.0 License. See the [LICENSE](LICENSE) file for details.
