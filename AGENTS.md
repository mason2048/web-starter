# Web Starter Development Guide

## Product boundary

- The repository, root Maven project, and workspace directory are named `web-starter`.
- The product name is `启程 Web Starter`.
- The project is a standalone, generic scaffold for internal Web management systems.
- Do not add public signup, billing, SaaS tenancy, an MCP client, arbitrary SQL, shell, filesystem, or dynamic code execution.
- Do not copy business modules, business vocabulary, credentials, or source code from unrelated projects.

## Architecture

- Java 21 and Spring Boot 4.1 are the runtime baseline.
- Spring Security 7 is the only security framework. Do not add a second authentication framework.
- Web sessions, OAuth access tokens, personal access tokens, and service-account tokens must resolve to the same caller contract and permission service.
- REST and MCP adapters must call the same application services and participate in the same transaction and audit boundaries.
- MySQL is the source of truth. Redis is limited to sessions, short-lived caches, and coordination data that can be rebuilt.
- Modules may depend inward on `web-starter-core`; domain modules must not depend on `web-starter-admin`.
- Keep `web-starter-core` small. Do not turn it into a general dumping ground.

## Security requirements

- Never commit a real password, API key, private key, token, or production hostname.
- Store long-lived token material as a one-way keyed hash; plaintext is displayed only at creation time.
- External MCP access uses OAuth 2.1. Direct PAT and service-account tokens are intended for the private ingress.
- Permission decisions are the intersection of current RBAC permissions and credential scopes.
- Every MCP call and state-changing Web request must have a trace ID and an auditable outcome.
- Production configuration is injected through `WEB_STARTER_` environment variables.

## Quality gates

- Keep unit, integration, container, browser, and protocol-conformance results separate in reports.
- Backend: `./mvnw verify` (or `mvn verify` before the wrapper exists).
- Frontend: `pnpm lint && pnpm typecheck && pnpm test && pnpm build`.
- Runtime acceptance must exercise a real login, a Project CRUD transaction, an authorization failure, and an MCP tool call.
- A successful build is not proof that deployment, migration, authentication, or the end-to-end workflow works.

## Change discipline

- Flyway migrations are append-only after release; never edit an applied production migration.
- Preserve module boundaries and avoid cyclic dependencies.
- Prefer explicit DTOs at transport boundaries over exposing persistence entities.
- Add or update tests with behavior changes.
- Keep documentation and `.env.example` synchronized with required configuration.
