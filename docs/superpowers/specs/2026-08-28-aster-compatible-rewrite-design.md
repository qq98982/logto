# Aster Behavioral-Compatibility Rewrite Design

Date: 2026-08-28

Status: Approved design

Reference implementation commit: `6852a7b8c8984c5c12b2061e8c51faa310a36412`

Reference release: Logto v1.42.0 plus the Box AI branding and WeChat connector changes present at the reference commit

## 1. Purpose

Replace the runnable open-source Logto product at the pinned reference commit with a predominantly Rust implementation while preserving client-observable behavior. Existing applications, SDKs, the React Console, the React sign-in Experience, and the Management API must continue to work without compatibility changes.

The rewrite is a new implementation of published behavior, not a line-by-line translation of the TypeScript repository. Rust owns identity state, authorization, protocol orchestration, persistence, keys, and the Management API. Restricted Node compatibility hosts initially execute existing npm connectors, selected SAML operations, custom JWT scripts, and Actions. These workloads have separate processes, credentials, and privilege profiles.

The baseline is immutable. Features added to upstream Logto after the reference commit are separate product work and do not silently expand this program.

### 1.1 Project identity

The new implementation's neutral engineering codename is **Aster**. New Rust crates, binaries, container images, Compose services and project names, environment-variable namespaces, runtime directories, logs, metrics, and deployment artifacts use `aster` or `ASTER_`; they do not use the upstream product name.

The upstream name remains only where technical or legal accuracy requires it: license and source attribution, the pinned behavioral oracle, inherited upstream package names or filesystem paths, compatibility statements, and references to existing public APIs or applications. The codename does not change any client-observable issuer, endpoint, API, protocol, Console, or Experience contract.

## 2. Scope

The compatibility target includes all behavior available from the runnable open-source repository at the reference commit:

- OIDC and OAuth endpoints and supported grants
- user registration, sign-in, recovery, consent, and account management
- passwords, verification codes, MFA, backup codes, and WebAuthn
- applications, resources, scopes, roles, organizations, and access control
- the public, Experience, Account, Management, and `/me` APIs
- the existing React Console, Account, and Experience applications
- enterprise SSO and SAML application behavior exposed by the open-source runtime
- connector discovery, configuration, execution, and npm connector compatibility
- custom JWT claim scripts and Actions, including their error policies and state effects
- hooks, audit logs, storage integration, rate limiting, tenant routing, custom domains, and key rotation
- the Box AI branding and WeChat Web, Native, Mini Program, and Official Account H5 changes at the reference commit

The repository contains UI paths that call proprietary Logto Cloud services whose implementations are not present in this source tree. The rewrite preserves these calls behind a `CloudServicePort`; recreating an unavailable proprietary Cloud backend is outside this compatibility target.

The initial Box AI deployment has no historical production database compatibility burden. The Rust implementation therefore starts with a clean final schema and rebuilt development data. If production data exists before rollout, data migration and reverse recovery become a separate required design and delivery workstream.

## 3. Compatibility Definition

Compatibility means client-observable behavioral equivalence, not equivalent source structure or storage layout.

### 3.1 Required equivalence

| Boundary | Required behavior |
| --- | --- |
| OIDC and OAuth | Discovery, authorization, PKCE, token exchange, refresh, UserInfo, JWKS, revocation, introspection, logout, device flow, and supported extensions |
| Tokens | Issuer, audience, claims, scopes, TTL, signing algorithms, key rotation, and rejection behavior |
| Management API | Paths, methods, validation, defaults, pagination, filtering, status codes, error codes, response JSON, authorization, and persisted outcomes |
| Sign-in Experience | Registration, sign-in, recovery, MFA, account linking, consent, session behavior, errors, and redirects |
| React Console | Existing Console build operates without API changes |
| Authorization | RBAC, organization roles, resource scopes, application access control, consent, and resulting token/API effects |
| Enterprise protocols | SAML applications, enterprise SSO, OIDC SSO, and JIT provisioning |
| Connectors | Discovery, metadata, config validation, authorization redirects, callbacks, user mapping, message delivery, errors, and linking rules |
| Custom execution | Custom JWT claims, Actions, dry runs, timeouts, error policies, environment variables, and validated result effects |
| Side effects | Audit records, hooks, email/SMS requests, session/grant revocation, and usage records |
| Multi-tenancy | Tenant routing, issuer selection, cookies, data isolation, suspension, and custom domains |

### 3.2 Allowed differences

- Rust module structure, SQL, table layout, and query order
- JSON object member order and HTTP header order
- random identifiers, timestamps within defined tolerances, and JWT signature bytes
- Node/Koa-specific exception objects with no published effect
- confirmed security vulnerabilities or insecure accidental behavior, recorded as explicit compatibility exceptions
- more durable webhook recovery after a process restart; payloads, signatures, per-attempt timeout, configured retry limits, and ordinary request behavior remain compatible
- outbound SSRF protections for connectors and scripts; legitimate private-network destinations require an explicit per-tenant allow rule rather than unrestricted access

The comparator may normalize random values, bounded timestamps, and signatures. It must not normalize claims, authorization decisions, status/error codes, redirect targets, protocol parameters, or security outcomes.

### 3.3 Acceptance rule

Every observed difference must be one of:

1. fixed in the Rust implementation;
2. shown to be an unstable value covered by an approved normalization rule; or
3. documented as a specific compatibility exception with security and product justification.

There are no placeholder endpoints that return success without implementing the effect.

## 4. Architecture

The product is a modular monolith deployed as one operational unit. Its dependencies point inward toward the identity domain.

```text
HTTP / OIDC / Management API / existing React assets
                         |
                 Protocol adapters
      OIDC | OAuth | SAML | Management REST | Console BFF
                         |
                    Identity domain
 Users | Identities | Applications | Grants | Sessions
 Roles | Resources | Organizations | MFA | Audit policies
                         |
             Ports owned by the domain
 ConnectorExecutor | ScriptExecutor | SamlEngine | KeyStore | Repositories | EventPublisher
                         |
                Infrastructure adapters
 PostgreSQL | Redis | KMS/encryption | object storage | isolated Node hosts
```

The four mandatory boundaries are:

1. Identity domain
2. Protocol and external API adapters
3. External IdP and connector adapters
4. Persistence, keys, cache, jobs, and other infrastructure

Framework types, SQL rows, connector payloads, and Logto API DTOs do not enter the identity domain. Each use case owns its transaction boundary and declares its ports explicitly.

## 5. Request Processing

The request path is:

```text
Axum edge
  -> trusted endpoint and data-tenant resolution
  -> IssuerContext plus DataTenantContext
  -> authentication and audience/scope validation
  -> protocol or Management API adapter
  -> domain use case in a tenant transaction
  -> Logto-compatible presenter
```

The service retains the reference paths, including `/oidc/*`, `/.well-known/*`, `/api/*`, `/me/*`, `/console`, `/account`, and the Experience routes.

Authentication tenant and data tenant are separate concepts. `IssuerContext` records the token issuer and key set used to validate a request. `DataTenantContext` selects the tenant whose state is accessed under RLS. Admin URL endpoints, `/console`, and `/me` run in the admin-tenant context. A Management API request addressed to a user tenant may accept a valid admin-tenant token for that tenant's Management API audience and scopes while still executing the use case under the user tenant's RLS context. Authentication must never silently replace the endpoint-selected data tenant with the token issuer.

Tenant resolution distinguishes the configured admin URL set, user-tenant URL set, path-based tenancy, subdomain tenancy, and active custom domains. The control-plane PostgreSQL lookup is authoritative for custom-domain ownership and active status; Redis may not independently assert a domain-to-tenant security decision.

The Management API adapter owns Logto request and response DTOs. It maps them to domain commands and maps domain results back to the precise response shape. Pagination headers, omitted/default fields, ETags, snake-case protocol fields, and Logto error bodies remain adapter concerns.

The existing OpenAPI documents are checked in as golden contracts. Rust-generated API documentation may supplement them, but it cannot redefine compatibility.

## 6. OIDC and OAuth Engine

Rust owns an internal `OidcEngine` boundary and the protocol state machine. No currently identified Rust OpenID Provider library is accepted as an opaque replacement for `node-oidc-provider`; candidates may supply tested primitives behind the boundary.

An authorization transaction follows explicit persisted transitions such as:

```text
requested -> interaction -> consented -> code_issued -> consumed
```

Authorization codes, device codes, refresh-token rotation records, verification records, and other one-time values are consumed with conditional atomic writes, not read-then-delete sequences.

The engine covers the flows and Logto extensions enabled at the pinned baseline, including resource indicators, client credentials, refresh tokens, device flow, token exchange, RP-initiated logout, back-channel behavior present in the baseline, consent, organization claims, and application access control.

Token issuance invokes `ScriptExecutor` when a tenant has a compatible custom JWT script. The returned claim object is validated and merged according to the reference rules before signing. Action execution occurs at the corresponding sign-in transitions; Rust validates every requested effect and applies permitted user mutations inside the owning domain transaction.

Cryptographic primitives are never implemented in product code. JOSE, password hashing, random number generation, WebAuthn verification, XML signatures, and constant-time comparisons use reviewed libraries behind narrow internal ports.

## 7. Data and Tenant Isolation

The target uses one PostgreSQL database with shared tenant-partitioned tables, mandatory `tenant_id`, and PostgreSQL row-level security.

### 7.1 RLS model

- Every tenant-owned table has a non-null `tenant_id`.
- Tenant-owned unique constraints include `tenant_id` unless global uniqueness is required by a published contract.
- Tenant-owned foreign keys include `tenant_id`, preventing cross-tenant relationships at the database layer.
- Tenant tables use `FORCE ROW LEVEL SECURITY`; request and worker roles neither own tenant tables nor have `BYPASSRLS`.
- Each request resolves a tenant through the control-plane path before opening a tenant transaction.
- A dedicated tenant-transaction entry point establishes `SET LOCAL app.tenant_id = ...` from a server-authenticated tenant binding. The runtime role cannot directly set, reset, or override the tenant parameter; the phase-1 database design must prove this with integration tests before tenant data is implemented.
- `BEFORE INSERT OR UPDATE` enforcement overwrites or rejects a mismatched `tenant_id` using the established transaction context.
- RLS policies fail closed when no tenant context exists.
- The request runtime role cannot bypass RLS.
- A separate admin pool performs tenant creation and explicit global operations and is unavailable to ordinary request handlers.
- Repository APIs use parameterized, statically reviewed SQL and do not expose arbitrary or multi-statement SQL execution to request data.

RLS protects against omitted tenant predicates, query defects, SQL injection into an individual repository statement, and pooled-connection context leakage. It is not claimed to isolate tenants after compromise of the rust-core process, which legitimately brokers all tenant contexts. Control-plane credentials and KMS authority should move to smaller processes only if the measured threat model later requires that additional containment.

The non-spoofable tenant-context mechanism, forced-RLS policies, tenant-write enforcement, pooled-connection leakage tests, worker isolation tests, and admin/data-tenant split tests are mandatory phase-1 exit gates. No tenant business table or later feature may be built on an unproven tenant context.

### 7.2 Logical data areas

| Area | Examples |
| --- | --- |
| Control plane | tenants, domains, tenant status |
| Identity | users, external identities, credentials, MFA factors |
| Authorization | applications, resources, scopes, roles, organizations, consent |
| Protocol state | sessions, grants, codes, refresh tokens, device codes, verifications |
| Operations | audit logs, hooks, outbox, usage, connector configuration |

Each domain use case performs its state transition in one transaction. Account linking, consent, authorization mutations, and grant/session revocation cannot expose partially committed state.

The new Rust project maintains its own forward migrations. It does not replay Logto's historical migration chain.

## 8. Keys and Secrets

Each tenant has independent signing keys, cookie keys, connector secrets, and other sensitive configuration.

- `KeyStore` owns envelope encryption, key versions, rotation, and retention.
- The database stores ciphertext and metadata, not immediately usable private-key plaintext.
- Domain entities use distinct secret types for passwords, MFA secrets, recovery codes, connector secrets, and signing material.
- Secret values are redacted from errors, traces, audit payloads, test fixtures, and RPC logs.
- Signing-key promotion publishes a coherent JWKS view atomically.
- Retired public keys remain available until every token they may have signed has expired.
- If the key service is unavailable, new token issuance fails closed while verification with already cached public keys can continue.
- SAML IdP and SP private keys follow the same handling rules as OIDC keys. They never enter the npm connector host or untrusted-script host.

## 9. Compatibility Execution Hosts

Exact npm connector and JavaScript execution compatibility conflicts with a single-process pure-Rust result. The approved design keeps restricted Node hosts in the same deployment unit, with OS-process separation between trust classes.

```text
Kubernetes Deployment / Pod
  - rust-core
  - node-connector-host
      - existing npm connectors
  - node-saml-host
      - pinned samlify compatibility operations
  - node-script-host
      - custom JWT scripts and Actions
```

Each host communicates with Rust over its own Unix-domain socket and versioned Protobuf/gRPC contract. Every Rust/host pair has a different `emptyDir`, Unix UID/GID, socket directory, and credential volume; the Node containers do not share an `fsGroup` or mount each other's runtime directories. Rust supplies a distinct per-startup capability credential through a small secret file mounted only into the corresponding pair of containers; credentials are never passed through environment variables or logs.

### 9.1 Isolation rules

- Rust exclusively owns HTTP ingress, identity state, authorization, persistence, sessions, and validation/application of host results.
- No Node host has database credentials, an admin role, an inbound network listener, OIDC private keys, user passwords, or arbitrary filesystem access.
- The connector host loads npm connectors but never receives SAML private keys or custom scripts.
- Connector outbound traffic passes through an egress proxy that blocks link-local, loopback, cloud-metadata, and private-network destinations by default and resists DNS rebinding. A connector that intentionally targets a private service requires an explicit per-tenant allow rule and audit record.
- Third-party connector invocations run in short-lived workers with bounded CPU, memory, time, output, and process count. Official connectors may use a pooled worker only after equivalent resource and state-isolation tests pass.
- The SAML host loads only pinned SAML compatibility code, including the pinned official `connector-saml` implementation, and no other connector or tenant-authored module. All SAML factory IDs route to `SamlEngine`, never to the generic npm executor. Rust performs private-key operations through `SamlEngine` when the compatibility path permits. A SAML operation that still requires Node-held private material is an explicit, time-bounded phase-5 exception: the key is delivered only for one operation through non-persistent protected memory, all buffers are cleared, and the phase cannot exit until the exception receives a dedicated security approval or is removed. Egress is limited to the operation's Rust-validated, configured IdP endpoints and uses the same DNS-rebinding and private-network policy as connectors.
- The script host loads no connector modules and receives only the selected script, reference-compatible API surface, explicit environment variables, and a minimized event payload.
- An RPC call receives only the selected tenant configuration and operation payload needed for that call.
- RPC logs redact all configuration, scripts, environment secrets, tokens, codes, credentials, keys, and provider responses that may contain personal data.
- Timeouts, response size limits, cancellation, and concurrency limits are enforced by Rust.

### 9.2 Connector migration

`ConnectorRegistry` selects either `NodeConnectorExecutor` or `NativeConnectorExecutor` by factory ID and implementation version. External connector IDs, factory IDs, configuration formats, metadata, and API responses remain stable.

The SAML connector factory is a deliberate exception to the generic registry path: it resolves to `SamlEngine`, whose initial adapter invokes the dedicated SAML host. This gives the pinned connector a valid metadata, signing, assertion-validation, and IdP-egress path without exposing SAML keys to arbitrary npm code.

An official connector moves to Rust only after provider-simulator differential tests pass. Switching is per connector and immediately reversible. Side-effecting operations such as email and SMS delivery are never shadow-executed or dual-written.

The connector host may remain permanently as the compatibility layer for third-party npm connectors.

### 9.3 Custom JWT and Action execution

`ScriptExecutor` preserves the OSS `getCustomJwtClaims` and `runAction` contracts, Management API dry runs, reference timeouts, `denyAccess`, error mapping, environment-variable semantics, and configured allow/block error policy. The host runs scripts in short-lived, resource-limited workers with bounded CPU, memory, time, output, and process count. Filesystem access is absent. Network egress is denied except for the explicit reference-compatible fetch policy, which is enforced by an outbound proxy with DNS rebinding and private-network protections.

The script host cannot mutate identity state directly. It returns an untrusted result; Rust validates the result schema, allowed claim changes, and Action effect before applying any change. Custom JWT execution is part of the token-issuance compatibility matrix rather than deferred as an unspecified long-tail feature.

## 10. Hooks, Jobs, and Side Effects

Operations are classified by whether their result changes the current authentication transaction.

| Class | Examples | Execution |
| --- | --- | --- |
| Synchronous | social callback, email/SMS verification send, token signing, password/MFA checks | request waits |
| Transaction-after-effect | webhook, cache invalidation, non-critical counters | PostgreSQL outbox |
| Scheduled | expiration cleanup, key rotation, failed-delivery retry | durable PostgreSQL job |

No external message broker is introduced. A restricted scheduler role can claim only job-control metadata across tenants with leases and `FOR UPDATE SKIP LOCKED`; payloads and side-effect data remain in RLS-protected tenant tables, so the scheduler cannot read or mutate tenant business data. Before executing a claimed job, the worker opens a new transaction under the ordinary RLS-enforcing worker role, establishes the job's authenticated `tenant_id` context through the same tenant-transaction entry point used by requests, and then invokes the domain use case. Routine jobs never use the admin pool.

### 10.1 Webhooks

- The domain change and complete webhook payload are committed in one transaction.
- The payload is generated at event time, not reconstructed later from mutable records.
- URL, headers, signature, timeout, payload, and configured retry count match the reference behavior.
- Ordinary business requests do not wait for webhook delivery and do not roll back on delivery failure.
- Delivery is at-least-once; an internal delivery ID is not added to the compatibility payload.
- Exhausted deliveries enter a queryable dead-letter state and produce the compatible audit result.
- The Console test-hook endpoint remains synchronous.

### 10.2 Recovery

Workers lease tasks. Crashed or timed-out tasks become claimable after lease expiry. Handlers use business idempotency keys and converge on one final state. Shutdown stops new claims, drains accepted requests and synchronous connector calls, then finishes or safely releases claimed tasks.

## 11. Cache Model

PostgreSQL is authoritative. Redis is an optional best-effort accelerator.

- Process-local caches hold short-lived discovery, public JWKS, and static connector metadata.
- Redis may share derived cache values and invalidation notifications between replicas.
- Users, suspension, authorization relationships, sessions, grants, consent, refresh tokens, MFA, and rate-limit truth remain in PostgreSQL.
- Final authorization decisions and revocation state are not stored only in cache.
- Cache keys contain tenant and data version information.
- Mutations clear local values immediately and enqueue cross-instance invalidation.
- Redis errors and bounded timeouts degrade to PostgreSQL reads.

PostgreSQL failure makes the instance unready and state-dependent requests return a service failure. Redis failure does not change authorization outcomes. A compatibility-host failure affects only operations that require that host. Webhook-target failure affects delivery, not the committed business transaction.

## 12. Error Model

Internal errors are divided into input parsing, business rejection, protocol rejection, external integration failure, and unexpected internal failure.

- Management API presenters reproduce the reference HTTP status and `code`, `message`, and `data` body.
- OIDC errors redirect only after validating the redirect URI; otherwise they return a direct protocol error.
- External connector failures map to the existing Logto connector error catalog.
- Unknown internal failures return a non-sensitive 500 response with a request ID.
- Internal logs retain an error chain while redacting tokens, codes, cookies, passwords, connector secrets, private keys, and personal fields defined by policy.

## 13. Open-Source Component Strategy

The implementation reuses mature components for general infrastructure and cryptographic mechanics. Logto-specific orchestration and compatibility behavior remain product code.

| Capability | Initial component direction |
| --- | --- |
| Runtime | Tokio |
| HTTP | Axum, Tower, tower-http |
| Database | SQLx and built-in migration support |
| HTTP client | reqwest with rustls |
| Serialization | serde and serde_json |
| JOSE | josekit behind `JoseEngine` |
| Password hashing | Vetted verifiers for the exact pinned `passwordAlgorithm` set: Argon2i, Argon2id, Argon2d, SHA1, SHA256, MD5, Bcrypt, and Legacy. Legacy sub-forms are `pbkdf2`/`pbkdf2Sync`, `firebase-scrypt`, and `node:crypto.createHash`-compatible OpenSSL digest expressions. RustCrypto crates are preferred where they implement the exact format |
| WebAuthn | webauthn-rs behind `WebAuthnEngine` |
| Sensitive memory | secrecy and zeroize |
| Cache | redis-rs |
| Rust/Node RPC | Protobuf, Tonic, and `@grpc/grpc-js` |
| Observability | tracing and OpenTelemetry |
| Integration testing | testcontainers-rs, wiremock, and proptest |
| OIDC acceptance | OpenID Foundation Conformance Suite |

`oxide-auth` may be evaluated for OAuth server primitives, but it does not define the domain model or replace compatibility tests. Existing `samlify` remains in the dedicated SAML host initially. A native SAML adapter may later evaluate `samael` plus `xmlsec1`, but only after compatibility and security review.

Large authentication frameworks that impose their own user model, session model, database schema, and routes are not adopted. High-risk libraries remain replaceable behind internal ports.

All dependencies are pinned in a committed `Cargo.lock`. Locked/offline builds, isolated dependency updates, `cargo vet`, `cargo audit`, and `cargo deny` are required. New dependencies are reviewed for license, advisories, maintenance, build scripts, procedural macros, unsafe code, and transitive growth.

## 14. Compatibility Test System

The pinned Logto container is the behavioral oracle throughout the program.

```text
scenario and deterministic fixture
  -> pinned Logto reference
  -> Rust candidate
  -> normalize permitted unstable fields
  -> compare HTTP, decoded tokens, final state, and side effects
```

The existing integration suite is adapted to accept a target base URL and is reused against both systems. Tests tied to Koa, Jest mocks, or internal helper calls are not mechanically translated. Pure rules such as claims filtering, scope calculations, normalization, password formats, and connector response parsing receive focused Rust tests.

Persisted-state comparison uses a versioned semantic projection, not row or table equality. The projection combines compatible Management/Experience API reads with explicit invariants for one-time consumption, revocation, identity uniqueness, authorization relationships, tenant isolation, and side-effect records. Raw SQL assertions are used only against each implementation's own schema to prove those invariants.

Test priority is:

1. protocol and API contracts;
2. authorization and identity invariants;
3. full Experience, Account, and Console workflows;
4. semantic persisted-state projections and implementation-local PostgreSQL invariant checks;
5. focused tests for deterministic logic.

The OpenID Foundation Conformance Suite runs in CI for every supported Provider profile. Provider simulators cover all official connectors without real external side effects. Representative real providers are tested separately before release.

### 14.1 Definition of done for one behavior

- The endpoint or protocol behavior is present in the compatibility matrix.
- Success, rejection, authorization, and boundary cases have black-box coverage.
- HTTP output, decoded tokens, persisted final state, and side effects have no unexplained differences.
- Relevant existing React E2E flows pass unchanged.
- Relevant conformance tests pass.
- Secret handling, errors, and failure injection are covered where applicable.

## 15. Delivery Program

This program is too large for one implementation specification. This document governs the program; each phase receives a focused design, plan, and acceptance record.

| Phase | Deliverable | Estimate |
| --- | --- | ---: |
| 0. Compatibility lab | pinned oracle, inventory, fixtures, differential harness | 2-3 person-months |
| 1. Platform vertical slice | workspace, RLS, KeyStore, compatibility hosts, one full PKCE flow | 3-5 person-months |
| 2. OIDC and OAuth | complete grants, sessions, consent, JWKS, custom JWT, token exchange, device flow | 8-12 person-months |
| 3. Identity Experience | registration, passwords, verification, MFA, WebAuthn, Account, social linking, Actions | 7-10 person-months |
| 4. Management plane | Management API, organizations/RBAC, applications/resources, Console | 8-12 person-months |
| 5. Enterprise and long tail | SAML, enterprise SSO, hooks, storage, remaining behavior | 8-12 person-months |
| 6. Hardening and rollout | conformance, security review, fault drills, rollout | 4-6 person-months |

Expected total: 40-60 person-months. A stable four-to-five-person team can target 12-18 calendar months, with parallel work only after shared protocol, data, and compatibility boundaries are stable.

### 15.1 First vertical slice

The first implementation milestone proves this full path:

```text
create tenant and application
  -> configure sign-in Experience
  -> authorization code plus PKCE
  -> password sign-in
  -> consent
  -> token issuance and refresh
  -> UserInfo
  -> Console reads the application and user
```

Infrastructure work that does not contribute to this path is deferred unless it is required for security or deterministic delivery.

## 16. Rollout and Rollback

Rollout follows a per-tenant single-writer rule. A tenant has exactly one active implementation that may mutate identity state or issue tokens.

1. Keep pinned Logto as the reference in CI.
2. Roll out Rust to development tenants.
3. Run the complete compatibility, React E2E, and conformance suites.
4. Roll out to test tenants and run provider interoperability and fault drills.
5. Put the tenant into a maintenance fence that rejects every new authorization, token issuance, identity/session/grant mutation, Experience write, and management write on both implementations.
6. For the tenant under cutover, stop claiming new background work and drain existing outbox deliveries and jobs to zero. If a production migration design explicitly preserves pending durable work, migrate and verify those records instead. Pause staged signing-key promotion and scheduled mutation on both implementations; then drain all in-flight Logto requests and verify zero active authorization, connector, script, and SAML operations. Pending work cannot be silently abandoned.
7. Validate tenant configuration, users if any, applications, clients, signing/cookie keys, and invariants. Import keys and stable identifiers when continuity is required.
8. Revoke the old Logto tenant's database and signing authority and stop its tenant runtime before enabling Rust as writer. Runtime shutdown supplements authority revocation and never substitutes for it.
9. Enable Rust's writer lease and then switch ingress. Ingress routing is not itself the writer fence.
10. Observe protocol errors, token failures, connector failures, and state invariants before ending the maintenance window.

There is no dual write. Step 8 remains reversible until Rust receives the writer lease. A pre-lease rollback uses a controlled sequence under the maintenance fence: restore the old Logto tenant's database role and signing-key access, restart its tenant runtime, verify its health and signing identity, and only then remove the fence. A partial restore leaves the fence in place for diagnosis or retry. After Rust becomes authoritative, rollback means rolling back the Rust release while retaining the Rust database, not blindly returning to an independently changing Logto database.

For the current greenfield Box AI state, the cutover may intentionally discard development sessions and tokens. Any rollout that promises continuity for existing clients or tokens must import signing and cookie keys, client identifiers/secrets, and protocol state as specified by the separate production-data migration design.

If production data exists by rollout time, the team must approve a separate migration and reverse-recovery design before rollout. That design must cover password digests without plaintext, signing and cookie keys, sessions, grants, external identities, connector secrets, audit verification, a cutover journal, and rollback after post-cutover writes.

## 17. Licensing

The Rust implementation is behavior-driven and must not copy or mechanically translate Logto source. Any copied or modified Logto files, including adapted integration-test files, retain MPL-2.0 notices and source-availability obligations. The new Rust implementation's license is a separate product decision and does not alter obligations on reused MPL files.

## 18. Major Risks and Controls

| Risk | Control |
| --- | --- |
| Moving upstream target | pin the exact reference commit; treat later features separately |
| Incomplete Rust OP ecosystem | own the `OidcEngine` boundary; reuse primitives; require OIDF conformance |
| Hidden Console/API coupling | run existing React applications unchanged against every delivered slice |
| Connector ecosystem lock-in | keep the connector host; migrate per factory ID with differential tests |
| SAML/XML security | use a dedicated SAML host with no plugins; keep private operations in KeyStore where possible; require approval for any time-bounded key exposure |
| Untrusted custom code | use a dedicated resource-limited script host; validate every result in Rust; constrain egress |
| Tenant data leak | force RLS, non-spoofable transaction context, tenant triggers, composite tenant foreign keys, separated admin pool, isolation tests |
| Secret exposure | typed secrets, envelope encryption, redaction tests, narrow RPC payloads |
| Long-tail behavior dominates schedule | complete capability inventory in phase 0 and enforce phase gates |
| Unsafe cutover | maintenance fence, drain, writer lease, key/state validation, and explicit migration design if data exists |

## 19. Next Step

The next artifact is the focused design and implementation plan for phase 0, the compatibility lab. No Rust production service is scaffolded until that plan defines the oracle image, capability inventory format, deterministic fixture model, normalizers, differential runner, reuse of existing integration tests, evidence format, and phase-0 exit criteria.
