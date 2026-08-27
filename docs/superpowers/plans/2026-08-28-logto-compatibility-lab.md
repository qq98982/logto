# Logto Compatibility Lab Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build phase 0 of the Rust rewrite program: a deterministic, secret-safe differential test lab that inventories the pinned Logto surface and proves that two independent instances of the pinned implementation produce equivalent behavior.

**Architecture:** Extend the existing TypeScript integration-test package with a small compatibility domain: inventory collectors, target-independent scenarios, explicit normalization rules, a semantic comparator, and evidence writers. Run one built Logto reference image twice against independent PostgreSQL/Redis state; the second target later becomes the Rust candidate without changing scenario code. Store runtime evidence under `/var/tmp/henry-build/logto-compatibility`, never in the repository.

**Tech Stack:** Node.js 22, TypeScript, Jest, Zod, Ky, Jose, existing Logto integration clients, Docker Compose, PostgreSQL 17, Redis 6.

---

## Scope And Exit Criteria

This plan implements only phase 0 from `docs/superpowers/specs/2026-08-28-logto-rust-compatible-rewrite-design.md`. It does not create a Rust workspace, a production service, a new database schema, or a compatibility proxy.

Phase 0 is complete only when all of these are true:

1. The reference commit is fixed at `6852a7b8c8984c5c12b2061e8c51faa310a36412`.
2. A deterministic manifest inventories runtime OpenAPI operations, OIDC advertised capabilities, connector factories, existing integration-test files, and manually enumerated non-HTTP behavior.
3. Two isolated instances of the same reference image complete discovery and password authorization-code scenarios with zero unexplained differences.
4. A built-in negative control changes one candidate observation and makes the comparator fail with a precise JSON path.
5. Evidence contains no raw password, authorization code, refresh/access/ID token, cookie value, connector secret, or private key.
6. The existing integration-test API, Experience, and Console commands retain their current behavior.
7. CI runs the positive control and negative control and uploads only sanitized evidence.

## File Map

### Repository-level artifacts

- Create: `compatibility/README.md` - phase-0 operation and acceptance rules.
- Create: `compatibility/manual-capabilities.json` - reviewed capabilities that cannot be discovered from runtime documents.
- Create: `compatibility/baseline-manifest.json` - deterministic generated inventory for the pinned reference.
- Create: `docker-compose.compatibility.yml` - complete, explicit oracle/candidate deployment with independent state.
- Create: `.scripts/compatibility/run.sh` - owned Compose lifecycle and positive/negative control runner.
- Create: `.github/workflows/compatibility-test.yml` - phase-0 CI gate.

### Integration-test package

- Modify: `packages/integration-tests/package.json` - compatibility build/test/run commands.
- Create: `packages/integration-tests/jest.config.compatibility.js` - compatibility tests without live API setup.
- Create: `packages/integration-tests/src/compatibility/model.ts` - Zod schemas and shared types.
- Create: `packages/integration-tests/src/compatibility/model.test.ts` - evidence-model contracts.
- Create: `packages/integration-tests/src/compatibility/config.ts` - validated target and evidence configuration.
- Create: `packages/integration-tests/src/compatibility/inventory/collect.ts` - runtime/source inventory collection.
- Create: `packages/integration-tests/src/compatibility/inventory/paths.ts` - repository-root manifest resolution.
- Create: `packages/integration-tests/src/compatibility/inventory/cli.ts` - deterministic manifest writer/checker.
- Create: `packages/integration-tests/src/compatibility/inventory/collect.test.ts` - pure inventory tests.
- Create: `packages/integration-tests/src/compatibility/symbol-table.ts` - logical-to-runtime ID binding.
- Create: `packages/integration-tests/src/compatibility/normalize.ts` - explicit URL, time, ID, cookie, and JWT normalization.
- Create: `packages/integration-tests/src/compatibility/normalize.test.ts` - normalization contracts.
- Create: `packages/integration-tests/src/compatibility/compare.ts` - recursive semantic diff.
- Create: `packages/integration-tests/src/compatibility/compare.test.ts` - difference and negative-control tests.
- Create: `packages/integration-tests/src/compatibility/evidence.ts` - redaction, schema validation, and atomic evidence writes.
- Create: `packages/integration-tests/src/compatibility/evidence.test.ts` - sensitive-value rejection tests.
- Create: `packages/integration-tests/src/compatibility/target-client.ts` - per-target Management/OIDC client.
- Create: `packages/integration-tests/src/compatibility/scenario.ts` - target-independent scenario contract and runner.
- Create: `packages/integration-tests/src/compatibility/scenarios/discovery.ts` - discovery comparison.
- Create: `packages/integration-tests/src/compatibility/scenarios/password-code.ts` - password, PKCE, token, refresh, UserInfo, and Management API projection.
- Create: `packages/integration-tests/src/compatibility/scenarios/index.ts` - single exported default scenario registry.
- Create: `packages/integration-tests/src/compatibility/scenarios/index.test.ts` - registry membership contract.
- Create: `packages/integration-tests/src/compatibility/cli.ts` - run scenarios, compare, write evidence, and set process exit status.
- Create: `packages/integration-tests/src/compatibility/tests/reference-parity.test.ts` - opt-in dual-target smoke test.

## Task 1: Define The Compatibility Data Model

**Files:**

- Create: `packages/integration-tests/jest.config.compatibility.js`
- Create: `packages/integration-tests/src/compatibility/model.ts`
- Create: `packages/integration-tests/src/compatibility/model.test.ts`

- [ ] **Step 1: Create a network-free Jest configuration**

Create `jest.config.compatibility.js` without `jest.setup.api.js`:

```javascript
/** @type {import('jest').Config} */
const config = {
  transform: {},
  testPathIgnorePatterns: ['/node_modules/'],
  coverageProvider: 'v8',
  setupFilesAfterEnv: ['jest-matcher-specific-error', './jest.setup.js'],
  roots: ['./lib/compatibility'],
  moduleNameMapper: {
    '^#src/(.*)\\.js(x)?$': '<rootDir>/lib/$1',
    '^(chalk|inquirer)$': '<rootDir>/../shared/lib/esm/module-proxy.js',
  },
};

export default config;
```

Compatibility tests must never load `jest.setup.api.js`, whose top-level setup mutates the live admin tenant.

- [ ] **Step 2: Add model tests for accepted evidence and rejected raw secrets**

Create `model.test.ts` with these contracts:

```typescript
import {
  capabilityManifestGuard,
  observationGuard,
  runEvidenceGuard,
  scenarioEvidenceGuard,
} from './model.js';

describe('compatibility model', () => {
  it('accepts a deterministic capability manifest', () => {
    expect(
      capabilityManifestGuard.parse({
        schemaVersion: 1,
        referenceCommit: '6852a7b8c8984c5c12b2061e8c51faa310a36412',
        capabilities: [
          {
            id: 'http.management.get./api/users',
            surface: 'management-api',
            source: '/api/.well-known/management.openapi.json',
            existingEvidence: [],
          },
        ],
      })
    ).toBeTruthy();
  });

  it('accepts only sanitized observations', () => {
    expect(
      observationGuard.parse({
        stepId: 'token.claims',
        kind: 'jwt-claims',
        value: { sub: '<user.primary>', tokenLifetimeSeconds: 3600 },
      })
    ).toBeTruthy();
  });

  it('requires oracle and candidate evidence for a scenario', () => {
    expect(() =>
      scenarioEvidenceGuard.parse({ schemaVersion: 1, scenarioId: 'discovery' })
    ).toThrow();
  });

  it('records immutable image identities in run evidence', () => {
    expect(
      runEvidenceGuard.parse({
        schemaVersion: 1,
        referenceCommit: '6852a7b8c8984c5c12b2061e8c51faa310a36412',
        oracleImageDigest: 'sha256:' + 'a'.repeat(64),
        candidateImageDigest: 'sha256:' + 'a'.repeat(64),
        scenarios: [{ scenarioId: 'discovery', differenceCount: 0 }],
        negativeControl: { differencePath: '/observations/0/value/issuer' },
      })
    ).toBeTruthy();
  });
});
```

- [ ] **Step 3: Run the focused test and confirm it fails because the model is absent**

Run:

```bash
cd packages/integration-tests
pnpm build
pnpm test:only -i --config=jest.config.compatibility.js ./lib/compatibility/model.test.js
```

Expected: build failure resolving `./model.js`.

- [ ] **Step 4: Implement the model with closed enums and recursive JSON guards**

Create `model.ts` with these exported contracts:

```typescript
import { z } from 'zod';

const jsonPrimitiveGuard = z.union([z.string(), z.number(), z.boolean(), z.null()]);
export const jsonValueGuard: z.ZodType<unknown> = z.lazy(() =>
  z.union([jsonPrimitiveGuard, z.array(jsonValueGuard), z.record(jsonValueGuard)])
);

export const targetConfigGuard = z.object({
  label: z.enum(['oracle', 'candidate']),
  coreUrl: z.string().url(),
  adminUrl: z.string().url(),
});

export const capabilityGuard = z.object({
  id: z.string().min(1),
  surface: z.enum([
    'management-api',
    'experience-api',
    'user-api',
    'oidc',
    'connector',
    'integration-test',
    'manual',
  ]),
  source: z.string().min(1),
  existingEvidence: z.array(z.string()),
});

export const capabilityManifestGuard = z.object({
  schemaVersion: z.literal(1),
  referenceCommit: z.literal('6852a7b8c8984c5c12b2061e8c51faa310a36412'),
  capabilities: z.array(capabilityGuard),
});

export const observationGuard = z.object({
  stepId: z.string().min(1),
  kind: z.enum([
    'http',
    'redirect',
    'cookie-metadata',
    'jwt-header',
    'jwt-claims',
    'semantic-state',
  ]),
  value: jsonValueGuard,
});

export const targetEvidenceGuard = z.object({
  target: z.enum(['oracle', 'candidate']),
  observations: z.array(observationGuard),
});

export const differenceGuard = z.object({
  path: z.string(),
  oracle: jsonValueGuard.optional(),
  candidate: jsonValueGuard.optional(),
});

export const scenarioEvidenceGuard = z.object({
  schemaVersion: z.literal(1),
  scenarioId: z.string().min(1),
  oracle: targetEvidenceGuard.extend({ target: z.literal('oracle') }),
  candidate: targetEvidenceGuard.extend({ target: z.literal('candidate') }),
  differences: z.array(differenceGuard),
});

export const runEvidenceGuard = z.object({
  schemaVersion: z.literal(1),
  referenceCommit: z.literal('6852a7b8c8984c5c12b2061e8c51faa310a36412'),
  oracleImageDigest: z.string().regex(/^sha256:[a-f\d]{64}$/),
  candidateImageDigest: z.string().regex(/^sha256:[a-f\d]{64}$/),
  scenarios: z.array(
    z.object({ scenarioId: z.string().min(1), differenceCount: z.number().int().nonnegative() })
  ),
  negativeControl: z.object({ differencePath: z.string().startsWith('/') }),
});

export type TargetConfig = z.infer<typeof targetConfigGuard>;
export type CapabilityManifest = z.infer<typeof capabilityManifestGuard>;
export type Observation = z.infer<typeof observationGuard>;
export type TargetEvidence = z.infer<typeof targetEvidenceGuard>;
export type Difference = z.infer<typeof differenceGuard>;
export type ScenarioEvidence = z.infer<typeof scenarioEvidenceGuard>;
export type RunEvidence = z.infer<typeof runEvidenceGuard>;
```

- [ ] **Step 5: Build and run the focused test**

Run the command from step 2. Expected: `PASS compatibility/model.test.js`.

- [ ] **Step 6: Commit the model**

```bash
git add packages/integration-tests/src/compatibility/model.ts \
  packages/integration-tests/src/compatibility/model.test.ts \
  packages/integration-tests/jest.config.compatibility.js
git commit -m "test(test): define compatibility evidence model"
```

## Task 2: Build A Deterministic Capability Inventory

**Files:**

- Create: `compatibility/manual-capabilities.json`
- Create: `packages/integration-tests/src/compatibility/inventory/collect.ts`
- Create: `packages/integration-tests/src/compatibility/inventory/collect.test.ts`
- Create: `packages/integration-tests/src/compatibility/inventory/paths.ts`
- Create: `packages/integration-tests/src/compatibility/inventory/cli.ts`
- Modify: `packages/integration-tests/package.json`
- Generate: `compatibility/baseline-manifest.json`

- [ ] **Step 1: Add pure extraction tests**

Test four deterministic collectors:

```typescript
import {
  collectIntegrationTestCapabilities,
  extractConnectorCapabilities,
  extractOidcCapabilities,
  extractOpenApiCapabilities,
} from './collect.js';

describe('capability inventory', () => {
  it('sorts OpenAPI operations by stable ID', () => {
    expect(
      extractOpenApiCapabilities('management-api', '/management.openapi.json', {
        paths: {
          '/api/users': { post: {}, get: {} },
        },
      }).map(({ id }) => id)
    ).toEqual([
      'http.management-api.get./api/users',
      'http.management-api.post./api/users',
    ]);
  });

  it('expands advertised OIDC arrays into stable capabilities', () => {
    expect(
      extractOidcCapabilities({
        grant_types_supported: ['refresh_token', 'authorization_code'],
        response_types_supported: ['code'],
        response_modes_supported: ['query'],
        token_endpoint_auth_methods_supported: ['client_secret_basic'],
      }).map(({ id }) => id)
    ).toContain('oidc.grant.authorization_code');
  });

  it('sorts connector factory IDs', () => {
    expect(
      extractConnectorCapabilities([{ id: 'wechat-web' }, { id: 'google-universal' }]).map(
        ({ id }) => id
      )
    ).toEqual(['connector.google-universal', 'connector.wechat-web']);
  });

  it('maps test files without parsing test names', async () => {
    await expect(
      collectIntegrationTestCapabilities('/repo/packages/integration-tests/src/tests', {
        readFiles: async () => ['api/users.test.ts', 'console/users/index.test.ts'],
      })
    ).resolves.toEqual([
      expect.objectContaining({ id: 'test.api/users.test.ts' }),
      expect.objectContaining({ id: 'test.console/users/index.test.ts' }),
    ]);
  });
});
```

- [ ] **Step 2: Implement collectors without source regex parsing**

`collect.ts` must:

- fetch `/api/.well-known/management.openapi.json`, `experience.openapi.json`, and `user.openapi.json`;
- fetch `/oidc/.well-known/openid-configuration`;
- fetch `/api/connector-factories` using only the test-only `development-user-id` header;
- enumerate existing `src/tests/**/*.test.ts` file paths;
- merge the reviewed JSON entries;
- sort by `id` and reject duplicate IDs.

Use this operation extractor rather than matching source text:

```typescript
const httpMethods = ['delete', 'get', 'patch', 'post', 'put'] as const;

export const extractOpenApiCapabilities = (
  surface: 'management-api' | 'experience-api' | 'user-api',
  source: string,
  document: { paths?: Record<string, Record<string, unknown>> }
) =>
  Object.entries(document.paths ?? {})
    .flatMap(([route, item]) =>
      httpMethods.flatMap((method) =>
        item[method]
          ? [{ id: `http.${surface}.${method}.${route}`, surface, source, existingEvidence: [] }]
          : []
      )
    )
    .toSorted((left, right) => left.id.localeCompare(right.id));
```

The connector extractor accepts runtime responses shaped as `{ id: string }[]`. The test-file collector accepts an injected `readFiles()` dependency so its unit test does not touch a fake filesystem.

- [ ] **Step 3: Add reviewed manual capabilities**

Create `compatibility/manual-capabilities.json` with this initial closed list:

```json
[
  {"id":"manual.tenant.admin-issuer-data-tenant","surface":"manual","source":"packages/core/src/middleware/koa-auth/index.ts","existingEvidence":[]},
  {"id":"manual.tenant.custom-domain-routing","surface":"manual","source":"packages/core/src/utils/tenant.ts","existingEvidence":[]},
  {"id":"manual.tenant.path-based-routing","surface":"manual","source":"packages/core/src/utils/tenant.ts","existingEvidence":[]},
  {"id":"manual.tenant.rls-isolation","surface":"manual","source":"packages/schemas/tables/_after_each.sql","existingEvidence":[]},
  {"id":"manual.keys.immediate-rotation","surface":"manual","source":"packages/core/src/libraries/oidc-private-key.ts","existingEvidence":[]},
  {"id":"manual.keys.staged-rotation","surface":"manual","source":"packages/core/src/libraries/oidc-private-key.ts","existingEvidence":[]},
  {"id":"manual.script.custom-jwt","surface":"manual","source":"packages/core/src/libraries/jwt-customizer.ts","existingEvidence":[]},
  {"id":"manual.script.post-first-factor","surface":"manual","source":"packages/core/src/libraries/action.ts","existingEvidence":[]},
  {"id":"manual.script.post-sign-in","surface":"manual","source":"packages/core/src/libraries/action.ts","existingEvidence":[]},
  {"id":"manual.saml.application-idp","surface":"manual","source":"packages/core/src/saml-application","existingEvidence":[]},
  {"id":"manual.saml.enterprise-sso-sp","surface":"manual","source":"packages/core/src/sso/SamlConnector","existingEvidence":[]},
  {"id":"manual.webhook.retry-and-signature","surface":"manual","source":"packages/core/src/libraries/hook/utils.ts","existingEvidence":[]},
  {"id":"manual.storage.user-assets","surface":"manual","source":"packages/core/src/utils/storage","existingEvidence":[]},
  {"id":"manual.password.all-import-algorithms","surface":"manual","source":"packages/schemas/tables/users.sql","existingEvidence":[]},
  {"id":"manual.cache.redis-degradation","surface":"manual","source":"packages/core/src/caches/index.ts","existingEvidence":[]}
]
```

- [ ] **Step 4: Add deterministic inventory CLI and package scripts**

Add these scripts to `packages/integration-tests/package.json`:

```json
"compatibility:inventory": "node ./lib/compatibility/inventory/cli.js",
"compatibility:run": "node ./lib/compatibility/cli.js",
"test:compatibility": "pnpm test:only -i --config=jest.config.compatibility.js ./lib/compatibility/"
```

The inventory CLI must accept `--target oracle|candidate` and exactly one of `--check` or `--write`. `--write` is allowed only for the oracle target when `COMPAT_ALLOW_MANIFEST_WRITE=1`; it uses two-space JSON plus a trailing newline. `--check` compares parsed objects, prints added/removed capability IDs, and exits `1` on drift.

`paths.ts` resolves the manifest as `path.join(repoRoot, 'compatibility/baseline-manifest.json')`. When `COMPAT_REPO_ROOT` is present, require an absolute path, resolve its real path, and verify that `<root>/pnpm-workspace.yaml` is a regular file. When absent in focused local tests, walk upward from `import.meta.url` until `pnpm-workspace.yaml` exists. Never resolve the manifest from `process.cwd()`. Add tests for a relative env path, a missing workspace marker, and a cwd change to an unrelated temporary directory.

- [ ] **Step 5: Run inventory unit tests without requiring a live service**

Run:

```bash
cd packages/integration-tests
pnpm build
pnpm test:only -i --config=jest.config.compatibility.js \
  ./lib/compatibility/inventory/collect.test.js
```

Expected: unit tests pass. Live manifest generation is deliberately deferred to task 8, where both isolated targets exist.

- [ ] **Step 6: Commit the inventory**

```bash
git add compatibility/manual-capabilities.json packages/integration-tests/package.json \
  packages/integration-tests/src/compatibility/inventory
git commit -m "test(test): inventory pinned Logto surface"
```

## Task 3: Implement Logical Symbols And Explicit Normalization

**Files:**

- Create: `packages/integration-tests/src/compatibility/symbol-table.ts`
- Create: `packages/integration-tests/src/compatibility/normalize.ts`
- Create: `packages/integration-tests/src/compatibility/normalize.test.ts`

- [ ] **Step 1: Write table-driven normalization tests**

Cover URL replacement, longest-first symbol replacement, timestamp paths, cookie metadata, and JWT claim preservation:

```typescript
it('does not erase authorization claims', () => {
  const normalized = normalizeJson(
    { scope: 'read write', aud: 'https://api.example', iat: 100, exp: 3700 },
    context,
    [
      { path: '/iat', strategy: 'timestamp', toleranceSeconds: 60 },
      { path: '/exp', strategy: 'timestamp', toleranceSeconds: 60 },
    ]
  );
  expect(normalized).toEqual({
    scope: 'read write',
    aud: 'https://api.example',
    iat: { $timestamp: 100, $toleranceSeconds: 60 },
    exp: { $timestamp: 3700, $toleranceSeconds: 60 },
  });
});

it('maps target-specific IDs to the same logical symbol', () => {
  const symbols = new SymbolTable();
  symbols.bind('user.primary', 'oracle-random-user-id');
  expect(symbols.replace('subject=oracle-random-user-id')).toBe('subject=<user.primary>');
});

it('keeps cookie attributes and removes cookie values', () => {
  expect(normalizeSetCookies(['interaction=secret; Path=/; HttpOnly; SameSite=Lax'])).toEqual([
    { name: 'interaction', path: '/', httpOnly: true, secure: false, sameSite: 'Lax' },
  ]);
});
```

- [ ] **Step 2: Implement a target-local symbol table**

`SymbolTable.bind()` is idempotent only for the same logical-name/runtime-value pair. It rejects changing either side of an existing binding or assigning one runtime value to two names. Before binding a JWT claim, look up an existing business symbol such as `user.primary`; allocate occurrence names such as `id-token.jti.1` and `access-token.jti.1` only for previously unseen values. Replacement must sort runtime values by descending length before replacing strings.

- [ ] **Step 3: Implement path-scoped normalization**

Use JSON-pointer paths. Supported strategies are only:

```typescript
export type NormalizationRule =
  | { path: string; strategy: 'drop' }
  | { path: string; strategy: 'timestamp'; toleranceSeconds: number }
  | { path: string; strategy: 'duration-seconds'; startPath: string };
```

Timestamp normalization retains the numeric value and explicit tolerance marker; the comparator reports a difference when oracle/candidate values differ by more than the smaller declared tolerance. It must never replace an unchecked value with a generic timestamp string. Always replace configured target core/admin URLs and bound symbols in strings. Do not automatically drop fields named `id`, `state`, `code`, `scope`, `aud`, `iss`, `sub`, `role`, or `organization`.

JWT handling must decode header/payload, bind `kid`, `sub`, `sid`, `jti`, and other subject/session IDs through the symbol table, apply explicit timestamp rules to `iat`, `exp`, `auth_time`, and equivalent time claims, remove the compact token before evidence creation, and add `tokenLifetimeSeconds = exp - iat`. Raw token strings must never be returned by the normalizer.

- [ ] **Step 4: Run normalization tests**

```bash
cd packages/integration-tests
pnpm build
pnpm test:only -i --config=jest.config.compatibility.js ./lib/compatibility/normalize.test.js
```

Expected: all normalization tests pass.

- [ ] **Step 5: Commit normalization**

```bash
git add packages/integration-tests/src/compatibility/symbol-table.ts \
  packages/integration-tests/src/compatibility/normalize.ts \
  packages/integration-tests/src/compatibility/normalize.test.ts
git commit -m "test(test): add compatibility normalizers"
```

## Task 4: Implement Semantic Comparison And Secret-Safe Evidence

**Files:**

- Create: `packages/integration-tests/src/compatibility/compare.ts`
- Create: `packages/integration-tests/src/compatibility/compare.test.ts`
- Create: `packages/integration-tests/src/compatibility/evidence.ts`
- Create: `packages/integration-tests/src/compatibility/evidence.test.ts`

- [ ] **Step 1: Write comparator tests that fail on material behavior**

```typescript
it.each([
  ['/observations/0/value/status', 200, 401],
  ['/observations/0/value/scope', 'read', 'write'],
  ['/observations/0/value/location', '/consent', '/error'],
])('reports %s', (path, oracle, candidate) => {
  expect(compareJson({ value: oracle }, { value: candidate })).toContainEqual(
    expect.objectContaining({ path: path.replace('/observations/0', '') })
  );
});

it('returns no differences for equal normalized values', () => {
  expect(compareJson({ sub: '<user.primary>' }, { sub: '<user.primary>' })).toEqual([]);
});

it('enforces timestamp tolerance instead of erasing timestamps', () => {
  expect(
    compareJson(
      { createdAt: { $timestamp: 100, $toleranceSeconds: 5 } },
      { createdAt: { $timestamp: 104, $toleranceSeconds: 5 } }
    )
  ).toEqual([]);
  expect(
    compareJson(
      { createdAt: { $timestamp: 100, $toleranceSeconds: 5 } },
      { createdAt: { $timestamp: 106, $toleranceSeconds: 5 } }
    )
  ).toContainEqual(expect.objectContaining({ path: '/createdAt' }));
});
```

- [ ] **Step 2: Implement a deterministic recursive comparator**

The comparator must:

- sort object keys;
- preserve array order unless a scenario normalizer sorted that specific array;
- report missing values separately from JSON `null`;
- cap displayed strings at 500 characters without changing the path;
- return `Difference[]` rather than throw on the first mismatch.

- [ ] **Step 3: Write evidence rejection tests**

Test all forbidden key/value classes after lowercasing and removing `_`, `-`, and whitespace from key names:

```typescript
it.each([
  'password',
  'password_value',
  'authorizationCode',
  'authorization_code',
  'accessToken',
  'access_token',
  'refreshToken',
  'refresh_token',
  'idToken',
  'id_token',
  'cookie',
  'cookieValue',
  'set-cookie',
  'set_cookie',
  'privateKey',
  'clientSecret',
  'client_secret',
  'connectorSecret',
  'connector_secret',
])(
  'rejects a %s field',
  (key) => {
    expect(() => assertEvidenceIsSanitized({ [key]: 'sensitive-test-value' })).toThrow(key);
  }
);

it('rejects compact JWT strings regardless of key name', () => {
  expect(() =>
    assertEvidenceIsSanitized({ value: 'eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.c2ln' })
  ).toThrow(
    'compact token'
  );
});

it.each(['passwordAlgorithm', 'hasPassword', 'tokenLifetimeSeconds', 'tokenType'])(
  'allows reviewed non-secret metadata %s',
  (key) => {
    expect(() => assertEvidenceIsSanitized({ [key]: 'reviewed-metadata' })).not.toThrow();
  }
);
```

Also reject values matching `Bearer <credential>`, OAuth authorization-code fields, and compact three-segment JWT/JWS strings. Mirror the key-fragment policy from `packages/core/src/utils/sensitive-data.ts`, but keep the explicit metadata allowlist above so `tokenLifetimeSeconds` and `passwordAlgorithm` remain recordable.

- [ ] **Step 4: Implement atomic private evidence writes**

`writeScenarioEvidence()` must:

1. validate with `scenarioEvidenceGuard`;
2. recursively scan forbidden keys and token/cookie patterns;
3. create the evidence directory with mode `0700`;
4. write a sibling temporary file with mode `0600`;
5. rename it to `<scenario-id>.json`;
6. never print evidence bodies to stdout.

`writeRunEvidence()` follows the same atomic write process but validates with `runEvidenceGuard` and always writes `run.json`. Add unit tests that parse the written file and reject a digest that does not match `sha256:<64 lowercase hex characters>`.

Both writers use exactly one destination variable: `COMPAT_EVIDENCE_DIR`. Direct local calls default it to `/var/tmp/henry-build/logto-compatibility/direct`; the owned lifecycle script always overrides it with its private per-run `evidence/` directory.

- [ ] **Step 5: Run tests and commit**

```bash
cd packages/integration-tests
pnpm build
pnpm test:only -i --config=jest.config.compatibility.js \
  ./lib/compatibility/compare.test.js ./lib/compatibility/evidence.test.js
git add src/compatibility/compare.ts src/compatibility/compare.test.ts \
  src/compatibility/evidence.ts src/compatibility/evidence.test.ts
git commit -m "test(test): compare sanitized compatibility evidence"
```

## Task 5: Add Validated Target Configuration And Scenario Runner

**Files:**

- Create: `packages/integration-tests/src/compatibility/config.ts`
- Create: `packages/integration-tests/src/compatibility/target-client.ts`
- Create: `packages/integration-tests/src/compatibility/scenario.ts`
- Create: `packages/integration-tests/src/compatibility/scenario.test.ts`

- [ ] **Step 1: Test configuration failures before network access**

Require all four URLs and reject identical labels with different URL semantics:

```typescript
expect(() => loadCompatibilityConfig({})).toThrow('COMPAT_ORACLE_URL');
expect(() =>
  loadCompatibilityConfig({
    COMPAT_ORACLE_URL: 'http://localhost:3101',
    COMPAT_ORACLE_ADMIN_URL: 'http://localhost:3201',
    COMPAT_CANDIDATE_URL: 'not-a-url',
    COMPAT_CANDIDATE_ADMIN_URL: 'http://localhost:3202',
  })
).toThrow('COMPAT_CANDIDATE_URL');
```

- [ ] **Step 2: Implement per-target clients**

`TargetClient` owns these Ky instances:

```typescript
this.core = ky.create({ prefixUrl: target.coreUrl });
this.management = ky.create({
  prefixUrl: new URL('/api/', target.coreUrl),
  headers: { 'development-user-id': 'integration-test-admin-user' },
});
this.experience = ky.create({
  prefixUrl: new URL('/api/', target.coreUrl),
});
```

`experience` is anonymous and is the only Ky instance passed into `ExperienceClient`. `management` is reserved for test setup, cleanup, OpenAPI reads that require it, and connector-factory inventory; it must never enter an end-user interaction flow.

Expose only the operations phase-0 scenarios need:

- `getDiscovery()`
- `getManagementOpenApi()` / `getExperienceOpenApi()` / `getUserOpenApi()`
- `listConnectorFactories()`
- `setUsernamePasswordExperience()`
- `createUser()` / `getUser()` / `deleteUser()`
- `getUserInfo(accessToken)`

The client never records request headers or bodies.

- [ ] **Step 3: Define the scenario interface**

```typescript
export type ScenarioContext = {
  target: TargetConfig;
  client: TargetClient;
  symbols: SymbolTable;
  observe: (observation: Observation) => void;
};

export type CompatibilityScenario = {
  id: string;
  run: (context: ScenarioContext) => Promise<void>;
};
```

`runScenarioForTarget()` creates fresh symbols/observations, runs cleanup in `finally`, normalizes observations before returning, and tags only the target label. Scenario code must not branch on `oracle` versus `candidate`.

- [ ] **Step 4: Test target independence with two local HTTP servers**

Use `node:http` servers bound to ephemeral ports. Return the same response from both and assert the scenario body is invoked exactly once per target and normalized base URLs compare equal.

- [ ] **Step 5: Run tests and commit**

```bash
cd packages/integration-tests
pnpm build
pnpm test:only -i --config=jest.config.compatibility.js ./lib/compatibility/scenario.test.js
git add src/compatibility/config.ts src/compatibility/target-client.ts \
  src/compatibility/scenario.ts src/compatibility/scenario.test.ts
git commit -m "test(test): add target-independent runner"
```

## Task 6: Add Discovery And Negative-Control Scenarios

**Files:**

- Create: `packages/integration-tests/src/compatibility/scenarios/discovery.ts`
- Create: `packages/integration-tests/src/compatibility/cli.ts`
- Create: `packages/integration-tests/src/compatibility/cli.test.ts`

- [ ] **Step 1: Implement the first black-box scenario**

The discovery scenario records:

- status and content type;
- normalized discovery JSON;
- JWKS key metadata (`kid` symbol, `kty`, `use`, `alg`, curve), never key material not already public;
- equality of OpenID and RFC 8414 authorization-server documents.

Use explicit normalization rules for issuer URLs and signing-key symbols. Sort documented set-like arrays by value; preserve order for arrays whose order is observable.

Export the scenario as `export default { id: 'discovery', run } satisfies CompatibilityScenario;`. JWKS observations are limited to `kid`, `kty`, `use`, `alg`, and `crv`; never record `x`, `y`, `n`, `e`, certificates, or PEM values.

- [ ] **Step 2: Implement CLI positive and negative controls**

The CLI runs selected scenarios on both targets, compares them, writes evidence, and exits:

- `0` for zero differences;
- `1` for real scenario differences or runtime failure;
- `2` when `--fault-injection discovery-issuer` successfully proves the comparator catches the injected candidate issuer change;
- `3` when fault injection fails to produce a difference.

Fault injection is applied only to the in-memory candidate observation after both targets finish. It never changes a service or proxy response. Fault-injected execution must not overwrite positive scenario evidence; it writes one sanitized `negative-control.json` containing only the injected rule name and resulting difference paths.

The CLI also has `--finalize-run --negative-control-path <json-pointer>` mode. It reads the already-written positive scenario evidence, validates `COMPAT_ORACLE_IMAGE_DIGEST` and `COMPAT_CANDIDATE_IMAGE_DIGEST`, calls `writeRunEvidence()`, and exits `0` only after `run.json` parses with `runEvidenceGuard`. Finalize mode performs no network requests.

- [ ] **Step 3: Unit-test both controls using fixture observations**

Assert the positive control exits `0`, the injected control returns the exact difference path `/observations/0/value/issuer`, positive scenario evidence remains byte-identical after fault injection, an unknown injection name is rejected before network access, and finalize mode writes a valid `run.json` with both fixture image digests.

- [ ] **Step 4: Run tests and commit**

```bash
cd packages/integration-tests
pnpm build
pnpm test:only -i --config=jest.config.compatibility.js ./lib/compatibility/cli.test.js
git add src/compatibility/scenarios/discovery.ts src/compatibility/cli.ts \
  src/compatibility/cli.test.ts
git commit -m "test(test): compare discovery behavior"
```

## Task 7: Add The Password Authorization-Code Vertical Scenario

**Files:**

- Create: `packages/integration-tests/src/compatibility/scenarios/password-code.ts`
- Create: `packages/integration-tests/src/compatibility/scenarios/password-code.test.ts`
- Create: `packages/integration-tests/src/compatibility/scenarios/index.ts`
- Create: `packages/integration-tests/src/compatibility/scenarios/index.test.ts`
- Modify: `packages/integration-tests/src/compatibility/cli.ts`
- Modify: `packages/integration-tests/src/compatibility/cli.test.ts`

- [ ] **Step 1: Test the scenario against a fake target boundary**

Provide a fake `TargetClient` and fake Experience client factory. Assert this exact order:

```text
set-sign-in-experience
create-user
start-interaction
verify-password
identify-user
submit-interaction
process-consent
decode-id-token
obtain-access-token
call-userinfo
clear-access-token
refresh-access-token
read-user
delete-user
```

Assert cleanup calls `delete-user` when any intermediate step rejects.

- [ ] **Step 2: Implement target-local setup without global API helpers**

Use the deterministic fixture:

```typescript
const fixture = Object.freeze({
  username: 'compat_phase0_password_user',
  password: 'Compat_phase0_password_42',
});
```

Each target has an independent database, so the same fixture is valid. Never write the password to observations or evidence.

- [ ] **Step 3: Reuse the existing Experience client with explicit endpoint/config**

Construct `ExperienceClient` with:

```typescript
const experienceClient = new ExperienceClient(
  {
    endpoint: context.target.coreUrl,
    appId: demoAppApplicationId,
    persistAccessToken: false,
  },
  context.client.experience
);
```

Pass `${context.target.coreUrl}/demo-app` as redirect URI. Reuse `identifyUserWithUsernamePassword()` and the existing client session methods, but do not use module-global `logtoUrl`, `authedAdminApi`, or `defaultConfig`.

The initialization call must be explicit:

```typescript
await experienceClient.initSession(`${context.target.coreUrl}/demo-app`);
```

Export the scenario as `export default { id: 'password-code', run } satisfies CompatibilityScenario;`.

- [ ] **Step 4: Record semantic observations only**

Bind the created user ID to `user.primary`. Record:

- created Management API user projection with volatile timestamps normalized;
- interaction cookie names/paths/security attributes without values;
- decoded ID-token header and claims plus token lifetime;
- decoded access-token claims, or opaque-token metadata if the token is not JWT;
- UserInfo response;
- proof that a second access token was obtained after clearing the cached access token;
- final Management API user projection;
- successful deletion status.

Do not record compact tokens, authorization codes, states, nonces, verification IDs, cookies, or passwords.

Create the sole default registry in `scenarios/index.ts`:

```typescript
import discoveryScenario from './discovery.js';
import passwordCodeScenario from './password-code.js';

export const defaultCompatibilityScenarios = Object.freeze([
  discoveryScenario,
  passwordCodeScenario,
]);
```

Add `index.test.ts` asserting:

```typescript
expect(defaultCompatibilityScenarios.map(({ id }) => id)).toEqual([
  'discovery',
  'password-code',
]);
```

Modify both the CLI and its tests to import `defaultCompatibilityScenarios`. Task 9's opt-in smoke test must import this same array; no caller may construct a second default list.

- [ ] **Step 5: Run the fake-boundary test and commit**

```bash
cd packages/integration-tests
pnpm build
pnpm test:only -i --config=jest.config.compatibility.js \
  ./lib/compatibility/scenarios/password-code.test.js \
  ./lib/compatibility/scenarios/index.test.js \
  ./lib/compatibility/cli.test.js
git add src/compatibility/scenarios/password-code.ts \
  src/compatibility/scenarios/password-code.test.ts \
  src/compatibility/scenarios/index.ts \
  src/compatibility/scenarios/index.test.ts \
  src/compatibility/cli.ts src/compatibility/cli.test.ts
git commit -m "test(test): add password code scenario"
```

## Task 8: Add The Isolated Dual-Instance Environment

**Files:**

- Create: `docker-compose.compatibility.yml`
- Create: `.scripts/compatibility/run.sh`

- [ ] **Step 1: Create an anchor-free Compose file**

Define complete services without YAML inheritance:

- `postgres-oracle`, `redis-oracle`, `logto-oracle`
- `postgres-candidate`, `redis-candidate`, `logto-candidate`

Use PostgreSQL 17 Alpine and Redis 6 Alpine exactly as `docker-compose.integration.yml`. Build and tag only `logto-oracle` as `logto-compat-reference:6852a7b8c`; default `logto-candidate` to that image through `COMPAT_CANDIDATE_IMAGE`.

Map:

```text
oracle core/admin:    3101/3201 -> 3001/3002
candidate core/admin: 3102/3202 -> 3001/3002
```

Set each service's advertised `ENDPOINT` and `ADMIN_ENDPOINT` to its mapped localhost URL. Give each service independent DB, Redis, and mock-message bind mounts. Require the lifecycle script to generate fresh PostgreSQL, vault KEK, and status API test credentials for every run; do not commit or print their values.

Use this complete service topology, retaining the existing health-check details:

```yaml
services:
  postgres-oracle:
    image: postgres:17-alpine
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: ${COMPAT_POSTGRES_PASSWORD:?required}
      POSTGRES_DB: postgres
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres -d postgres"]
      interval: 3s
      timeout: 3s
      retries: 20

  redis-oracle:
    image: redis:6-alpine
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 3s
      timeout: 3s
      retries: 20

  logto-oracle:
    image: logto-compat-reference:6852a7b8c
    build:
      context: .
      dockerfile: Dockerfile.integration
    stop_signal: SIGINT
    volumes:
      - ${COMPAT_ORACLE_MESSAGE_DIR:?required}:/tmp/logto
    extra_hosts:
      - "host.docker.internal:host-gateway"
    depends_on:
      postgres-oracle:
        condition: service_healthy
      redis-oracle:
        condition: service_healthy
    environment:
      DB_URL: postgres://postgres:${COMPAT_POSTGRES_PASSWORD:?required}@postgres-oracle:5432/postgres
      REDIS_URL: redis://redis-oracle:6379
      ENDPOINT: http://localhost:3101
      ADMIN_ENDPOINT: http://localhost:3201
      SECRET_VAULT_KEK: ${COMPAT_SECRET_VAULT_KEK:?required}
      STATUS_API_KEY: ${COMPAT_STATUS_API_KEY:?required}
      TRUST_PROXY_HEADER: "1"
    healthcheck:
      test: ["CMD-SHELL", "nc -z localhost 3001 || exit 1"]
      interval: 3s
      timeout: 3s
      retries: 60
    ports:
      - "3101:3001"
      - "3201:3002"

  postgres-candidate:
    image: postgres:17-alpine
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: ${COMPAT_POSTGRES_PASSWORD:?required}
      POSTGRES_DB: postgres
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres -d postgres"]
      interval: 3s
      timeout: 3s
      retries: 20

  redis-candidate:
    image: redis:6-alpine
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 3s
      timeout: 3s
      retries: 20

  logto-candidate:
    image: ${COMPAT_CANDIDATE_IMAGE:-logto-compat-reference:6852a7b8c}
    stop_signal: SIGINT
    volumes:
      - ${COMPAT_CANDIDATE_MESSAGE_DIR:?required}:/tmp/logto
    extra_hosts:
      - "host.docker.internal:host-gateway"
    depends_on:
      postgres-candidate:
        condition: service_healthy
      redis-candidate:
        condition: service_healthy
    environment:
      DB_URL: postgres://postgres:${COMPAT_POSTGRES_PASSWORD:?required}@postgres-candidate:5432/postgres
      REDIS_URL: redis://redis-candidate:6379
      ENDPOINT: http://localhost:3102
      ADMIN_ENDPOINT: http://localhost:3202
      SECRET_VAULT_KEK: ${COMPAT_SECRET_VAULT_KEK:?required}
      STATUS_API_KEY: ${COMPAT_STATUS_API_KEY:?required}
      TRUST_PROXY_HEADER: "1"
    healthcheck:
      test: ["CMD-SHELL", "nc -z localhost 3001 || exit 1"]
      interval: 3s
      timeout: 3s
      retries: 60
    ports:
      - "3102:3001"
      - "3202:3002"
```

- [ ] **Step 2: Implement an owned lifecycle script**

`run.sh` must:

1. require a clean runtime-source diff against `6852a7b8c8984c5c12b2061e8c51faa310a36412` using `git diff --quiet` over the whole repository while excluding only `docs/superpowers/**`, `packages/integration-tests/**`, `compatibility/**`, `.scripts/compatibility/**`, `docker-compose.compatibility.yml`, and `.github/workflows/compatibility-test.yml`;
2. create a private run directory under `/var/tmp/henry-build/logto-compatibility` using `mktemp -d`;
3. use a unique explicit Compose project name `logto-compat-<pid>`;
4. export separate oracle/candidate mock-message directories;
5. build the reference image once;
6. start all six services with `docker compose up -d --wait`;
7. build `@logto/integration-tests...`;
8. when `COMPAT_WRITE_BASELINE=1`, generate the oracle manifest with `COMPAT_ALLOW_MANIFEST_WRITE=1`; otherwise check both oracle and candidate inventories against the committed manifest;
9. run the positive CLI, then the injected negative control without restarting services;
10. record exact oracle and candidate image digests in sanitized `run.json` evidence;
11. dump per-service logs and sanitized evidence into the private run directory;
12. call `docker compose down -v --remove-orphans` only for its owned project in an EXIT trap;
13. preserve evidence after cleanup and print only its directory path.

Before its first Docker command, the script must fail clearly if any of ports 3101, 3201, 3102, or 3202 is already listening. It must not terminate the owning process or reuse that service.

The script must not use `/dev/shm`, a broad `docker compose down` without the owned project, or `rm -rf` on a variable path.

Implement the lifecycle with this exact control flow:

```bash
#!/usr/bin/env bash
set -euo pipefail
umask 077

REFERENCE_COMMIT=6852a7b8c8984c5c12b2061e8c51faa310a36412
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/docker-compose.compatibility.yml"
PROJECT_NAME="logto-compat-$$"
RUN_ROOT="${COMPAT_RUN_ROOT:-/var/tmp/henry-build/logto-compatibility}"

mkdir -p "${RUN_ROOT}"
chmod 700 "${RUN_ROOT}"
RUN_DIR="$(mktemp -d "${RUN_ROOT}/run.XXXXXX")"
export COMPAT_ORACLE_MESSAGE_DIR="${RUN_DIR}/oracle-messages"
export COMPAT_CANDIDATE_MESSAGE_DIR="${RUN_DIR}/candidate-messages"
mkdir -p "${COMPAT_ORACLE_MESSAGE_DIR}" "${COMPAT_CANDIDATE_MESSAGE_DIR}"
export COMPAT_EVIDENCE_DIR="${RUN_DIR}/evidence"
mkdir -p "${COMPAT_EVIDENCE_DIR}"
chmod 700 "${COMPAT_EVIDENCE_DIR}"

export COMPAT_POSTGRES_PASSWORD
export COMPAT_SECRET_VAULT_KEK
export COMPAT_STATUS_API_KEY
COMPAT_POSTGRES_PASSWORD="$(node -e "process.stdout.write(require('node:crypto').randomBytes(16).toString('hex'))")"
COMPAT_SECRET_VAULT_KEK="$(node -e "process.stdout.write(require('node:crypto').randomBytes(32).toString('base64'))")"
COMPAT_STATUS_API_KEY="$(node -e "process.stdout.write(require('node:crypto').randomBytes(24).toString('hex'))")"

for port in 3101 3201 3102 3202; do
  if timeout 1 bash -c "</dev/tcp/127.0.0.1/${port}" 2>/dev/null; then
    printf '[compat] port %s is already in use\n' "${port}" >&2
    exit 1
  fi
done

compose=(docker compose -p "${PROJECT_NAME}" -f "${COMPOSE_FILE}")

dump_logs() {
  local service
  for service in postgres-oracle redis-oracle logto-oracle postgres-candidate redis-candidate logto-candidate; do
    "${compose[@]}" logs "${service}" >"${RUN_DIR}/${service}.log" 2>&1 || true
  done
}

cleanup() {
  local exit_code=$?
  dump_logs
  "${compose[@]}" down -v --remove-orphans || true
  printf '[compat] evidence: %s\n' "${RUN_DIR}"
  exit "${exit_code}"
}
trap cleanup EXIT

cd "${REPO_ROOT}"
git diff --quiet "${REFERENCE_COMMIT}" -- . \
  ':(exclude)docs/superpowers/**' \
  ':(exclude)packages/integration-tests/**' \
  ':(exclude)compatibility/**' \
  ':(exclude).scripts/compatibility/**' \
  ':(exclude)docker-compose.compatibility.yml' \
  ':(exclude).github/workflows/compatibility-test.yml'

untracked_runtime="$(git ls-files --others --exclude-standard | grep -Ev \
  '^(docs/superpowers/|packages/integration-tests/|compatibility/|\.scripts/compatibility/|docker-compose\.compatibility\.yml$|\.github/workflows/compatibility-test\.yml$)' || true)"
if [[ -n "${untracked_runtime}" ]]; then
  printf '[compat] untracked runtime input:\n%s\n' "${untracked_runtime}" >&2
  exit 1
fi

"${compose[@]}" build logto-oracle
"${compose[@]}" up -d --wait

pnpm -r --filter '@logto/integration-tests...' build

export COMPAT_ORACLE_URL=http://localhost:3101
export COMPAT_ORACLE_ADMIN_URL=http://localhost:3201
export COMPAT_CANDIDATE_URL=http://localhost:3102
export COMPAT_CANDIDATE_ADMIN_URL=http://localhost:3202
export COMPAT_REPO_ROOT="${REPO_ROOT}"
export COMPAT_ORACLE_IMAGE_DIGEST
export COMPAT_CANDIDATE_IMAGE_DIGEST
COMPAT_ORACLE_IMAGE_DIGEST="$(docker inspect --format '{{.Image}}' "$("${compose[@]}" ps -q logto-oracle)")"
COMPAT_CANDIDATE_IMAGE_DIGEST="$(docker inspect --format '{{.Image}}' "$("${compose[@]}" ps -q logto-candidate)")"

cd "${REPO_ROOT}/packages/integration-tests"
if [[ "${COMPAT_WRITE_BASELINE:-0}" == "1" ]]; then
  COMPAT_ALLOW_MANIFEST_WRITE=1 pnpm compatibility:inventory -- --target oracle --write
else
  pnpm compatibility:inventory -- --target oracle --check
  pnpm compatibility:inventory -- --target candidate --check
fi

pnpm compatibility:run
printf '[compat] positive control: zero differences\n'

set +e
pnpm compatibility:run -- --fault-injection discovery-issuer
negative_exit=$?
set -e
if [[ "${negative_exit}" != "2" ]]; then
  printf '[compat] negative control failed with exit %s\n' "${negative_exit}" >&2
  exit 1
fi
printf '[compat] negative control: expected difference detected\n'
pnpm compatibility:run -- \
  --finalize-run \
  --negative-control-path /observations/0/value/issuer
```

Task 9 adds the opt-in Jest invocation after the negative-control block and before cleanup.

- [ ] **Step 3: Run the complete local lab**

```bash
COMPAT_WRITE_BASELINE=1 ./.scripts/compatibility/run.sh
```

Expected:

```text
[compat] positive control: zero differences
[compat] negative control: expected difference detected
[compat] evidence: /var/tmp/henry-build/logto-compatibility/<run-id>
```

All six containers must be gone after the command exits. `compatibility/baseline-manifest.json` must now exist, be sorted, and contain non-zero entries for all seven surfaces. Run `./.scripts/compatibility/run.sh` a second time without `COMPAT_WRITE_BASELINE`; it must check both targets without modifying the manifest.

- [ ] **Step 4: Inspect evidence and verify forbidden material is absent**

Run:

```bash
evidence_dir="$(find /var/tmp/henry-build/logto-compatibility -mindepth 2 -maxdepth 2 \
  -type d -name evidence -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)"
test -n "${evidence_dir}"
find "${evidence_dir}" -type f -name '*.json' -print0 | xargs -0 -r rg -n \
  '(access_token|refresh_token|id_token|set-cookie|authorization_code|Compat_phase0_password_42)'
```

Expected: no matches in JSON evidence. Confirm `evidence_dir` is below the configured run root before scanning. Service logs are diagnostic artifacts and must remain in the private run directory, never uploaded until separately redacted.

- [ ] **Step 5: Commit the environment**

```bash
chmod 755 .scripts/compatibility/run.sh
git add compatibility/baseline-manifest.json docker-compose.compatibility.yml \
  .scripts/compatibility/run.sh
git update-index --chmod=+x .scripts/compatibility/run.sh
git commit -m "test(test): run isolated reference pair"
```

## Task 9: Add The Opt-In Jest Smoke Test And Existing-Suite Regression

**Files:**

- Create: `packages/integration-tests/src/compatibility/tests/reference-parity.test.ts`
- Modify: `.scripts/compatibility/run.sh`

- [ ] **Step 1: Add an opt-in smoke test**

The test skips unless `COMPAT_RUN_DUAL_TARGET=1`. When enabled, it loads validated configuration, imports `defaultCompatibilityScenarios` from `scenarios/index.ts`, runs every member, and asserts `differences` is empty for both. It must not name discovery or password-code separately.

- [ ] **Step 2: Make the lifecycle script run the smoke test while targets are live**

After the positive control, negative control, and `--finalize-run` command have completed, but before log collection, invoke the built Jest test with `COMPAT_RUN_DUAL_TARGET=1` and the four target URLs already owned by the script.

Append this command immediately after the `--finalize-run` command in `run.sh`:

```bash
COMPAT_RUN_DUAL_TARGET=1 \
  pnpm test:only -i --config=jest.config.compatibility.js \
    ./lib/compatibility/tests/reference-parity.test.js
```

- [ ] **Step 3: Run compatibility unit and dual-target tests from a clean environment**

```bash
cd packages/integration-tests
pnpm build
pnpm test:compatibility
cd ../..
./.scripts/compatibility/run.sh
```

Expected: unit tests and both scenarios pass.

- [ ] **Step 4: Run the existing API suite against one standard integration instance**

```bash
./.scripts/integration/run.sh api
```

Expected: existing API integration suite passes unchanged.

- [ ] **Step 5: Run package quality gates**

```bash
pnpm --filter @logto/integration-tests check
pnpm --filter @logto/integration-tests lint
```

Expected: TypeScript and ESLint pass.

- [ ] **Step 6: Commit the smoke test and lifecycle update**

```bash
git add packages/integration-tests/src/compatibility/tests/reference-parity.test.ts \
  .scripts/compatibility/run.sh
git commit -m "test(test): verify reference parity"
```

## Task 10: Document Operation And Add CI

**Files:**

- Create: `compatibility/README.md`
- Create: `.github/workflows/compatibility-test.yml`

- [ ] **Step 1: Write the operator README**

Document:

- pinned commit and what is excluded (proprietary Cloud backend);
- inventory generation/check commands;
- positive and negative controls;
- evidence schema and `/var/tmp/henry-build` location;
- forbidden evidence fields;
- how `COMPAT_CANDIDATE_IMAGE` replaces the mirror target later;
- phase-0 exit criteria from this plan;
- troubleshooting using private service logs without committing them.
- the intentional frozen-baseline behavior: runtime-source changes fail the pin gate, and this workflow must not become a required check on unrelated product branches without an explicit baseline-update process.

- [ ] **Step 2: Add a direct CI workflow**

Create a workflow on `ubuntu-22.04` with `timeout-minutes: 60`. Record actual wall time in the phase-0 acceptance record before deciding whether a lower timeout is safe. It must:

1. check out the branch;
2. install Node 22 and pnpm 10;
3. run `pnpm install --frozen-lockfile`;
4. set `COMPAT_RUN_ROOT=${RUNNER_TEMP}/logto-compatibility-evidence`;
5. run `bash .scripts/compatibility/run.sh`;
6. upload only `${COMPAT_RUN_ROOT}/run.*/evidence/*.json` with `actions/upload-artifact@v4` under `if: always()`;
7. never upload service logs automatically.

Configure `actions/checkout@v4` with `fetch-depth: 0` so the pinned commit exists for the runtime diff gate.

Trigger on pull requests that change:

```yaml
paths:
  - 'compatibility/**'
  - 'docker-compose.compatibility.yml'
  - 'Dockerfile.integration'
  - 'Dockerfile'
  - '.scripts/compatibility/**'
  - '.scripts/integration/**'
  - '.scripts/package.sh'
  - '.github/workflows/compatibility-test.yml'
  - 'packages/**'
  - 'pnpm-lock.yaml'
```

- [ ] **Step 3: Validate workflow and README commands locally**

```bash
pnpm --filter @logto/integration-tests exec prettier --check \
  ../../compatibility/README.md ../../.github/workflows/compatibility-test.yml
./.scripts/compatibility/run.sh
```

Expected: formatting passes; controls produce the same results as task 8.

- [ ] **Step 4: Commit documentation and CI**

```bash
git add compatibility/README.md .github/workflows/compatibility-test.yml
git commit -m "ci(test): gate Logto compatibility lab"
```

## Task 11: Produce And Verify The Phase-0 Acceptance Record

**Files:**

- Create: `compatibility/phase-0-acceptance.md`

- [ ] **Step 1: Run the final commands from a clean checkout state**

```bash
pnpm --filter @logto/integration-tests check
pnpm --filter @logto/integration-tests lint
pnpm --filter @logto/integration-tests build
pnpm --filter @logto/integration-tests test:compatibility
./.scripts/compatibility/run.sh
./.scripts/integration/run.sh api
./.scripts/integration/run.sh experience
./.scripts/integration/run.sh console
```

Expected: every command exits `0`; the compatibility script explicitly reports both the zero-diff positive control and detected negative control, and all three existing integration targets remain green.

- [ ] **Step 2: Generate the acceptance record from actual evidence**

Write only observed values:

- reference commit and reference image digest;
- counts by capability surface from `baseline-manifest.json`;
- scenario IDs and zero-difference result;
- negative-control difference path;
- command list and exit status;
- evidence directory path, without embedding service logs or secrets;
- remaining phase-1 prerequisites: non-spoofable RLS context, admin/data-tenant split, and compatibility-host isolation.

- [ ] **Step 3: Verify the acceptance record has no placeholders or sensitive material**

```bash
rg -n 'TBD|TODO|FIXME|PLACEHOLDER' compatibility/phase-0-acceptance.md
rg -n '(BEGIN .*PRIVATE KEY|access_token|refresh_token|id_token|set-cookie|Compat_phase0_password_42)' \
  compatibility/phase-0-acceptance.md
```

Expected: both commands return no matches.

- [ ] **Step 4: Obtain required independent review**

Prepare a private, non-secret packet containing the intent, exact diff, final command outputs, sanitized acceptance record, and open risks. Run read-only Claude Code and Grok reviews under the repository review policy. Address every `BLOCK`; unavailable output is not approval.

- [ ] **Step 5: Commit the acceptance record**

```bash
git add compatibility/phase-0-acceptance.md
git commit -m "docs(test): record compatibility lab acceptance"
```

## Final Phase-0 Verification

Before declaring phase 0 complete:

```bash
git status --short
git log --oneline --decorate -12
git diff --check 6c56cb7cd..HEAD
```

Expected:

- no uncommitted files;
- one reviewable commit per task unit;
- no whitespace errors;
- final acceptance record cites fresh command evidence;
- phase 1 has not been scaffolded.
