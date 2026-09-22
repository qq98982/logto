#!/usr/bin/env node

import { Buffer } from "node:buffer";
import { randomBytes } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, open, realpath, stat, unlink } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const REFERENCE_SOURCE = "6852a7b8c8984c5c12b2061e8c51faa310a36412";
const REFERENCE_IMAGE =
  "sha256:76a9977bfc5ea3ed5b7623b879c27256670e377e27b987e8af99b53d55b30bbd";
const BUILD_ROOT = "/var/tmp/henry-build";
const SUCCESS_TEXT = "Phase 2 client credentials oracle collected.\n";
const FAILURE_TEXT = "Phase 2 client credentials oracle collection failed.\n";
const MAXIMUM_BODY_BYTES = 64 * 1024;
const MAXIMUM_HEADER_BYTES = 16 * 1024;
const JWKS_MEDIA_TYPE = "application/jwk-set+json";
const CANCELLATION_TIMEOUT_MILLISECONDS = 100;
const REQUEST_TIMEOUT_MILLISECONDS = 5_000;
const COLLECTION_TIMEOUT_MILLISECONDS = 25_000;
const CLEANUP_TIMEOUT_MILLISECONDS = 15_000;
const TOTAL_TIMEOUT_MILLISECONDS = 40_000;
const CASES = Object.freeze([
  "basic-explicit-resource",
  "post-explicit-resource",
  "default-resource",
  "resource-no-scope",
  "resource-partial-scope",
  "organization-empty-scope",
  "organization-scope",
  "organization-resource-scope",
  "unknown-client-basic",
  "unknown-client-post",
  "wrong-secret-basic",
  "wrong-secret-post",
  "mixed-authentication",
  "missing-target",
  "unknown-resource",
  "unassociated-organization",
  "duplicate-resource",
  "duplicate-scope-name",
  "malformed-scope-whitespace",
  "unsupported-parameter",
]);
const REQUIRED_ARGUMENTS = new Set([
  "--endpoint",
  "--output",
  "--reference-source",
  "--reference-image",
]);
const PRIVATE_JWK_MEMBERS = new Set([
  "d",
  "p",
  "q",
  "dp",
  "dq",
  "qi",
  "oth",
  "k",
]);
const FORBIDDEN_FIELD_NAME =
  /(?:authorization|proxy.?authorization|cookie|set.?cookie|client.?secret|access.?token|refresh.?token|id.?token)/iu;
const CREDENTIAL_LABEL =
  /\b(?:authorization|proxy-authorization|cookie|set-cookie)\s*:/iu;

class CollectorError extends Error {
  constructor() {
    super("collector failed");
    this.name = "CollectorError";
    this.stack = this.message;
  }
}

const fail = () => {
  throw new CollectorError();
};

const parseArguments = (argv) => {
  if (!Array.isArray(argv) || argv.length !== REQUIRED_ARGUMENTS.size * 2) {
    return fail();
  }
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (
      typeof name !== "string" ||
      typeof value !== "string" ||
      !REQUIRED_ARGUMENTS.has(name) ||
      values.has(name) ||
      value.length === 0 ||
      Buffer.byteLength(value) > 4096 ||
      /\p{Cc}/u.test(value)
    ) {
      return fail();
    }
    values.set(name, value);
  }
  if ([...REQUIRED_ARGUMENTS].some((name) => !values.has(name))) {
    return fail();
  }
  return Object.freeze({
    endpoint: values.get("--endpoint"),
    output: values.get("--output"),
    referenceSource: values.get("--reference-source"),
    referenceImage: values.get("--reference-image"),
  });
};

const validateLoopbackOrigin = (value) => {
  try {
    const url = new URL(value);
    const port = Number(url.port);
    if (
      url.protocol !== "http:" ||
      (url.hostname !== "127.0.0.1" && url.hostname !== "localhost") ||
      !/^[1-9][0-9]{0,4}$/u.test(url.port) ||
      port < 1024 ||
      port > 65_535 ||
      url.username !== "" ||
      url.password !== "" ||
      url.pathname !== "/" ||
      url.search !== "" ||
      url.hash !== ""
    ) {
      return fail();
    }
    return url;
  } catch {
    return fail();
  }
};

const assertPrivateDirectory = async (directory) => {
  const resolved = await realpath(directory).catch(fail);
  const metadata = await lstat(directory).catch(fail);
  if (
    resolved !== directory ||
    !metadata.isDirectory() ||
    metadata.isSymbolicLink() ||
    metadata.uid !== process.getuid() ||
    (metadata.mode & 0o777) !== 0o700
  ) {
    return fail();
  }
};

const validateOutputPath = async (value) => {
  if (
    typeof value !== "string" ||
    !path.isAbsolute(value) ||
    path.normalize(value) !== value ||
    !/^phase2-client-credentials-oracle-[A-Za-z0-9][A-Za-z0-9_-]{0,79}\.json$/u.test(
      path.basename(value),
    )
  ) {
    return fail();
  }
  const parent = path.dirname(value);
  if (parent !== BUILD_ROOT && !parent.startsWith(`${BUILD_ROOT}/`)) {
    return fail();
  }
  await assertPrivateDirectory(BUILD_ROOT);
  let current = BUILD_ROOT;
  for (const segment of path
    .relative(BUILD_ROOT, parent)
    .split(path.sep)
    .filter(Boolean)) {
    current = path.join(current, segment);
    const metadata = await lstat(current).catch(fail);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      return fail();
    }
  }
  await assertPrivateDirectory(parent);
  try {
    await lstat(value);
    return fail();
  } catch (error) {
    if (error?.code !== "ENOENT") {
      return fail();
    }
  }
  return value;
};

const responseHeaderBytes = (headers) =>
  [...headers.entries()].reduce(
    (total, [name, value]) =>
      total + Buffer.byteLength(name) + Buffer.byteLength(value) + 4,
    0,
  );

export const cancelSafely = async (value) => {
  try {
    if (typeof value !== "object" || value === null) {
      return;
    }
    const cancel = Reflect.get(value, "cancel");
    if (typeof cancel !== "function") {
      return;
    }
    const cancellation = (async () => {
      try {
        await Promise.resolve(Reflect.apply(cancel, value, []));
      } catch {
        // Cancellation is best-effort.
      }
    })();
    const timeout = new Promise((resolve) => {
      setTimeout(resolve, CANCELLATION_TIMEOUT_MILLISECONDS);
    });
    await Promise.race([cancellation, timeout]);
  } catch {
    // Best-effort cancellation must not alter the fixed public error.
  }
};

const cancelResponse = async (response) => cancelSafely(response.body);

const readBoundedBody = async (response) => {
  if (responseHeaderBytes(response.headers) > MAXIMUM_HEADER_BYTES) {
    await cancelResponse(response);
    return fail();
  }
  const contentLength = response.headers.get("content-length");
  if (
    contentLength !== null &&
    (!/^(?:0|[1-9][0-9]*)$/u.test(contentLength) ||
      Number(contentLength) > MAXIMUM_BODY_BYTES)
  ) {
    await cancelResponse(response);
    return fail();
  }
  if (!response.body) {
    return new Uint8Array();
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) {
        break;
      }
      if (!(result.value instanceof Uint8Array)) {
        await cancelSafely(reader);
        return fail();
      }
      total += result.value.byteLength;
      if (total > MAXIMUM_BODY_BYTES) {
        await cancelSafely(reader);
        return fail();
      }
      chunks.push(result.value);
    }
  } catch {
    await cancelSafely(reader);
    return fail();
  } finally {
    reader.releaseLock();
  }
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
};

const request = async (url, init, totalSignal) => {
  if (totalSignal.aborted) {
    return fail();
  }
  const requestSignal = AbortSignal.any([
    totalSignal,
    AbortSignal.timeout(REQUEST_TIMEOUT_MILLISECONDS),
    ...(init.signal instanceof AbortSignal ? [init.signal] : []),
  ]);
  let response;
  try {
    response = await fetch(url, {
      ...init,
      redirect: "manual",
      signal: requestSignal,
    });
  } catch {
    return fail();
  }
  if (response.status >= 300 && response.status < 400) {
    await cancelResponse(response);
    return fail();
  }
  return response;
};

const parseJsonObject = (bytes) => {
  try {
    const value = JSON.parse(
      new TextDecoder("utf8", { fatal: true }).decode(bytes),
    );
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      return fail();
    }
    return value;
  } catch {
    return fail();
  }
};

const createAdminClient = (origin, totalSignal) => {
  const call = async (
    method,
    apiPath,
    body,
    expectedStatuses,
    responseKind = "object",
  ) => {
    if (
      !/^[A-Za-z0-9._~!$&'()*+,;=:@%/-]+$/u.test(apiPath) ||
      apiPath.startsWith("/")
    ) {
      return fail();
    }
    const headers = new Headers({
      "development-user-id": "integration-test-admin-user",
    });
    if (body !== undefined) {
      headers.set("content-type", "application/json");
    }
    const response = await request(
      new URL(`/api/${apiPath}`, origin),
      {
        method,
        headers,
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      },
      totalSignal,
    );
    if (!expectedStatuses.includes(response.status)) {
      await cancelResponse(response);
      return fail();
    }
    const bytes = await readBoundedBody(response);
    if (responseKind === "status") {
      return response.status;
    }
    if (responseKind === "empty") {
      if (bytes.byteLength !== 0) {
        return fail();
      }
      return undefined;
    }
    const mediaType = response.headers
      .get("content-type")
      ?.split(";", 1)[0]
      ?.trim()
      .toLowerCase();
    if (responseKind === "created") {
      if (
        mediaType !== "text/plain" ||
        new TextDecoder("utf8", { fatal: true }).decode(bytes) !== "Created"
      ) {
        return fail();
      }
      return undefined;
    }
    if (mediaType !== "application/json") {
      return fail();
    }
    if (responseKind === "array") {
      try {
        const value = JSON.parse(
          new TextDecoder("utf8", { fatal: true }).decode(bytes),
        );
        return Array.isArray(value) ? value : fail();
      } catch {
        return fail();
      }
    }
    return parseJsonObject(bytes);
  };
  return Object.freeze({
    getArray: (apiPath) => call("GET", apiPath, undefined, [200], "array"),
    post: (apiPath, body, statuses = [200, 201]) =>
      call("POST", apiPath, body, statuses),
    postCreated: (apiPath, body) =>
      call("POST", apiPath, body, [201], "created"),
    patch: (apiPath, body) => call("PATCH", apiPath, body, [200]),
    delete: (apiPath) =>
      call("DELETE", apiPath, undefined, [204, 404], "status"),
  });
};

const idFrom = (value) => {
  const id = value?.id;
  if (typeof id !== "string" || !/^[A-Za-z0-9._~-]{1,128}$/u.test(id)) {
    return fail();
  }
  return id;
};

const validateJwks = (value) => {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Reflect.ownKeys(value).some((key) => key !== "keys") ||
    !Array.isArray(value.keys) ||
    value.keys.length === 0 ||
    value.keys.length > 32
  ) {
    return fail();
  }
  for (const key of value.keys) {
    if (
      typeof key !== "object" ||
      key === null ||
      Array.isArray(key) ||
      Reflect.ownKeys(key).some(
        (member) =>
          typeof member !== "string" || PRIVATE_JWK_MEMBERS.has(member),
      )
    ) {
      return fail();
    }
  }
  return structuredClone(value);
};

const fetchJwks = async (origin, totalSignal) => {
  const response = await request(
    new URL("/oidc/jwks", origin),
    { method: "GET" },
    totalSignal,
  );
  if (response.status !== 200) {
    await cancelResponse(response);
    return fail();
  }
  if (
    response.headers
      .get("content-type")
      ?.split(";", 1)[0]
      ?.trim()
      .toLowerCase() !== JWKS_MEDIA_TYPE
  ) {
    await cancelResponse(response);
    return fail();
  }
  return validateJwks(parseJsonObject(await readBoundedBody(response)));
};

const createCleanup = () => {
  const pending = [];
  const add = (name, apiPath) => {
    pending.push(Object.freeze({ name, apiPath }));
  };
  const run = async (admin) => {
    const operations = [];
    let successful = true;
    while (pending.length > 0) {
      const operation = pending.pop();
      try {
        const status = await admin.delete(operation.apiPath);
        operations.push(
          Object.freeze({
            name: operation.name,
            status: status === 204 ? "deleted" : "absent",
          }),
        );
      } catch {
        successful = false;
        operations.push(
          Object.freeze({ name: operation.name, status: "failed" }),
        );
      }
    }
    return Object.freeze({ successful, operations: Object.freeze(operations) });
  };
  return Object.freeze({ add, run });
};

const reconcileProvisionedEntities = async (admin, allocationId) => {
  const marker = `phase2-client-credentials-${allocationId}`;
  const definitions = [
    {
      kind: "organization",
      path: "organizations",
      owns: (row) => row.name === `Phase 2 ${marker} organization`,
    },
    {
      kind: "application",
      path: "applications",
      owns: (row) =>
        row.name === `Phase 2 ${marker} basic client` ||
        row.name === `Phase 2 ${marker} post client`,
    },
    {
      kind: "organization-role",
      path: "organization-roles",
      owns: (row) => row.name === `${marker}-organization-role`,
    },
    {
      kind: "organization-scope",
      path: "organization-scopes",
      owns: (row) => row.description === `Phase 2 ${marker} organization scope`,
    },
    {
      kind: "role",
      path: "roles",
      owns: (row) => row.name === `${marker}-resource-role`,
    },
    {
      kind: "resource",
      path: "resources",
      owns: (row) =>
        row.name === `Phase 2 ${marker} primary resource` ||
        row.name === `Phase 2 ${marker} default resource`,
    },
  ];
  const operations = [];
  let successful = true;

  for (const definition of definitions) {
    let rows;
    try {
      rows = await admin.getArray(definition.path);
    } catch {
      successful = false;
      operations.push(
        Object.freeze({ name: `list-${definition.kind}`, status: "failed" }),
      );
      continue;
    }
    for (const row of rows.filter(definition.owns)) {
      let id;
      try {
        id = idFrom(row);
      } catch {
        successful = false;
        operations.push(
          Object.freeze({
            name: `identify-${definition.kind}`,
            status: "failed",
          }),
        );
        continue;
      }
      try {
        const status = await admin.delete(
          `${definition.path}/${encodeURIComponent(id)}`,
        );
        operations.push(
          Object.freeze({
            name: `${definition.kind}-${id}`,
            status: status === 204 ? "deleted" : "absent",
          }),
        );
      } catch {
        successful = false;
        operations.push(
          Object.freeze({ name: `${definition.kind}-${id}`, status: "failed" }),
        );
      }
    }
  }

  return Object.freeze({ successful, operations: Object.freeze(operations) });
};

const readApplicationSecret = async (admin, applicationId) => {
  const secrets = await admin.getArray(
    `applications/${encodeURIComponent(applicationId)}/secrets`,
  );
  if (secrets.length !== 1) {
    return fail();
  }
  const secret = secrets[0]?.value;
  if (typeof secret !== "string" || !/^[A-Za-z0-9]{32}$/u.test(secret)) {
    return fail();
  }
  return secret;
};

const provision = async (admin, cleanup, allocationId) => {
  const marker = `phase2-client-credentials-${allocationId}`;
  const createApplication = async (label) => {
    const application = await admin.post("applications", {
      name: `Phase 2 ${marker} ${label} client`,
      type: "MachineToMachine",
    });
    const id = idFrom(application);
    cleanup.add(
      `application-${label}`,
      `applications/${encodeURIComponent(id)}`,
    );
    return Object.freeze({
      id,
      secret: await readApplicationSecret(admin, id),
    });
  };
  const createResource = async (label, indicator) => {
    const resource = await admin.post(
      "resources",
      { name: `Phase 2 ${marker} ${label} resource`, indicator },
      [201],
    );
    const id = idFrom(resource);
    cleanup.add(`resource-${label}`, `resources/${encodeURIComponent(id)}`);
    return Object.freeze({ id, indicator });
  };
  const createScope = async (resource, name) => {
    const scope = await admin.post(
      `resources/${encodeURIComponent(resource.id)}/scopes`,
      { name, description: `Phase 2 ${name}` },
      [201],
    );
    const id = idFrom(scope);
    cleanup.add(
      `resource-scope-${name}`,
      `resources/${encodeURIComponent(resource.id)}/scopes/${encodeURIComponent(id)}`,
    );
    return Object.freeze({ id, name });
  };

  const basic = await createApplication("basic");
  const post = await createApplication("post");
  const primary = await createResource(
    "primary",
    "https://phase2.example.invalid/api-primary",
  );
  const defaultResource = await createResource(
    "default",
    "https://phase2.example.invalid/api-default",
  );
  const read = await createScope(primary, "read");
  const write = await createScope(primary, "write");
  const unassigned = await createScope(primary, "unassigned");

  const resourceRole = await admin.post("roles", {
    name: `${marker}-resource-role`,
    description: `Phase 2 ${marker} resource authority`,
    type: "MachineToMachine",
    scopeIds: [read.id, write.id],
  });
  const resourceRoleId = idFrom(resourceRole);
  cleanup.add("resource-role", `roles/${encodeURIComponent(resourceRoleId)}`);
  for (const [label, client] of [
    ["basic", basic],
    ["post", post],
  ]) {
    cleanup.add(
      `application-${label}-resource-role`,
      `applications/${encodeURIComponent(client.id)}/roles/${encodeURIComponent(resourceRoleId)}`,
    );
    await admin.post(
      `applications/${encodeURIComponent(client.id)}/roles`,
      { roleIds: [resourceRoleId] },
      [201],
    );
  }

  const organization = await admin.post(
    "organizations",
    { name: `Phase 2 ${marker} organization` },
    [201],
  );
  const organizationId = idFrom(organization);
  cleanup.add(
    "organization",
    `organizations/${encodeURIComponent(organizationId)}`,
  );
  const organizationScope = await admin.post(
    "organization-scopes",
    {
      name: "organization:read",
      description: `Phase 2 ${marker} organization scope`,
    },
    [201],
  );
  const organizationScopeId = idFrom(organizationScope);
  cleanup.add(
    "organization-scope",
    `organization-scopes/${encodeURIComponent(organizationScopeId)}`,
  );
  const organizationRole = await admin.post(
    "organization-roles",
    {
      name: `${marker}-organization-role`,
      description: `Phase 2 ${marker} organization authority`,
      type: "MachineToMachine",
      organizationScopeIds: [organizationScopeId],
      resourceScopeIds: [read.id, write.id],
    },
    [201],
  );
  const organizationRoleId = idFrom(organizationRole);
  cleanup.add(
    "organization-role",
    `organization-roles/${encodeURIComponent(organizationRoleId)}`,
  );
  cleanup.add(
    "organization-application-association",
    `organizations/${encodeURIComponent(organizationId)}/applications/${encodeURIComponent(
      basic.id,
    )}`,
  );
  await admin.postCreated(
    `organizations/${encodeURIComponent(organizationId)}/applications`,
    { applicationIds: [basic.id] },
  );
  cleanup.add(
    "organization-application-role",
    `organizations/${encodeURIComponent(organizationId)}/applications/${encodeURIComponent(
      basic.id,
    )}/roles/${encodeURIComponent(organizationRoleId)}`,
  );
  await admin.postCreated(
    `organizations/${encodeURIComponent(organizationId)}/applications/${encodeURIComponent(
      basic.id,
    )}/roles`,
    { organizationRoleIds: [organizationRoleId] },
  );
  await admin.patch(
    `resources/${encodeURIComponent(defaultResource.id)}/is-default`,
    {
      isDefault: true,
    },
  );

  return Object.freeze({
    basic,
    post,
    primary,
    defaultResource,
    scopes: Object.freeze({ read, write, unassigned }),
    organization: Object.freeze({
      id: organizationId,
      scopeName: "organization:read",
    }),
  });
};

const sanitizeValue = (
  value,
  sensitiveValues,
  containsCompactJwt,
  seen = new WeakSet(),
) => {
  if (typeof value === "string") {
    const lower = value.toLowerCase();
    if (
      containsCompactJwt(value) ||
      CREDENTIAL_LABEL.test(value) ||
      sensitiveValues.some(
        (sensitive) =>
          sensitive.length > 0 && lower.includes(sensitive.toLowerCase()),
      )
    ) {
      return "<redacted>";
    }
    return value;
  }
  if (Array.isArray(value)) {
    if (seen.has(value)) {
      return fail();
    }
    seen.add(value);
    return value.map((entry) =>
      sanitizeValue(entry, sensitiveValues, containsCompactJwt, seen),
    );
  }
  if (typeof value === "object" && value !== null) {
    if (seen.has(value)) {
      return fail();
    }
    seen.add(value);
    const output = {};
    for (const [key, entry] of Object.entries(value)) {
      if (!FORBIDDEN_FIELD_NAME.test(key)) {
        output[key] = sanitizeValue(
          entry,
          sensitiveValues,
          containsCompactJwt,
          seen,
        );
      }
    }
    return output;
  }
  return value;
};

const collectCases = async ({
  endpoint,
  jwks,
  fixture,
  admin,
  totalSignal,
  observeClientCredentialsToken,
  containsCompactJwt,
}) => {
  const tokenEndpoint = new URL("/oidc/token", endpoint);
  const wrongSecret = "WrongCollectorSecret000000000000";
  const unknownSecret = "UnknownCollectorSecret0000000000";
  const secretValues = [
    fixture.basic.secret,
    fixture.post.secret,
    wrongSecret,
    unknownSecret,
  ];
  const sensitiveValues = [
    ...secretValues,
    ...[fixture.basic, fixture.post].flatMap((client) => {
      const encodedId = new URLSearchParams([["value", client.id]])
        .toString()
        .slice(6);
      const encodedSecret = new URLSearchParams([["value", client.secret]])
        .toString()
        .slice(6);
      return [
        `${client.id}:${client.secret}`,
        Buffer.from(`${encodedId}:${encodedSecret}`, "utf8").toString("base64"),
      ];
    }),
  ];
  const observations = [];
  const observe = async (name, requestValue, rawEntries) => {
    const options = {
      maximumBodyBytes: MAXIMUM_BODY_BYTES,
      maximumHeaderBytes: MAXIMUM_HEADER_BYTES,
      signal: totalSignal,
      ...(rawEntries === undefined
        ? {
            fetch: (input, init = {}) => {
              if (String(input) !== tokenEndpoint.href) {
                return fail();
              }
              return request(tokenEndpoint, init, totalSignal);
            },
          }
        : {
            fetch: (_input, init = {}) =>
              request(
                tokenEndpoint,
                {
                  method: "POST",
                  headers: init.headers,
                  body: new URLSearchParams(rawEntries),
                  signal: init.signal,
                },
                totalSignal,
              ),
          }),
    };
    const observation = await observeClientCredentialsToken(
      tokenEndpoint,
      jwks,
      requestValue,
      options,
    );
    observations.push(
      Object.freeze({
        name,
        observation: sanitizeValue(
          observation,
          sensitiveValues,
          containsCompactJwt,
        ),
      }),
    );
  };
  const basicRequest = (rest = {}) => ({
    method: "client_secret_basic",
    clientId: fixture.basic.id,
    clientSecret: fixture.basic.secret,
    ...rest,
  });
  const postRequest = (rest = {}) => ({
    method: "client_secret_post",
    clientId: fixture.post.id,
    clientSecret: fixture.post.secret,
    ...rest,
  });
  await observe(
    "basic-explicit-resource",
    basicRequest({ resource: fixture.primary.indicator }),
  );
  await observe(
    "post-explicit-resource",
    postRequest({ resource: fixture.primary.indicator }),
  );
  await observe("default-resource", basicRequest());
  await observe(
    "resource-no-scope",
    basicRequest({ resource: fixture.primary.indicator }),
  );
  await observe(
    "resource-partial-scope",
    basicRequest({
      resource: fixture.primary.indicator,
      scope: "read unavailable",
    }),
  );
  await observe(
    "organization-empty-scope",
    basicRequest({ organizationId: fixture.organization.id }),
  );
  await observe(
    "organization-scope",
    basicRequest({
      organizationId: fixture.organization.id,
      scope: "organization:read unavailable",
    }),
  );
  await observe(
    "organization-resource-scope",
    basicRequest({
      resource: fixture.primary.indicator,
      organizationId: fixture.organization.id,
      scope: "read write unassigned",
    }),
  );
  await observe("unknown-client-basic", {
    method: "client_secret_basic",
    clientId: "phase2-unknown-client-basic",
    clientSecret: unknownSecret,
    resource: fixture.primary.indicator,
  });
  await observe("unknown-client-post", {
    method: "client_secret_post",
    clientId: "phase2-unknown-client-post",
    clientSecret: unknownSecret,
    resource: fixture.primary.indicator,
  });
  await observe(
    "wrong-secret-basic",
    basicRequest({
      clientSecret: wrongSecret,
      resource: fixture.primary.indicator,
    }),
  );
  await observe(
    "wrong-secret-post",
    postRequest({
      clientSecret: wrongSecret,
      resource: fixture.primary.indicator,
    }),
  );
  await observe(
    "mixed-authentication",
    basicRequest({ resource: fixture.primary.indicator }),
    [
      ["grant_type", "client_credentials"],
      ["resource", fixture.primary.indicator],
      ["client_id", fixture.post.id],
      ["client_secret", fixture.post.secret],
    ],
  );
  await admin.patch(
    `resources/${encodeURIComponent(fixture.defaultResource.id)}/is-default`,
    {
      isDefault: false,
    },
  );
  await observe("missing-target", basicRequest());
  await observe(
    "unknown-resource",
    basicRequest({ resource: "https://phase2.example.invalid/unknown" }),
  );
  await observe(
    "unassociated-organization",
    postRequest({ organizationId: fixture.organization.id }),
  );
  await observe(
    "duplicate-resource",
    basicRequest({ resource: fixture.primary.indicator }),
    [
      ["grant_type", "client_credentials"],
      ["resource", fixture.primary.indicator],
      ["resource", fixture.defaultResource.indicator],
    ],
  );
  await observe(
    "duplicate-scope-name",
    basicRequest({
      resource: fixture.primary.indicator,
      scope: "read read write",
    }),
  );
  await observe(
    "malformed-scope-whitespace",
    basicRequest({
      resource: fixture.primary.indicator,
      scope: " read  write ",
    }),
  );
  await observe(
    "unsupported-parameter",
    basicRequest({ resource: fixture.primary.indicator }),
    [
      ["grant_type", "client_credentials"],
      ["resource", fixture.primary.indicator],
      ["unsupported_parameter", "rejected"],
    ],
  );

  if (
    observations.length !== CASES.length ||
    observations.some(({ name }, index) => name !== CASES[index])
  ) {
    return fail();
  }
  return Object.freeze({
    observations: Object.freeze(observations),
    sensitiveValues,
  });
};

const assertPacketSafe = (packet, sensitiveValues, containsCompactJwt) => {
  const serialized = JSON.stringify(packet);
  const lower = serialized.toLowerCase();
  if (
    containsCompactJwt(serialized) ||
    CREDENTIAL_LABEL.test(serialized) ||
    lower.includes("authorization") ||
    lower.includes("client_secret") ||
    lower.includes("access_token") ||
    sensitiveValues.some(
      (sensitive) =>
        sensitive.length > 0 && lower.includes(sensitive.toLowerCase()),
    )
  ) {
    return fail();
  }
  return `${serialized}\n`;
};

const publish = async (output, contents) => {
  await validateOutputPath(output);
  let handle;
  let created = false;
  let completed = false;
  try {
    handle = await open(
      output,
      fsConstants.O_WRONLY |
        fsConstants.O_CREAT |
        fsConstants.O_EXCL |
        fsConstants.O_NOFOLLOW,
      0o600,
    );
    created = true;
    const metadata = await handle.stat();
    if (
      !metadata.isFile() ||
      metadata.uid !== process.getuid() ||
      (metadata.mode & 0o777) !== 0o600
    ) {
      return fail();
    }
    await handle.writeFile(contents, { encoding: "utf8" });
    await handle.sync();
    const finalMetadata = await stat(output);
    if (
      !finalMetadata.isFile() ||
      finalMetadata.dev !== metadata.dev ||
      finalMetadata.ino !== metadata.ino ||
      (finalMetadata.mode & 0o777) !== 0o600
    ) {
      return fail();
    }
    completed = true;
  } catch {
    return fail();
  } finally {
    await handle?.close().catch(() => undefined);
    if (created && !completed) {
      await unlink(output).catch(() => undefined);
    }
  }
};

const run = async () => {
  const args = parseArguments(process.argv.slice(2));
  if (
    args.referenceSource !== REFERENCE_SOURCE ||
    args.referenceImage !== REFERENCE_IMAGE
  ) {
    return fail();
  }
  const endpoint = validateLoopbackOrigin(args.endpoint);
  await validateOutputPath(args.output);
  const allocationId = randomBytes(12).toString("hex");
  const clientModule = await import(
    "../../packages/integration-tests/lib/compatibility/phase-2/clients/client-credentials.js"
  );
  if (
    typeof clientModule.observeClientCredentialsToken !== "function" ||
    typeof clientModule.containsCompactJwt !== "function"
  ) {
    return fail();
  }

  const totalSignal = AbortSignal.timeout(TOTAL_TIMEOUT_MILLISECONDS);
  const collectionSignal = AbortSignal.any([
    totalSignal,
    AbortSignal.timeout(COLLECTION_TIMEOUT_MILLISECONDS),
  ]);
  const admin = createAdminClient(endpoint, collectionSignal);
  const cleanup = createCleanup();
  let collection;
  let collectionFailed = false;
  try {
    const jwks = await fetchJwks(endpoint, collectionSignal);
    const fixture = await provision(admin, cleanup, allocationId);
    collection = await collectCases({
      endpoint,
      jwks,
      fixture,
      admin,
      totalSignal: collectionSignal,
      observeClientCredentialsToken: clientModule.observeClientCredentialsToken,
      containsCompactJwt: clientModule.containsCompactJwt,
    });
  } catch {
    collectionFailed = true;
  }
  const cleanupSignal = AbortSignal.any([
    totalSignal,
    AbortSignal.timeout(CLEANUP_TIMEOUT_MILLISECONDS),
  ]);
  const cleanupAdmin = createAdminClient(endpoint, cleanupSignal);
  const cleanupResult = await cleanup.run(cleanupAdmin);
  const reconciliationResult = await reconcileProvisionedEntities(
    cleanupAdmin,
    allocationId,
  );
  if (
    collectionFailed ||
    !cleanupResult.successful ||
    !reconciliationResult.successful ||
    collection === undefined
  ) {
    return fail();
  }
  const packet = Object.freeze({
    schemaVersion: 1,
    reference: Object.freeze({
      sourceCommit: REFERENCE_SOURCE,
      imageDigest: REFERENCE_IMAGE,
    }),
    cases: collection.observations,
    cleanup: Object.freeze({
      status: "complete",
      operations: cleanupResult.operations,
      reconciliation: reconciliationResult.operations,
    }),
  });
  const contents = assertPacketSafe(
    packet,
    collection.sensitiveValues,
    clientModule.containsCompactJwt,
  );
  await publish(args.output, contents);
};

if (
  typeof process.argv[1] === "string" &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  try {
    await run();
    process.stdout.write(SUCCESS_TEXT);
  } catch {
    process.exitCode = 1;
    process.stderr.write(FAILURE_TEXT);
  }
}
