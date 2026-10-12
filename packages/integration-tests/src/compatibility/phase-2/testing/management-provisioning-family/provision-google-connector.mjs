const bootstrapEndpoint = process.env.BOX_AI_LOGTO_BOOTSTRAP_ENDPOINT ?? 'http://127.0.0.1:3001';
const managementToken = process.env.BOX_AI_LOGTO_MANAGEMENT_TOKEN;
const identityBaseUrl = process.env.BOX_AI_LOGTO_ENDPOINT;
const clientId = process.env.BOX_AI_GOOGLE_CLIENT_ID;
const clientSecret = process.env.BOX_AI_GOOGLE_CLIENT_SECRET;

// Logto's bundled Google connector. Leaving `scope` unset in the connector
// config keeps Logto's default `openid profile email`, which is what account
// linking by verified email depends on.
const factory = 'google-universal';

const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

const isSet = (value) => value !== undefined && value !== '';

const validateLocalBootstrapEndpoint = (value) => {
  const url = new URL(value);
  if (
    url.protocol !== 'http:' ||
    !['127.0.0.1', '::1', 'localhost'].includes(url.hostname) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    throw new Error('Logto bootstrap endpoint must be loopback-only');
  }
  return url;
};

const parsePublicOrigin = (value, name) => {
  const url = new URL(value);
  const loopbackHttp =
    url.protocol === 'http:' &&
    (['127.0.0.1', '::1', 'localhost'].includes(url.hostname) ||
      url.hostname.endsWith('.localhost'));
  if (
    (url.protocol !== 'https:' && !loopbackHttp) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== '/'
  ) {
    throw new Error(`${name} is invalid for Logto client provisioning`);
  }
  return url;
};

const requestJson = async (endpoint, path, options = {}) => {
  if (
    typeof managementToken !== 'string' ||
    managementToken.length === 0 ||
    managementToken.length > 4096 ||
    /[\0\r\n]/u.test(managementToken)
  ) {
    throw new Error('BOX_AI_LOGTO_MANAGEMENT_TOKEN is invalid');
  }
  const response = await fetch(new URL(path, endpoint), {
    ...options,
    headers: {
      accept: 'application/json',
      'content-type': 'application/json',
      authorization: `Bearer ${managementToken}`,
      ...options.headers,
    },
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) {
    throw new Error(`Logto Management API request failed with status ${response.status}`);
  }
  return response.json();
};

const waitForLogto = async (endpoint) => {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    try {
      const response = await fetch(new URL('/oidc/.well-known/openid-configuration', endpoint), {
        signal: AbortSignal.timeout(3_000),
      });
      if (response.ok) {
        return;
      }
    } catch {
      // The temporary server is still starting.
    }
    await delay(1_000);
  }
  throw new Error('temporary Logto server did not become ready');
};

// Google's client IDs are project-numbered and always end in this suffix;
// rejecting anything else catches a pasted client secret or project ID before
// it reaches the connector configuration.
const googleClientId = (value, name) => {
  if (typeof value !== 'string' || !/^[0-9]+-[0-9a-z]+\.apps\.googleusercontent\.com$/u.test(value)) {
    throw new Error(`${name} is invalid`);
  }
  return value;
};

// The client secret reaches Google verbatim, so reject anything that could
// smuggle a control character or a line break into the connector
// configuration. Google has used more than one opaque format over the years,
// so this only bounds shape, not a specific prefix.
const googleClientSecret = (value, name) => {
  if (typeof value !== 'string' || !/^[!-~]{8,100}$/u.test(value)) {
    throw new Error(`${name} is invalid`);
  }
  return value;
};

const sameConfig = (current, desired) =>
  Boolean(current) &&
  typeof current === 'object' &&
  current.clientId === desired.clientId &&
  current.clientSecret === desired.clientSecret;

const provision = async () => {
  const configured = [clientId, clientSecret].filter((value) => isSet(value));
  if (configured.length === 0) {
    // A deployment with no Google OAuth client keeps whatever other sign-in
    // methods it has configured. This is a supported deployment, not a failure.
    process.stdout.write('Google connector provisioning skipped\n');
    return;
  }
  if (configured.length !== 2) {
    throw new Error('Google connector provisioning configuration is incomplete');
  }
  if (!identityBaseUrl) {
    throw new Error('BOX_AI_LOGTO_ENDPOINT is required for Google connector provisioning');
  }

  const desiredConfig = {
    clientId: googleClientId(clientId, 'BOX_AI_GOOGLE_CLIENT_ID'),
    clientSecret: googleClientSecret(clientSecret, 'BOX_AI_GOOGLE_CLIENT_SECRET'),
  };
  const identityBase = parsePublicOrigin(identityBaseUrl, 'BOX_AI_LOGTO_ENDPOINT');

  const endpoint = validateLocalBootstrapEndpoint(bootstrapEndpoint);
  await waitForLogto(endpoint);

  const connectors = await requestJson(endpoint, '/api/connectors');
  if (!Array.isArray(connectors)) {
    throw new Error('Logto returned an invalid connector list');
  }
  const managed = connectors.filter((connector) => connector?.connectorId === factory);
  if (managed.length > 1) {
    throw new Error('multiple managed Google connectors exist');
  }

  let connectorId;
  const existing = managed[0];
  if (!existing) {
    const created = await requestJson(endpoint, '/api/connectors', {
      method: 'POST',
      body: JSON.stringify({ connectorId: factory, config: desiredConfig }),
    });
    if (typeof created?.id !== 'string' || created.id.length === 0) {
      throw new Error('Logto returned an invalid connector ID');
    }
    connectorId = created.id;
  } else {
    if (typeof existing.id !== 'string' || existing.id.length === 0) {
      throw new Error('Logto returned an invalid connector ID');
    }
    if (!sameConfig(existing.config, desiredConfig)) {
      await requestJson(endpoint, `/api/connectors/${encodeURIComponent(existing.id)}`, {
        method: 'PATCH',
        body: JSON.stringify({ config: desiredConfig }),
      });
    }
    connectorId = existing.id;
  }

  const callbackUrl = new URL(`/callback/${connectorId}`, identityBase).href;
  process.stdout.write(`Google connector provisioned; authorized redirect URI: ${callbackUrl}\n`);
};

await provision();
