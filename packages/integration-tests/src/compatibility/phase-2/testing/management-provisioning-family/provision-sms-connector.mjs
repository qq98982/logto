const bootstrapEndpoint = process.env.BOX_AI_LOGTO_BOOTSTRAP_ENDPOINT ?? 'http://127.0.0.1:3001';
const managementToken = process.env.BOX_AI_LOGTO_MANAGEMENT_TOKEN;
const market = process.env.BOX_AI_MARKET;
const accessKeyId = process.env.BOX_AI_SMS_ACCESS_KEY_ID;
const accessKeySecret = process.env.BOX_AI_SMS_ACCESS_KEY_SECRET;
// Mainland China signatures are Chinese text, which the runtime env renderer
// refuses to carry verbatim, so the deployment ships it base64-encoded.
const signNameBase64 = process.env.BOX_AI_SMS_SIGN_NAME_BASE64;
const templateCode = process.env.BOX_AI_SMS_TEMPLATE_CODE;
const factoryOverride = process.env.BOX_AI_SMS_CONNECTOR_FACTORY_ID;

// Mainland China always sends through Aliyun, so cn defaults. Markets outside
// mainland China deploy independently and may keep Aliyun or move to a local
// vendor, so they name the factory instead of inheriting a guess.
const defaultFactoryByMarket = Object.freeze({
  cn: 'aliyun-short-message-service',
  global: undefined,
  eu: undefined,
});

// Every factory listed here accepts Aliyun's accessKey/signName/template
// configuration shape, which is the only shape this provisioner builds. A
// vendor with a different shape, such as Twilio's account SID and messaging
// service, needs its own provisioning path; sending it this configuration would
// install a connector that cannot deliver.
const aliyunShapedFactories = Object.freeze(['aliyun-short-message-service']);

// Logto asks a connector for a code in each of these flows. Registration and
// password recovery are the flows Box-AI needs; the rest are wired to the same
// template so an operator never has to file a second Aliyun review to enable
// them.
const usageTypes = Object.freeze(['Register', 'SignIn', 'ForgotPassword', 'Generic']);

const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

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

// Credentials and the signature reach Aliyun verbatim, so reject anything that
// could smuggle a control character into the connector configuration.
const opaqueSecret = (value, name) => {
  if (typeof value !== 'string' || !/^[0-9A-Za-z]{16,64}$/u.test(value)) {
    throw new Error(`${name} is invalid`);
  }
  return value;
};

const displayText = (value, name) => {
  if (
    typeof value !== 'string' ||
    value.trim() !== value ||
    value.length === 0 ||
    value.length > 60 ||
    // eslint-disable-next-line no-control-regex
    /[\0-\x1f\x7f]/u.test(value)
  ) {
    throw new Error(`${name} is invalid`);
  }
  return value;
};

const decodeSignName = (value, name) => {
  if (typeof value !== 'string' || value.length > 200 || !/^[A-Za-z0-9+/]+={0,2}$/u.test(value)) {
    throw new Error(`${name} is invalid`);
  }
  const decoded = Buffer.from(value, 'base64');
  if (decoded.toString('base64') !== value) {
    throw new Error(`${name} is not canonical base64`);
  }
  const text = decoded.toString('utf8');
  if (text.includes('�')) {
    throw new Error(`${name} is not valid UTF-8`);
  }
  return text;
};

const aliyunTemplateCode = (value, name) => {
  if (typeof value !== 'string' || !/^SMS_\d{6,20}$/u.test(value)) {
    throw new Error(`${name} is invalid`);
  }
  return value;
};

const connectorFactoryId = (value, name) => {
  if (typeof value !== 'string' || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(value) || value.length > 80) {
    throw new Error(`${name} is invalid`);
  }
  return value;
};

const sameConfig = (current, desired) => {
  if (!current || typeof current !== 'object') {
    return false;
  }
  if (
    current.accessKeyId !== desired.accessKeyId ||
    current.accessKeySecret !== desired.accessKeySecret ||
    current.signName !== desired.signName
  ) {
    return false;
  }
  const templates = current.templates;
  return (
    Array.isArray(templates) &&
    templates.length === desired.templates.length &&
    desired.templates.every((template, index) =>
      templates[index]?.templateCode === template.templateCode &&
      templates[index]?.usageType === template.usageType
    )
  );
};

const provision = async () => {
  const configured = [accessKeyId, accessKeySecret, signNameBase64, templateCode].filter(
    (value) => value !== undefined && value !== ''
  );
  if (configured.length === 0) {
    // A market without SMS credentials keeps email-only verification. This is a
    // supported deployment, not a failure.
    process.stdout.write('SMS connector provisioning skipped\n');
    return;
  }
  if (configured.length !== 4) {
    throw new Error('SMS connector provisioning configuration is incomplete');
  }
  if (!market || !Object.hasOwn(defaultFactoryByMarket, market)) {
    throw new Error('BOX_AI_MARKET is invalid for SMS connector provisioning');
  }
  const factory = factoryOverride
    ? connectorFactoryId(factoryOverride, 'BOX_AI_SMS_CONNECTOR_FACTORY_ID')
    : defaultFactoryByMarket[market];
  if (!factory) {
    throw new Error(`BOX_AI_SMS_CONNECTOR_FACTORY_ID is required for the ${market} market`);
  }
  if (!aliyunShapedFactories.includes(factory)) {
    throw new Error(
      `${factory} does not take Aliyun connector configuration and needs its own provisioning`
    );
  }

  const desiredConfig = {
    accessKeyId: opaqueSecret(accessKeyId, 'BOX_AI_SMS_ACCESS_KEY_ID'),
    accessKeySecret: opaqueSecret(accessKeySecret, 'BOX_AI_SMS_ACCESS_KEY_SECRET'),
    signName: displayText(
      decodeSignName(signNameBase64, 'BOX_AI_SMS_SIGN_NAME_BASE64'),
      'BOX_AI_SMS_SIGN_NAME_BASE64'
    ),
    templates: usageTypes.map((usageType) => ({
      templateCode: aliyunTemplateCode(templateCode, 'BOX_AI_SMS_TEMPLATE_CODE'),
      usageType,
    })),
  };

  const endpoint = validateLocalBootstrapEndpoint(bootstrapEndpoint);
  await waitForLogto(endpoint);

  const connectors = await requestJson(endpoint, '/api/connectors');
  if (!Array.isArray(connectors)) {
    throw new Error('Logto returned an invalid connector list');
  }
  const managed = connectors.filter((connector) => connector?.connectorId === factory);
  if (managed.length > 1) {
    throw new Error('multiple managed SMS connectors exist');
  }

  const existing = managed[0];
  if (!existing) {
    // Logto permits a single SMS connector, so a foreign one must be removed by
    // an operator rather than silently replaced here.
    const conflicting = connectors.find(
      (connector) => connector?.type === 'Sms' && connector.connectorId !== factory
    );
    if (conflicting) {
      throw new Error('a different SMS connector is already installed');
    }
    await requestJson(endpoint, '/api/connectors', {
      method: 'POST',
      body: JSON.stringify({ connectorId: factory, config: desiredConfig }),
    });
    process.stdout.write('SMS connector provisioned\n');
    return;
  }

  if (typeof existing.id !== 'string' || existing.id.length === 0) {
    throw new Error('Logto returned an invalid connector ID');
  }
  if (!sameConfig(existing.config, desiredConfig)) {
    await requestJson(endpoint, `/api/connectors/${encodeURIComponent(existing.id)}`, {
      method: 'PATCH',
      body: JSON.stringify({ config: desiredConfig }),
    });
  }
  process.stdout.write('SMS connector provisioned\n');
};

await provision();
