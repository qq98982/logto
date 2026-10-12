const bootstrapEndpoint = process.env.BOX_AI_LOGTO_BOOTSTRAP_ENDPOINT ?? 'http://127.0.0.1:3001';
const managementToken = process.env.BOX_AI_LOGTO_MANAGEMENT_TOKEN;
const market = process.env.BOX_AI_MARKET;
const host = process.env.BOX_AI_SMTP_HOST;
const port = process.env.BOX_AI_SMTP_PORT;
const security = process.env.BOX_AI_SMTP_SECURITY;
const fromName = process.env.BOX_AI_SMTP_FROM_NAME;
const fromEmail = process.env.BOX_AI_SMTP_FROM_EMAIL;
const username = process.env.BOX_AI_SMTP_USERNAME;
const password = process.env.BOX_AI_SMTP_PASSWORD;

// Logto's bundled SMTP connector.
//
// This provisioner stays deliberately vendor-agnostic. Tencent SES and Aliyun
// DirectMail both expose plain SMTP relays, so a deployment moves between them
// by changing BOX_AI_SMTP_HOST and the credentials — no second provisioning
// path, and no connector whose configuration shape only one vendor can read.
// That is the opposite of the SMS story, where Aliyun's signature-and-template
// shape genuinely does not transfer.
const factory = 'simple-mail-transfer-protocol';

// Logto asks an email connector for a code in each of these flows. Registration
// and password recovery are the ones Box AI needs; the rest are wired to the
// same template so enabling them later needs no further work.
const usageTypes = Object.freeze(['Register', 'SignIn', 'ForgotPassword', 'Generic']);

// A market that cannot deliver a verification code cannot register a customer.
// Markets are listed explicitly so an unknown value fails rather than silently
// provisioning against a policy nobody wrote down.
const knownMarkets = Object.freeze(['cn', 'global', 'eu']);

// The connector renders `{{code}}`; nothing else in these strings is a variable.
const copyByMarket = Object.freeze({
  cn: {
    subject: 'Box AI 验证码',
    content: '您的验证码为：{{code}}，10 分钟内有效，请勿泄露于他人。',
  },
  default: {
    subject: 'Your Box AI verification code',
    content:
      'Your Box AI verification code is {{code}}. It expires in 10 minutes. Do not share it with anyone.',
  },
});

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

const isSet = (value) => value !== undefined && value !== '';

// Credentials and display text reach the mail relay verbatim, so reject
// anything that could smuggle a control character or a header break into the
// connector configuration.
const singleLineText = (value, name, maxLength) => {
  if (
    typeof value !== 'string' ||
    value.trim() !== value ||
    value.length === 0 ||
    value.length > maxLength ||
    // eslint-disable-next-line no-control-regex
    /[\0-\x1f\x7f]/u.test(value)
  ) {
    throw new Error(`${name} is invalid`);
  }
  return value;
};

// A loopback relay would have to run inside the Logto container, which no
// deployment does. Accepting one would install a connector that reports success
// and never delivers, which is the failure this provisioner exists to prevent.
const deliverableHost = (value, name) => {
  const text = singleLineText(value, name, 253);
  if (
    !/^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$/u.test(text)
  ) {
    throw new Error(`${name} must be a fully qualified relay hostname`);
  }
  if (['localhost', '127.0.0.1', '::1'].includes(text) || text.endsWith('.localhost')) {
    throw new Error(`${name} must not be a loopback address`);
  }
  return text;
};

const relayPort = (value, name) => {
  if (!/^[1-9][0-9]{0,4}$/u.test(String(value ?? ''))) {
    throw new Error(`${name} is invalid`);
  }
  const parsed = Number(value);
  if (parsed > 65_535) {
    throw new Error(`${name} is invalid`);
  }
  return parsed;
};

// RFC 2606 reserves `.invalid`, so a from address in it is a placeholder that
// no receiver will ever accept a bounce for.
const senderAddress = (value, name) => {
  const text = singleLineText(value, name, 254);
  if (
    !/^[^\s@,<>]+@[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$/u.test(
      text
    )
  ) {
    throw new Error(`${name} must be a single email address`);
  }
  if (/\.(invalid|example|test|localhost)$/u.test(text)) {
    throw new Error(`${name} must not use a reserved placeholder domain`);
  }
  return text;
};

// Logto hands `fromEmail` straight to nodemailer's `from`, which accepts either
// a bare address or `Display Name <address>`.
const buildFrom = (name, address) =>
  isSet(name) ? `${singleLineText(name, 'BOX_AI_SMTP_FROM_NAME', 64)} <${address}>` : address;

// `implicit_tls` opens the TLS session immediately, which is what port 465
// expects. `starttls` upgrades a plaintext session and must require the
// upgrade, or a relay that silently declines it would send credentials in the
// clear. `plaintext` is refused: these messages carry verification codes.
const transportSecurity = (value, name) => {
  switch (value) {
    case 'implicit_tls': {
      return { secure: true };
    }
    case 'starttls': {
      return { secure: false, requireTLS: true };
    }
    case 'plaintext': {
      throw new Error(
        `${name} must not be plaintext for a connector that carries verification codes`
      );
    }
    default: {
      throw new Error(`${name} is invalid`);
    }
  }
};

const sameConfig = (current, desired) => {
  if (!current || typeof current !== 'object') {
    return false;
  }
  if (
    current.host !== desired.host ||
    current.port !== desired.port ||
    current.secure !== desired.secure ||
    current.requireTLS !== desired.requireTLS ||
    current.fromEmail !== desired.fromEmail ||
    current.auth?.user !== desired.auth.user ||
    current.auth?.pass !== desired.auth.pass
  ) {
    return false;
  }
  const templates = current.templates;
  return (
    Array.isArray(templates) &&
    templates.length === desired.templates.length &&
    desired.templates.every(
      (template, index) =>
        templates[index]?.usageType === template.usageType &&
        templates[index]?.subject === template.subject &&
        templates[index]?.content === template.content &&
        templates[index]?.contentType === template.contentType
    )
  );
};

const provision = async () => {
  if (!market || !knownMarkets.includes(market)) {
    throw new Error('BOX_AI_MARKET is invalid for email connector provisioning');
  }

  // Credentials are the opt-in. The rest of BOX_AI_SMTP_* is required by
  // Compose and therefore always present, so it cannot signal intent. A relay
  // that authorises by source address instead of credentials would need its own
  // opt-in rather than being inferred from an empty password.
  const credentials = [username, password].filter((value) => isSet(value));
  if (credentials.length === 1) {
    throw new Error('email connector provisioning configuration is incomplete');
  }

  if (credentials.length === 0) {
    // A market delivering codes over SMS wants no email connector. A market
    // with neither channel cannot register anyone, so it fails here rather
    // than at a customer's first sign-up attempt.
    const smsConfigured = [
      process.env.BOX_AI_SMS_ACCESS_KEY_ID,
      process.env.BOX_AI_SMS_ACCESS_KEY_SECRET,
      process.env.BOX_AI_SMS_SIGN_NAME_BASE64,
      process.env.BOX_AI_SMS_TEMPLATE_CODE,
    ].every((value) => isSet(value));
    if (!smsConfigured) {
      throw new Error(`the ${market} market has no verification channel configured`);
    }
    process.stdout.write('Email connector provisioning skipped\n');
    return;
  }

  const copy = copyByMarket[market] ?? copyByMarket.default;
  const desiredConfig = {
    host: deliverableHost(host, 'BOX_AI_SMTP_HOST'),
    port: relayPort(port, 'BOX_AI_SMTP_PORT'),
    ...transportSecurity(security, 'BOX_AI_SMTP_SECURITY'),
    auth: {
      user: singleLineText(username, 'BOX_AI_SMTP_USERNAME', 254),
      pass: singleLineText(password, 'BOX_AI_SMTP_PASSWORD', 254),
    },
    fromEmail: buildFrom(fromName, senderAddress(fromEmail, 'BOX_AI_SMTP_FROM_EMAIL')),
    templates: usageTypes.map((usageType) => ({
      usageType,
      contentType: 'text/plain',
      subject: copy.subject,
      content: copy.content,
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
    throw new Error('multiple managed email connectors exist');
  }

  const existing = managed[0];
  if (!existing) {
    // Logto permits a single email connector, so a foreign one must be removed
    // by an operator rather than silently replaced here.
    const conflicting = connectors.find(
      (connector) => connector?.type === 'Email' && connector.connectorId !== factory
    );
    if (conflicting) {
      throw new Error('a different email connector is already installed');
    }
    await requestJson(endpoint, '/api/connectors', {
      method: 'POST',
      body: JSON.stringify({ connectorId: factory, config: desiredConfig }),
    });
    process.stdout.write('Email connector provisioned\n');
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
  process.stdout.write('Email connector provisioned\n');
};

await provision();
