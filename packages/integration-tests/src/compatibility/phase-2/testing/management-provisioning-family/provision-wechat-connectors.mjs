import { createHash, randomUUID } from 'node:crypto';
import { chmod, mkdir, open, rename, rm } from 'node:fs/promises';
import { join } from 'node:path';

const bootstrapEndpoint = process.env.BOX_AI_LOGTO_BOOTSTRAP_ENDPOINT ?? 'http://127.0.0.1:3001';
const managementToken = process.env.BOX_AI_LOGTO_MANAGEMENT_TOKEN;
const credentialDirectory = process.env.BOX_AI_LOGTO_CREDENTIAL_DIR;
const market = process.env.BOX_AI_MARKET;
const channelValue = process.env.BOX_AI_WECHAT_CHANNELS ?? '';

const channelOrder = Object.freeze(['web', 'h5', 'mini', 'native']);
const channelDefinitions = Object.freeze({
  web: {
    connectorId: 'wechat-web',
    platform: 'Web',
    values: {
      appId: process.env.BOX_AI_WECHAT_WEB_APP_ID,
      appSecret: process.env.BOX_AI_WECHAT_WEB_APP_SECRET,
    },
  },
  h5: {
    connectorId: 'wechat-h5',
    platform: 'Universal',
    values: {
      appId: process.env.BOX_AI_WECHAT_H5_APP_ID,
      appSecret: process.env.BOX_AI_WECHAT_H5_APP_SECRET,
    },
  },
  mini: {
    connectorId: 'wechat-mini',
    platform: null,
    values: {
      appId: process.env.BOX_AI_WECHAT_MINI_APP_ID,
      appSecret: process.env.BOX_AI_WECHAT_MINI_APP_SECRET,
    },
  },
  native: {
    connectorId: 'wechat-native',
    platform: 'Native',
    values: {
      appId: process.env.BOX_AI_WECHAT_NATIVE_APP_ID,
      appSecret: process.env.BOX_AI_WECHAT_NATIVE_APP_SECRET,
      universalLinks: process.env.BOX_AI_WECHAT_NATIVE_UNIVERSAL_LINKS,
    },
  },
});

const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
const isSet = (value) => value !== undefined && value !== '';
const maximumManagementResponseBytes = 65_536;

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

const invalidManagementResponse = (path, status) =>
  new Error(`Logto Management API response for ${path} with status ${status} is invalid`);

const readBoundedJson = async (response, path) => {
  const declaredLength = response.headers.get('content-length');
  if (
    declaredLength !== null &&
    (!/^[0-9]+$/u.test(declaredLength) || Number(declaredLength) > maximumManagementResponseBytes)
  ) {
    throw invalidManagementResponse(path, response.status);
  }
  if (!response.body) {
    throw invalidManagementResponse(path, response.status);
  }

  const reader = response.body.getReader();
  const chunks = [];
  let receivedBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      receivedBytes += value.byteLength;
      if (receivedBytes > maximumManagementResponseBytes) {
        await reader.cancel().catch(() => {});
        throw invalidManagementResponse(path, response.status);
      }
      chunks.push(Buffer.from(value));
    }
    const text = new TextDecoder('utf-8', { fatal: true }).decode(
      Buffer.concat(chunks, receivedBytes)
    );
    return JSON.parse(text);
  } catch {
    throw invalidManagementResponse(path, response.status);
  }
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
  const requestUrl = new URL(path, endpoint);
  const response = await fetch(requestUrl, {
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
  return readBoundedJson(response, requestUrl.pathname);
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

const parseChannels = (value) => {
  if (value === '') {
    return [];
  }
  const channels = value.split(',');
  const enabled = new Set(channels);
  const canonical = channelOrder.filter((channel) => enabled.has(channel));
  if (enabled.size !== channels.length || canonical.join(',') !== value) {
    throw new Error(
      'BOX_AI_WECHAT_CHANNELS must be a canonical sorted subset of web,h5,mini,native'
    );
  }
  return channels;
};

const appId = (value, name) => {
  if (typeof value !== 'string' || !/^wx[0-9a-f]{16}$/u.test(value)) {
    throw new Error(`${name} is invalid`);
  }
  return value;
};

const appSecret = (value, name) => {
  if (typeof value !== 'string' || !/^[0-9A-Za-z]{16,128}$/u.test(value)) {
    throw new Error(`${name} is invalid`);
  }
  return value;
};

const universalLinks = (value, name) => {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} is invalid`);
  }
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    !url.pathname.endsWith('/')
  ) {
    throw new Error(`${name} is invalid`);
  }
  return url.href;
};

const connectorInstanceId = (value) => {
  if (typeof value !== 'string' || !/^[0-9A-Za-z._~-]{1,256}$/u.test(value)) {
    throw new Error('Logto returned an invalid connector ID');
  }
  return value;
};

const connectorFactoryId = (value) =>
  typeof value === 'string' &&
  value.length <= 128 &&
  /^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(value);

const isRecord = (value) =>
  Boolean(value) && typeof value === 'object' && !Array.isArray(value);

const validConnector = (connector) =>
  isRecord(connector) &&
  connectorInstanceId(connector.id) &&
  connectorFactoryId(connector.connectorId) &&
  isRecord(connector.config) &&
  (connector.target === undefined || typeof connector.target === 'string') &&
  (connector.platform === undefined ||
    connector.platform === null ||
    ['Web', 'Native', 'Universal'].includes(connector.platform));

const sameConfig = (current, desired) => {
  if (!current || typeof current !== 'object' || Array.isArray(current)) {
    return false;
  }
  const currentKeys = Object.keys(current).sort();
  const desiredKeys = Object.keys(desired).sort();
  return (
    currentKeys.length === desiredKeys.length &&
    currentKeys.every((key, index) => key === desiredKeys[index] && current[key] === desired[key])
  );
};

const validMetadataValue = (connector, name, expected) =>
  !Object.hasOwn(connector, name) || connector[name] === expected;

const writeMetadata = async (directory, name, value) => {
  const destination = join(directory, name);
  const temporary = join(directory, `.${name}.${randomUUID()}.tmp`);
  try {
    const handle = await open(temporary, 'wx', 0o600);
    try {
      await handle.writeFile(`${value}\n`, 'utf8');
      await handle.sync();
    } finally {
      await handle.close();
    }
    await chmod(temporary, 0o444);
    await rename(temporary, destination);
  } finally {
    await rm(temporary, { force: true });
  }
};

const validatedConfigs = (channels) => {
  const enabled = new Set(channels);
  const desired = new Map();
  for (const channel of channelOrder) {
    const definition = channelDefinitions[channel];
    const values = Object.values(definition.values);
    const configuredCount = values.filter(isSet).length;
    if (configuredCount !== 0 && configuredCount !== values.length) {
      throw new Error(`WeChat ${channel} credential group is incomplete`);
    }
    if (configuredCount === values.length && !enabled.has(channel)) {
      throw new Error(`WeChat ${channel} credentials are configured for a disabled channel`);
    }
    if (!enabled.has(channel)) {
      continue;
    }
    if (configuredCount !== values.length) {
      throw new Error(`WeChat ${channel} credential group is incomplete`);
    }

    const config = {
      appId: appId(definition.values.appId, `BOX_AI_WECHAT_${channel.toUpperCase()}_APP_ID`),
      appSecret: appSecret(
        definition.values.appSecret,
        `BOX_AI_WECHAT_${channel.toUpperCase()}_APP_SECRET`
      ),
    };
    if (channel === 'native') {
      config.universalLinks = universalLinks(
        definition.values.universalLinks,
        'BOX_AI_WECHAT_NATIVE_UNIVERSAL_LINKS'
      );
    }
    desired.set(channel, config);
  }
  return desired;
};

const writeRuntimeMetadata = async (channels, connectorIds, desired) => {
  await mkdir(credentialDirectory, { recursive: true, mode: 0o755 });
  await chmod(credentialDirectory, 0o755);
  for (const channel of channelOrder) {
    const name = `wechat-${channel}-connector-id`;
    if (channels.includes(channel)) {
      await writeMetadata(credentialDirectory, name, connectorIds.get(channel));
    } else {
      await rm(join(credentialDirectory, name), { force: true });
    }
  }
  for (const channel of ['h5', 'mini']) {
    const name = `wechat-${channel}-app-id-digest`;
    if (channels.includes(channel)) {
      const digest = createHash('sha256').update(desired.get(channel).appId, 'utf8').digest('hex');
      await writeMetadata(credentialDirectory, name, digest);
    } else {
      await rm(join(credentialDirectory, name), { force: true });
    }
  }
  await writeMetadata(credentialDirectory, 'wechat-enabled-channels', channels.join(','));
};

const provision = async () => {
  if (!credentialDirectory || !market) {
    throw new Error('WeChat connector provisioning configuration is incomplete');
  }
  const channels = parseChannels(channelValue);
  const anyWechatInput =
    isSet(channelValue) ||
    Object.values(channelDefinitions).some((definition) =>
      Object.values(definition.values).some(isSet)
    );
  if (market !== 'cn' && anyWechatInput) {
    throw new Error('WeChat connector configuration is allowed only for BOX_AI_MARKET=cn');
  }
  const desired = validatedConfigs(channels);

  if (channels.length === 0) {
    await writeRuntimeMetadata(channels, new Map(), desired);
    process.stdout.write('WeChat connector provisioning disabled\n');
    return;
  }

  const endpoint = validateLocalBootstrapEndpoint(bootstrapEndpoint);
  await waitForLogto(endpoint);
  const connectors = await requestJson(endpoint, '/api/connectors?target=wechat');
  if (!Array.isArray(connectors) || !connectors.every(validConnector)) {
    throw new Error('Logto returned an invalid connector list');
  }

  const managedByChannel = new Map();
  for (const channel of channels) {
    const definition = channelDefinitions[channel];
    const managed = connectors.filter(
      (connector) => connector?.connectorId === definition.connectorId
    );
    if (managed.length > 1) {
      throw new Error(`multiple managed WeChat ${channel} connectors exist`);
    }
    const conflict = connectors.find(
      (connector) =>
        connector?.connectorId !== definition.connectorId &&
        connector?.target === 'wechat' &&
        Object.hasOwn(connector, 'platform') &&
        connector.platform === definition.platform &&
        !(
          definition.platform === null &&
          ['wechat-h5', 'wechat-mini'].includes(connector?.connectorId)
        )
    );
    if (conflict) {
      throw new Error(`a foreign connector conflicts with the WeChat ${channel} channel`);
    }
    const existing = managed[0];
    if (existing) {
      connectorInstanceId(existing.id);
      if (
        !validMetadataValue(existing, 'target', 'wechat') ||
        !validMetadataValue(existing, 'platform', definition.platform)
      ) {
        throw new Error(`managed WeChat ${channel} connector metadata is invalid`);
      }
    }
    managedByChannel.set(channel, existing);
  }

  const connectorIds = new Map();
  for (const channel of channels) {
    const definition = channelDefinitions[channel];
    let connector = managedByChannel.get(channel);
    if (!connector) {
      connector = await requestJson(endpoint, '/api/connectors', {
        method: 'POST',
        body: JSON.stringify({ connectorId: definition.connectorId, config: desired.get(channel) }),
      });
    } else {
      if (!sameConfig(connector.config, desired.get(channel))) {
        connector = await requestJson(
          endpoint,
          `/api/connectors/${encodeURIComponent(connector.id)}`,
          {
            method: 'PATCH',
            body: JSON.stringify({ config: desired.get(channel) }),
          }
        );
      }
    }
    if (
      !validConnector(connector) ||
      connector.connectorId !== definition.connectorId ||
      connector.target !== 'wechat' ||
      connector.platform !== definition.platform ||
      !sameConfig(connector.config, desired.get(channel))
    ) {
      throw new Error(`Logto returned an invalid WeChat ${channel} connector`);
    }
    connectorIds.set(channel, connector.id);
  }

  await writeRuntimeMetadata(channels, connectorIds, desired);
  const nativeGuidance = channels.includes('native')
    ? `; native callback: ${new URL('logto-callback', desired.get('native').universalLinks).href}`
    : '';
  process.stdout.write(
    `WeChat connectors provisioned for channels: ${channels.join(',')}${nativeGuidance}\n`
  );
};

await provision();
