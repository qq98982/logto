import { randomUUID } from 'node:crypto';
import { chmod, mkdir, open, readFile, rename, rm } from 'node:fs/promises';
import { join } from 'node:path';

const applicationName = 'Box-AI';
const applicationDescription = 'Managed by the Box-AI deployment';
const nativeApplicationName = 'Box-AI Native';
const nativeApplicationDescription = 'Managed by the Box-AI deployment as a native public client';
const nativeResourceName = 'Box-AI Native Session API';
const nativeResourceScopeName = 'session:exchange';
const nativeResourceScopeDescription =
  'Managed by the Box-AI deployment for native session exchange';
const nativeResourceAccessTokenTtl = 300;
const nativeSessionRoleName = 'Box-AI Native Session User';
const nativeSessionRoleDescription = nativeResourceScopeDescription;
const bootstrapEndpoint = process.env.BOX_AI_LOGTO_BOOTSTRAP_ENDPOINT ?? 'http://127.0.0.1:3001';
const managementToken = process.env.BOX_AI_LOGTO_MANAGEMENT_TOKEN;
const credentialDirectory = process.env.BOX_AI_LOGTO_CREDENTIAL_DIR;
const identityBaseUrl = process.env.BOX_AI_LOGTO_ENDPOINT;
const market = process.env.BOX_AI_MARKET;
const publicBaseUrl = process.env.BOX_AI_PUBLIC_BASE_URL;
const googleClientId = process.env.BOX_AI_GOOGLE_CLIENT_ID;
const googleClientSecret = process.env.BOX_AI_GOOGLE_CLIENT_SECRET;
const wechatChannelValue = process.env.BOX_AI_WECHAT_CHANNELS ?? '';

const wechatChannelOrder = Object.freeze(['web', 'h5', 'mini', 'native']);
const wechatCredentialGroups = Object.freeze({
  web: {
    appId: process.env.BOX_AI_WECHAT_WEB_APP_ID,
    appSecret: process.env.BOX_AI_WECHAT_WEB_APP_SECRET,
  },
  h5: {
    appId: process.env.BOX_AI_WECHAT_H5_APP_ID,
    appSecret: process.env.BOX_AI_WECHAT_H5_APP_SECRET,
  },
  mini: {
    appId: process.env.BOX_AI_WECHAT_MINI_APP_ID,
    appSecret: process.env.BOX_AI_WECHAT_MINI_APP_SECRET,
  },
  native: {
    appId: process.env.BOX_AI_WECHAT_NATIVE_APP_ID,
    appSecret: process.env.BOX_AI_WECHAT_NATIVE_APP_SECRET,
    universalLinks: process.env.BOX_AI_WECHAT_NATIVE_UNIVERSAL_LINKS,
  },
});

const fallbackLanguageByMarket = Object.freeze({
  cn: 'zh-CN',
  global: 'en',
  eu: 'en',
});

const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
const maximumManagementResponseBytes = 65_536;

const isSet = (value) => value !== undefined && value !== '';

const parseWechatChannels = (value) => {
  if (value === '') {
    return [];
  }
  const channels = value.split(',');
  const enabled = new Set(channels);
  const canonical = wechatChannelOrder.filter((channel) => enabled.has(channel));
  if (enabled.size !== channels.length || canonical.join(',') !== value) {
    throw new Error(
      'BOX_AI_WECHAT_CHANNELS must be a canonical sorted subset of web,h5,mini,native'
    );
  }
  return channels;
};

const validateWechatAppId = (value, name) => {
  if (typeof value !== 'string' || !/^wx[0-9a-f]{16}$/u.test(value)) {
    throw new Error(`${name} is invalid`);
  }
};

const validateWechatAppSecret = (value, name) => {
  if (typeof value !== 'string' || !/^[0-9A-Za-z]{16,128}$/u.test(value)) {
    throw new Error(`${name} is invalid`);
  }
};

const parseNativeUniversalLinks = (value) => {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error('BOX_AI_WECHAT_NATIVE_UNIVERSAL_LINKS is invalid');
  }
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    !url.pathname.endsWith('/')
  ) {
    throw new Error('BOX_AI_WECHAT_NATIVE_UNIVERSAL_LINKS is invalid');
  }
  return url;
};

const validateWechatConfiguration = async () => {
  const channels = parseWechatChannels(wechatChannelValue);
  const enabled = new Set(channels);
  const anyWechatInput =
    isSet(wechatChannelValue) ||
    Object.values(wechatCredentialGroups).some((group) => Object.values(group).some(isSet));
  if (market !== 'cn' && anyWechatInput) {
    throw new Error('WeChat configuration is allowed only for BOX_AI_MARKET=cn');
  }

  let nativeLinks;
  for (const channel of wechatChannelOrder) {
    const group = wechatCredentialGroups[channel];
    const values = Object.values(group);
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
    validateWechatAppId(group.appId, `BOX_AI_WECHAT_${channel.toUpperCase()}_APP_ID`);
    validateWechatAppSecret(
      group.appSecret,
      `BOX_AI_WECHAT_${channel.toUpperCase()}_APP_SECRET`
    );
    if (channel === 'native') {
      nativeLinks = parseNativeUniversalLinks(group.universalLinks);
    }
  }

  if (channels.length > 0) {
    let completedChannels;
    try {
      completedChannels = await readFile(join(credentialDirectory, 'wechat-enabled-channels'), 'utf8');
    } catch {
      throw new Error('WeChat connector provisioning metadata is unavailable');
    }
    if (completedChannels !== `${wechatChannelValue}\n`) {
      throw new Error('WeChat connector provisioning metadata does not match the configured channels');
    }
  }
  return { channels, nativeLinks };
};

const parsePublicOrigin = (value, name) => {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} is invalid for Logto client provisioning`);
  }
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
  if (!validCredential(managementToken)) {
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

const sameStrings = (left, right) =>
  Array.isArray(left) && left.length === right.length && left.every((value, index) => value === right[index]);

const hasDesiredMetadata = (application, desired) => {
  const current = application.oidcClientMetadata;
  return (
    current &&
    sameStrings(current.redirectUris, desired.redirectUris) &&
    sameStrings(current.postLogoutRedirectUris, desired.postLogoutRedirectUris) &&
    current.backchannelLogoutUri === desired.backchannelLogoutUri &&
    current.backchannelLogoutSessionRequired === desired.backchannelLogoutSessionRequired
  );
};

const hasDesiredNativeMetadata = (application, desired) =>
  sameStrings(application?.oidcClientMetadata?.redirectUris, desired.redirectUris) &&
  sameStrings(
    application?.oidcClientMetadata?.postLogoutRedirectUris,
    desired.postLogoutRedirectUris
  );

const sameSignInMethod = (left, right) =>
  left?.identifier === right.identifier &&
  left.password === right.password &&
  left.verificationCode === right.verificationCode &&
  left.isPasswordPrimary === right.isPasswordPrimary;

const sameSignInMethods = (left, right) =>
  Array.isArray(left) &&
  left.length === right.length &&
  left.every((method, index) => sameSignInMethod(method, right[index]));

const boxAiDefaultPhoneCountryKey = 'boxAiDefaultPhoneCountry';

const validCustomContent = (value) =>
  value === undefined ||
  (isRecord(value) &&
    Object.values(value).every((content) => typeof content === 'string'));

const sameCustomContent = (left, right) => {
  if (!validCustomContent(left) || !validCustomContent(right)) {
    return false;
  }
  const leftEntries = Object.entries(left ?? {}).sort(([leftKey], [rightKey]) =>
    leftKey.localeCompare(rightKey)
  );
  const rightEntries = Object.entries(right ?? {}).sort(([leftKey], [rightKey]) =>
    leftKey.localeCompare(rightKey)
  );
  return (
    leftEntries.length === rightEntries.length &&
    leftEntries.every(
      ([key, content], index) =>
        key === rightEntries[index]?.[0] && content === rightEntries[index]?.[1]
    )
  );
};

const desiredCustomContent = (current, currentMarket) => {
  const entries = Object.entries(current ?? {}).filter(
    ([key]) => key !== boxAiDefaultPhoneCountryKey
  );
  return Object.fromEntries(
    currentMarket === 'cn' ? [...entries, [boxAiDefaultPhoneCountryKey, 'CN']] : entries
  );
};

const hasDesiredSignInExperience = (current, desired) =>
  current?.branding?.logoUrl === desired.branding.logoUrl &&
  current.branding.darkLogoUrl === desired.branding.darkLogoUrl &&
  current.branding.favicon === desired.branding.favicon &&
  current.branding.darkFavicon === desired.branding.darkFavicon &&
  current?.color?.primaryColor === desired.color.primaryColor &&
  current.color.darkPrimaryColor === desired.color.darkPrimaryColor &&
  current.color.isDarkModeEnabled === desired.color.isDarkModeEnabled &&
  current?.languageInfo?.autoDetect === desired.languageInfo.autoDetect &&
  current.languageInfo.fallbackLanguage === desired.languageInfo.fallbackLanguage &&
  sameStrings(current?.signUp?.identifiers, desired.signUp.identifiers) &&
  current?.signUp?.password === desired.signUp.password &&
  current?.signUp?.verify === desired.signUp.verify &&
  sameSignInMethods(current?.signIn?.methods, desired.signIn.methods) &&
  sameStrings(current?.socialSignInConnectorTargets, desired.socialSignInConnectorTargets) &&
  current?.socialSignIn?.automaticAccountLinking === desired.socialSignIn.automaticAccountLinking &&
  sameCustomContent(current?.customContent, desired.customContent);

const validCredential = (value) =>
  typeof value === 'string' && value.length > 0 && value.length <= 4096 && !/[\0\r\n]/u.test(value);

const validIdentifier = (value) =>
  typeof value === 'string' && /^[0-9A-Za-z._~-]{1,256}$/u.test(value);

const validManagementIdentifier = (value) => validIdentifier(value) && value.length <= 21;

const isRecord = (value) =>
  Boolean(value) && typeof value === 'object' && !Array.isArray(value);

const validStringArray = (value) =>
  Array.isArray(value) &&
  value.length <= 100 &&
  value.every(
    (entry) => typeof entry === 'string' && entry.length <= 4096 && !/[\0\r\n]/u.test(entry)
  );

const applicationTypes = new Set([
  'Native',
  'SPA',
  'Traditional',
  'MachineToMachine',
  'Protected',
  'SAML',
]);

const validApplication = (application) =>
  isRecord(application) &&
  validIdentifier(application.id) &&
  typeof application.name === 'string' &&
  application.name.length > 0 &&
  application.name.length <= 256 &&
  (application.description === null ||
    application.description === undefined ||
    typeof application.description === 'string') &&
  applicationTypes.has(application.type) &&
  isRecord(application.oidcClientMetadata) &&
  (application.oidcClientMetadata.redirectUris === undefined ||
    validStringArray(application.oidcClientMetadata.redirectUris)) &&
  (application.oidcClientMetadata.postLogoutRedirectUris === undefined ||
    validStringArray(application.oidcClientMetadata.postLogoutRedirectUris));

const validScope = (scope) =>
  isRecord(scope) &&
  typeof scope.tenantId === 'string' &&
  scope.tenantId.length <= 21 &&
  validManagementIdentifier(scope.id) &&
  validManagementIdentifier(scope.resourceId) &&
  typeof scope.name === 'string' &&
  scope.name.length > 0 &&
  scope.name.length <= 256 &&
  (scope.description === null || typeof scope.description === 'string') &&
  Number.isFinite(scope.createdAt);

const validResource = (resource, requireScopes = false) =>
  isRecord(resource) &&
  typeof resource.tenantId === 'string' &&
  resource.tenantId.length <= 21 &&
  validManagementIdentifier(resource.id) &&
  typeof resource.name === 'string' &&
  resource.name.length > 0 &&
  resource.name.length <= 4096 &&
  validCredential(resource.indicator) &&
  typeof resource.isDefault === 'boolean' &&
  Number.isFinite(resource.accessTokenTtl) &&
  (!requireScopes || Array.isArray(resource.scopes)) &&
  (resource.scopes === undefined ||
    (Array.isArray(resource.scopes) && resource.scopes.every(validScope)));

const validRole = (role) =>
  isRecord(role) &&
  typeof role.tenantId === 'string' &&
  role.tenantId.length <= 21 &&
  validManagementIdentifier(role.id) &&
  typeof role.name === 'string' &&
  role.name.length > 0 &&
  role.name.length <= 128 &&
  typeof role.description === 'string' &&
  role.description.length > 0 &&
  role.description.length <= 128 &&
  ['User', 'MachineToMachine'].includes(role.type) &&
  typeof role.isDefault === 'boolean';

const validRoleScope = (scope) =>
  validScope(scope) &&
  validResource(scope.resource) &&
  scope.resourceId === scope.resource.id;

const readAllRoles = async (endpoint) => {
  const roles = [];
  for (let page = 1; page <= 100; page += 1) {
    const batch = await requestJson(endpoint, `/api/roles?page=${page}&page_size=100`);
    if (!Array.isArray(batch) || !batch.every(validRole)) {
      throw new Error('Logto returned an invalid role list');
    }
    roles.push(...batch);
    if (batch.length < 100) {
      return roles;
    }
  }
  throw new Error('Logto returned an invalid role list');
};

const hasDuplicates = (values) => new Set(values).size !== values.length;

const validSignInExperienceResponse = (value) =>
  isRecord(value) &&
  isRecord(value.branding) &&
  isRecord(value.color) &&
  isRecord(value.languageInfo) &&
  isRecord(value.signUp) &&
  isRecord(value.signIn) &&
  isRecord(value.socialSignIn) &&
  validStringArray(value.socialSignInConnectorTargets) &&
  validCustomContent(value.customContent);

const validSecretList = (value) =>
  Array.isArray(value) &&
  value.every(
    (secret) =>
      isRecord(secret) &&
      (secret.value === undefined || typeof secret.value === 'string') &&
      (secret.expiresAt === undefined || secret.expiresAt === null || Number.isFinite(secret.expiresAt))
  );

const writeCredential = async (directory, name, value) => {
  if (!validCredential(value)) {
    throw new Error(`Logto returned an invalid ${name}`);
  }
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

const provision = async () => {
  if (!credentialDirectory || !identityBaseUrl || !market || !publicBaseUrl) {
    throw new Error('Logto client provisioning configuration is incomplete');
  }
  if (!Object.hasOwn(fallbackLanguageByMarket, market)) {
    throw new Error('BOX_AI_MARKET is invalid for Logto client provisioning');
  }
  const googleConfigured = [googleClientId, googleClientSecret].filter((value) => isSet(value));
  if (googleConfigured.length !== 0 && googleConfigured.length !== 2) {
    throw new Error('Google sign-in configuration is incomplete');
  }
  const endpoint = validateLocalBootstrapEndpoint(bootstrapEndpoint);
  const wechat = await validateWechatConfiguration();
  const identityBase = parsePublicOrigin(identityBaseUrl, 'BOX_AI_LOGTO_ENDPOINT');
  const publicBase = parsePublicOrigin(publicBaseUrl, 'BOX_AI_PUBLIC_BASE_URL');
  const oidcClientMetadata = {
    redirectUris: [new URL('/api/v1/hosted-auth/callback', publicBase).href],
    postLogoutRedirectUris: [new URL('/login', publicBase).href],
    backchannelLogoutUri: new URL('/api/v1/hosted-auth/backchannel-logout', publicBase).href,
    backchannelLogoutSessionRequired: true,
  };
  const logoUrl = new URL('/brand/box-ai-logo.svg?v=2', identityBase).href;
  const favicon = new URL('/brand/box-ai-favicon.svg?v=2', identityBase).href;
  const isChina = market === 'cn';
  const chinaSignUp = {
    identifiers: ['phone'],
    password: false,
    verify: true,
  };
  const chinaSignIn = {
    methods: [
      { identifier: 'phone', password: false, verificationCode: true, isPasswordPrimary: false },
      { identifier: 'email', password: false, verificationCode: true, isPasswordPrimary: false },
    ],
  };
  const defaultSignUp = {
    identifiers: ['email'],
    password: true,
    verify: true,
  };
  const defaultSignIn = {
    methods: [
      { identifier: 'email', password: true, verificationCode: true, isPasswordPrimary: true },
      { identifier: 'username', password: true, verificationCode: false, isPasswordPrimary: true },
    ],
  };
  const desiredSignInExperience = {
    branding: {
      logoUrl,
      darkLogoUrl: logoUrl,
      favicon,
      darkFavicon: favicon,
    },
    color: {
      primaryColor: '#2f6f4e',
      darkPrimaryColor: '#63a883',
      isDarkModeEnabled: false,
    },
    languageInfo: {
      autoDetect: true,
      fallbackLanguage: fallbackLanguageByMarket[market],
    },
    signUp: isChina ? chinaSignUp : defaultSignUp,
    signIn: isChina ? chinaSignIn : defaultSignIn,
    socialSignInConnectorTargets: isChina
      ? wechat.channels.includes('web')
        ? ['wechat']
        : []
      : googleConfigured.length === 2
        ? ['google']
        : [],
    socialSignIn: {
      automaticAccountLinking: !isChina && googleConfigured.length === 2,
    },
  };

  const nativeOidcClientMetadata = wechat.channels.includes('native')
    ? {
        redirectUris: [new URL('logto-callback', wechat.nativeLinks).href],
        postLogoutRedirectUris: [new URL('post-logout', wechat.nativeLinks).href],
      }
    : undefined;
  const nativeResourceIndicator = nativeOidcClientMetadata
    ? new URL('/api', publicBase).href
    : undefined;

  await waitForLogto(endpoint);
  const applications = await requestJson(endpoint, '/api/applications');
  if (!Array.isArray(applications) || !applications.every(validApplication)) {
    throw new Error('Logto returned an invalid application list');
  }
  const markerApplications = applications.filter(
    (application) => application?.description === applicationDescription
  );
  const namedApplications = applications.filter(
    (application) => application?.name === applicationName
  );
  if (markerApplications.length > 1) {
    throw new Error('multiple managed Box-AI Logto applications exist');
  }
  if (namedApplications.length > 1) {
    throw new Error('multiple applications use the Box-AI application name');
  }
  if (
    markerApplications[0] &&
    namedApplications[0] &&
    markerApplications[0].id !== namedApplications[0].id
  ) {
    throw new Error('Box-AI application ownership is ambiguous');
  }
  if (
    namedApplications[0] &&
    namedApplications[0].description !== applicationDescription
  ) {
    throw new Error('the Box-AI application name is owned by a foreign application');
  }
  const managedApplication = markerApplications[0];
  const markerNativeApplications = applications.filter(
    (application) => application?.description === nativeApplicationDescription
  );
  const namedNativeApplications = applications.filter(
    (application) => application?.name === nativeApplicationName
  );
  if (wechat.channels.includes('native') && markerNativeApplications.length > 1) {
    throw new Error('multiple managed Box-AI Native Logto applications exist');
  }
  if (wechat.channels.includes('native') && namedNativeApplications.length > 1) {
    throw new Error('multiple applications use the Box-AI Native application name');
  }
  if (
    wechat.channels.includes('native') &&
    markerNativeApplications[0] &&
    namedNativeApplications[0] &&
    markerNativeApplications[0].id !== namedNativeApplications[0].id
  ) {
    throw new Error('Box-AI Native application ownership is ambiguous');
  }
  if (
    wechat.channels.includes('native') &&
    namedNativeApplications[0] &&
    namedNativeApplications[0].description !== nativeApplicationDescription
  ) {
    throw new Error('the Box-AI Native application name is owned by a foreign application');
  }
  if (managedApplication && managedApplication.type !== 'Traditional') {
    throw new Error('managed Box-AI Logto application has the wrong type');
  }
  if (managedApplication && !validCredential(managedApplication.id)) {
    throw new Error('Logto returned an invalid application ID');
  }
  if (
    wechat.channels.includes('native') &&
    markerNativeApplications[0] &&
    markerNativeApplications[0].type !== 'Native'
  ) {
    throw new Error('managed Box-AI Native Logto application has the wrong type');
  }
  if (
    wechat.channels.includes('native') &&
    markerNativeApplications[0] &&
    !validCredential(markerNativeApplications[0].id)
  ) {
    throw new Error('Logto returned an invalid Native application ID');
  }

  let nativeResource;
  let nativeResourceScope;
  let nativeSessionRole;
  let nativeSessionRoleScopes = [];
  let discoveredResourceIds = new Set();
  let discoveredScopeIds = new Set();
  let discoveredRoleIds = new Set();
  if (nativeResourceIndicator) {
    const resources = await requestJson(endpoint, '/api/resources?includeScopes=true');
    if (!Array.isArray(resources) || !resources.every((resource) => validResource(resource, true))) {
      throw new Error('Logto returned an invalid resource list');
    }
    if (hasDuplicates(resources.map(({ id }) => id))) {
      throw new Error('duplicate Logto resource IDs exist');
    }
    discoveredResourceIds = new Set(resources.map(({ id }) => id));
    if (hasDuplicates(resources.map(({ indicator }) => indicator))) {
      throw new Error('duplicate Logto resource indicators exist');
    }

    const scopes = resources.flatMap((resource) => resource.scopes);
    if (
      scopes.some((scope) => !resources.some((resource) => resource.id === scope.resourceId)) ||
      resources.some((resource) =>
        resource.scopes.some((scope) => scope.resourceId !== resource.id)
      )
    ) {
      throw new Error('Logto resource scope ownership is ambiguous');
    }
    if (hasDuplicates(scopes.map(({ id }) => id))) {
      throw new Error('duplicate Logto resource scope IDs exist');
    }
    discoveredScopeIds = new Set(scopes.map(({ id }) => id));

    const markerResources = resources.filter(({ name }) => name === nativeResourceName);
    const indicatorResources = resources.filter(
      ({ indicator }) => indicator === nativeResourceIndicator
    );
    if (markerResources.length > 1) {
      throw new Error('multiple managed Box-AI Native Session API resources exist');
    }
    if (indicatorResources.length > 1) {
      throw new Error('multiple resources use the Box-AI Native Session API indicator');
    }
    if (
      markerResources[0] &&
      indicatorResources[0] &&
      markerResources[0].id !== indicatorResources[0].id
    ) {
      throw new Error('Box-AI Native Session API resource ownership is ambiguous');
    }
    if (indicatorResources[0] && indicatorResources[0].name !== nativeResourceName) {
      throw new Error('the Box-AI Native Session API indicator is owned by a foreign resource');
    }
    if (markerResources[0] && markerResources[0].indicator !== nativeResourceIndicator) {
      throw new Error('the Box-AI Native Session API marker is attached to a foreign indicator');
    }

    nativeResource = indicatorResources[0] ?? markerResources[0];
    const markerScopes = scopes.filter(
      ({ description }) => description === nativeResourceScopeDescription
    );
    if (markerScopes.length > 1) {
      throw new Error('multiple managed Box-AI native session exchange scopes exist');
    }
    if (nativeResource) {
      const namedScopes = nativeResource.scopes.filter(
        ({ name }) => name === nativeResourceScopeName
      );
      if (namedScopes.length > 1) {
        throw new Error('multiple native session exchange scopes exist');
      }
      if (
        namedScopes[0] &&
        namedScopes[0].description !== nativeResourceScopeDescription
      ) {
        throw new Error('the native session exchange scope name is owned by a foreign scope');
      }
      if (
        markerScopes[0] &&
        (markerScopes[0].resourceId !== nativeResource.id ||
          (namedScopes[0] && markerScopes[0].id !== namedScopes[0].id))
      ) {
        throw new Error('Box-AI native session exchange scope ownership is ambiguous');
      }
      nativeResourceScope = markerScopes[0] ?? namedScopes[0];
    } else if (markerScopes.length > 0) {
      throw new Error('Box-AI native session exchange scope ownership is ambiguous');
    }

    const roles = await readAllRoles(endpoint);
    if (hasDuplicates(roles.map(({ id }) => id))) {
      throw new Error('duplicate Logto role IDs exist');
    }
    discoveredRoleIds = new Set(roles.map(({ id }) => id));
    const markerRoles = roles.filter(
      ({ description }) => description === nativeSessionRoleDescription
    );
    const namedRoles = roles.filter(({ name }) => name === nativeSessionRoleName);
    if (markerRoles.length > 1) {
      throw new Error('multiple managed Box-AI native session roles exist');
    }
    if (namedRoles.length > 1) {
      throw new Error('multiple roles use the Box-AI native session role name');
    }
    if (namedRoles[0] && namedRoles[0].description !== nativeSessionRoleDescription) {
      throw new Error('the Box-AI native session role name is owned by a foreign role');
    }
    if (markerRoles[0] && namedRoles[0] && markerRoles[0].id !== namedRoles[0].id) {
      throw new Error('Box-AI native session role ownership is ambiguous');
    }
    nativeSessionRole = markerRoles[0];
    if (nativeSessionRole && nativeSessionRole.type !== 'User') {
      throw new Error('managed Box-AI native session role has the wrong type');
    }
    if (nativeSessionRole) {
      nativeSessionRoleScopes = await requestJson(
        endpoint,
        `/api/roles/${encodeURIComponent(nativeSessionRole.id)}/scopes`
      );
      if (
        !Array.isArray(nativeSessionRoleScopes) ||
        !nativeSessionRoleScopes.every(validRoleScope) ||
        hasDuplicates(nativeSessionRoleScopes.map(({ id }) => id))
      ) {
        throw new Error('Logto returned an invalid native session role scope list');
      }
      if (
        nativeSessionRoleScopes.some((roleScope) => {
          const discoveredScope = scopes.find(({ id }) => id === roleScope.id);
          const discoveredResource = resources.find(
            ({ id }) => id === roleScope.resourceId
          );
          return (
            !discoveredScope ||
            !discoveredResource ||
            discoveredScope.resourceId !== roleScope.resourceId ||
            roleScope.resource.id !== discoveredScope.resourceId ||
            roleScope.resource.indicator !== discoveredResource.indicator
          );
        })
      ) {
        throw new Error('Box-AI native session role has a foreign scope relation');
      }
      if (
        nativeSessionRoleScopes.length > 1 ||
        (nativeSessionRoleScopes[0] &&
          (!nativeResourceScope || nativeSessionRoleScopes[0].id !== nativeResourceScope.id))
      ) {
        throw new Error('Box-AI native session role has an extra scope relation');
      }
    }
  }

  let application = managedApplication;
  if (!application) {
    application = await requestJson(endpoint, '/api/applications', {
      method: 'POST',
      body: JSON.stringify({
        name: applicationName,
        description: applicationDescription,
        type: 'Traditional',
        oidcClientMetadata,
      }),
    });
  } else {
    if (
      application.name !== applicationName ||
      application.description !== applicationDescription ||
      !hasDesiredMetadata(application, oidcClientMetadata)
    ) {
      application = await requestJson(endpoint, `/api/applications/${encodeURIComponent(application.id)}`, {
        method: 'PATCH',
        body: JSON.stringify({
          name: applicationName,
          description: applicationDescription,
          oidcClientMetadata,
        }),
      });
    }
  }
  if (
    !validApplication(application) ||
    application.type !== 'Traditional' ||
    application.name !== applicationName ||
    application.description !== applicationDescription ||
    !hasDesiredMetadata(application, oidcClientMetadata)
  ) {
    throw new Error('Logto returned an invalid application ID');
  }

  let nativeApplication;
  if (nativeOidcClientMetadata) {
    nativeApplication = markerNativeApplications[0];
    if (!nativeApplication) {
      nativeApplication = await requestJson(endpoint, '/api/applications', {
        method: 'POST',
        body: JSON.stringify({
          name: nativeApplicationName,
          description: nativeApplicationDescription,
          type: 'Native',
          oidcClientMetadata: nativeOidcClientMetadata,
        }),
      });
    } else if (
      nativeApplication.name !== nativeApplicationName ||
      nativeApplication.description !== nativeApplicationDescription ||
      !hasDesiredNativeMetadata(nativeApplication, nativeOidcClientMetadata)
    ) {
      nativeApplication = await requestJson(
        endpoint,
        `/api/applications/${encodeURIComponent(nativeApplication.id)}`,
        {
          method: 'PATCH',
          body: JSON.stringify({
            name: nativeApplicationName,
            description: nativeApplicationDescription,
            oidcClientMetadata: nativeOidcClientMetadata,
          }),
        }
      );
    }
    if (
      !validApplication(nativeApplication) ||
      nativeApplication.type !== 'Native' ||
      nativeApplication.name !== nativeApplicationName ||
      nativeApplication.description !== nativeApplicationDescription ||
      !hasDesiredNativeMetadata(nativeApplication, nativeOidcClientMetadata)
    ) {
      throw new Error('Logto returned an invalid Native application ID');
    }
  }

  if (nativeResourceIndicator) {
    const expectedResourceId = nativeResource?.id;
    let createdResource = false;
    if (!nativeResource) {
      createdResource = true;
      nativeResource = await requestJson(endpoint, '/api/resources', {
        method: 'POST',
        body: JSON.stringify({
          name: nativeResourceName,
          indicator: nativeResourceIndicator,
          accessTokenTtl: nativeResourceAccessTokenTtl,
        }),
      });
    } else if (nativeResource.accessTokenTtl !== nativeResourceAccessTokenTtl) {
      nativeResource = await requestJson(
        endpoint,
        `/api/resources/${encodeURIComponent(nativeResource.id)}`,
        {
          method: 'PATCH',
          body: JSON.stringify({ accessTokenTtl: nativeResourceAccessTokenTtl }),
        }
      );
    }
    if (
      !validResource(nativeResource) ||
      (createdResource
        ? discoveredResourceIds.has(nativeResource.id) ||
          !Array.isArray(nativeResource.scopes) ||
          nativeResource.scopes.length !== 0
        : nativeResource.id !== expectedResourceId) ||
      nativeResource.name !== nativeResourceName ||
      nativeResource.indicator !== nativeResourceIndicator ||
      nativeResource.accessTokenTtl !== nativeResourceAccessTokenTtl
    ) {
      throw new Error('Logto returned an invalid Native Session API resource');
    }

    const scopePath = `/api/resources/${encodeURIComponent(nativeResource.id)}/scopes`;
    const expectedScopeId = nativeResourceScope?.id;
    let createdScope = false;
    if (!nativeResourceScope) {
      createdScope = true;
      nativeResourceScope = await requestJson(endpoint, scopePath, {
        method: 'POST',
        body: JSON.stringify({
          name: nativeResourceScopeName,
          description: nativeResourceScopeDescription,
        }),
      });
    } else if (nativeResourceScope.name !== nativeResourceScopeName) {
      nativeResourceScope = await requestJson(
        endpoint,
        `${scopePath}/${encodeURIComponent(nativeResourceScope.id)}`,
        {
          method: 'PATCH',
          body: JSON.stringify({ name: nativeResourceScopeName }),
        }
      );
    }
    if (
      !validScope(nativeResourceScope) ||
      (createdScope
        ? discoveredScopeIds.has(nativeResourceScope.id)
        : nativeResourceScope.id !== expectedScopeId) ||
      nativeResourceScope.resourceId !== nativeResource.id ||
      nativeResourceScope.name !== nativeResourceScopeName ||
      nativeResourceScope.description !== nativeResourceScopeDescription
    ) {
      throw new Error('Logto returned an invalid native session exchange scope');
    }

    const expectedRoleId = nativeSessionRole?.id;
    let createdRole = false;
    if (!nativeSessionRole) {
      createdRole = true;
      nativeSessionRole = await requestJson(endpoint, '/api/roles', {
        method: 'POST',
        body: JSON.stringify({
          name: nativeSessionRoleName,
          description: nativeSessionRoleDescription,
          type: 'User',
          isDefault: true,
          scopeIds: [nativeResourceScope.id],
        }),
      });
    } else {
      const rolePatch = {
        ...(nativeSessionRole.name === nativeSessionRoleName
          ? {}
          : { name: nativeSessionRoleName }),
        ...(nativeSessionRole.isDefault ? {} : { isDefault: true }),
      };
      if (Object.keys(rolePatch).length > 0) {
        nativeSessionRole = await requestJson(
          endpoint,
          `/api/roles/${encodeURIComponent(nativeSessionRole.id)}`,
          {
            method: 'PATCH',
            body: JSON.stringify(rolePatch),
          }
        );
      }
    }
    if (
      !validRole(nativeSessionRole) ||
      (createdRole && discoveredRoleIds.has(nativeSessionRole.id)) ||
      (!createdRole && nativeSessionRole.id !== expectedRoleId) ||
      nativeSessionRole.name !== nativeSessionRoleName ||
      nativeSessionRole.description !== nativeSessionRoleDescription ||
      nativeSessionRole.type !== 'User' ||
      !nativeSessionRole.isDefault
    ) {
      throw new Error('Logto returned an invalid native session role');
    }

    const roleScopesPath = `/api/roles/${encodeURIComponent(nativeSessionRole.id)}/scopes`;
    if (createdRole) {
      const assignedScopes = await requestJson(endpoint, roleScopesPath);
      if (
        !Array.isArray(assignedScopes) ||
        assignedScopes.length !== 1 ||
        !validRoleScope(assignedScopes[0]) ||
        assignedScopes[0].id !== nativeResourceScope.id ||
        assignedScopes[0].resource.indicator !== nativeResourceIndicator
      ) {
        throw new Error('Logto returned an invalid native session role scope list');
      }
    } else if (nativeSessionRoleScopes.length === 0) {
      const assignedScopes = await requestJson(endpoint, roleScopesPath, {
        method: 'POST',
        body: JSON.stringify({ scopeIds: [nativeResourceScope.id] }),
      });
      if (
        !Array.isArray(assignedScopes) ||
        assignedScopes.length !== 1 ||
        !validScope(assignedScopes[0]) ||
        assignedScopes[0].id !== nativeResourceScope.id ||
        assignedScopes[0].resourceId !== nativeResource.id
      ) {
        throw new Error('Logto returned an invalid native session role scope assignment');
      }
    }
  }

  const signInExperience = await requestJson(endpoint, '/api/sign-in-exp');
  if (!validSignInExperienceResponse(signInExperience)) {
    throw new Error('Logto returned an invalid sign-in experience');
  }
  const desiredSignInExperienceForCurrent = {
    ...desiredSignInExperience,
    customContent: desiredCustomContent(signInExperience.customContent, market),
  };
  if (!hasDesiredSignInExperience(signInExperience, desiredSignInExperienceForCurrent)) {
    const patchedSignInExperience = await requestJson(endpoint, '/api/sign-in-exp', {
      method: 'PATCH',
      body: JSON.stringify(desiredSignInExperienceForCurrent),
    });
    if (
      !validSignInExperienceResponse(patchedSignInExperience) ||
      !hasDesiredSignInExperience(patchedSignInExperience, desiredSignInExperienceForCurrent)
    ) {
      throw new Error('Logto returned an invalid sign-in experience');
    }
  }

  const secretPath = `/api/applications/${encodeURIComponent(application.id)}/secrets`;
  const secrets = await requestJson(endpoint, secretPath);
  if (!validSecretList(secrets)) {
    throw new Error('Logto returned an invalid application secret list');
  }
  const now = Date.now();
  let secret = secrets.find(
    (candidate) =>
      validCredential(candidate?.value) &&
      (candidate.expiresAt === null || candidate.expiresAt === undefined || candidate.expiresAt > now)
  );
  if (!secret) {
    secret = await requestJson(endpoint, secretPath, {
      method: 'POST',
      body: JSON.stringify({ name: `Box-AI runtime ${now}` }),
    });
  }
  if (!isRecord(secret) || !validCredential(secret.value)) {
    throw new Error('Logto returned an invalid application secret');
  }

  await mkdir(credentialDirectory, { recursive: true, mode: 0o755 });
  await chmod(credentialDirectory, 0o755);
  await writeCredential(credentialDirectory, 'client-id', application.id);
  await writeCredential(credentialDirectory, 'client-secret', secret.value);
  if (nativeApplication) {
    await writeCredential(credentialDirectory, 'native-client-id', nativeApplication.id);
    await writeCredential(
      credentialDirectory,
      'native-resource-indicator',
      nativeResourceIndicator
    );
    await writeCredential(
      credentialDirectory,
      'native-resource-scope',
      nativeResourceScopeName
    );
  } else {
    await rm(join(credentialDirectory, 'native-client-id'), { force: true });
    await rm(join(credentialDirectory, 'native-resource-indicator'), { force: true });
    await rm(join(credentialDirectory, 'native-resource-scope'), { force: true });
  }
  process.stdout.write('Logto client credentials provisioned\n');
};

await provision();
