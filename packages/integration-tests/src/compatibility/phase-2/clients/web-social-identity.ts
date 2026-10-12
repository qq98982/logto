/* eslint-disable complexity -- The driver validates one closed provider authorization and identification sequence. */
import { randomBytes } from 'node:crypto';

import type { NativeSocialIdentityDriver } from './user-token-issuance.js';

const fail = (): never => {
  throw new TypeError('Invalid Common web social identity flow');
};
const record = async (response: Response): Promise<Record<string, unknown>> => {
  const text = await response.text();
  const value: unknown = Buffer.byteLength(text) <= 16 * 1024 ? JSON.parse(text) : fail();
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? Object.fromEntries(Object.entries(value))
    : fail();
};
const bounded = (value: unknown): string =>
  typeof value === 'string' && value.length > 0 && Buffer.byteLength(value) <= 4096
    ? value
    : fail();

/** Drives a public Google or WeChat Web identity through the real Experience endpoints. */
export const createWebSocialIdentityDriver =
  (
    input: Readonly<{
      connectorId: string;
      redirectUri: string;
      provider: 'google' | 'wechat';
      takeProviderCode(authorizationUri: string, state: string): Promise<string>;
      observeIdentification?(status: number, body: Readonly<Record<string, unknown>>): void;
    }>
  ): NativeSocialIdentityDriver =>
  async ({ request }) => {
    const initialized = await request('/api/experience', 'PUT', { interactionEvent: 'SignIn' });
    if (initialized.status !== 204) {
      return fail();
    }
    await initialized.body?.cancel();
    const state = randomBytes(24).toString('base64url');
    const authorization = await request(
      `/api/experience/verification/social/${encodeURIComponent(input.connectorId)}/authorization-uri`,
      'POST',
      { redirectUri: input.redirectUri, state }
    );
    if (authorization.status !== 200) {
      return fail();
    }
    const authorizationBody = await record(authorization);
    const verificationId = bounded(authorizationBody.verificationId);
    const authorizationUri = bounded(authorizationBody.authorizationUri);
    const parsed = new URL(authorizationUri);
    if (
      parsed.searchParams.getAll('state').length !== 1 ||
      parsed.searchParams.get('state') !== state ||
      (input.provider === 'google' && parsed.protocol !== 'https:') ||
      (input.provider === 'wechat' && !['https:', 'weixin:'].includes(parsed.protocol))
    ) {
      return fail();
    }
    const code = bounded(await input.takeProviderCode(authorizationUri, state));
    const verified = await request(
      `/api/experience/verification/social/${encodeURIComponent(input.connectorId)}/verify`,
      'POST',
      { verificationId, connectorData: { code, redirectUri: input.redirectUri } }
    );
    const verifiedBody = await record(verified);
    if (verified.status !== 200 || bounded(verifiedBody.verificationId) !== verificationId) {
      return fail();
    }
    const identified = await request('/api/experience/identification', 'POST', { verificationId });
    if (identified.status === 204) {
      input.observeIdentification?.(204, {});
      await identified.body?.cancel();
      return;
    }
    const identifiedBody = await record(identified);
    input.observeIdentification?.(identified.status, identifiedBody);
    return fail();
  };
/* eslint-enable complexity */
