/* eslint-disable max-lines -- One closed security-boundary suite keeps request, response, stream, JWKS, and leakage controls together. */
import { createHash } from 'node:crypto';

import { base64url, exportJWK, generateKeyPair, SignJWT, type JSONWebKeySet } from 'jose';

import {
  ClientCredentialsClientError,
  observeClientCredentialsToken,
  type ClientCredentialsRequest,
  type ClientCredentialsRequestOptions,
} from './clients/client-credentials.js';

const fixtureSecret = ['AsterPhaseTwo', 'FixtureSecret', '000000'].join('');
const fixtureClientId = 'fixture-client';
const endpoint = 'https://issuer.example/oidc/token';

const createSigningFixture = async (
  kid: string,
  payload: Record<string, unknown> = {},
  protectedHeader: Record<string, unknown> = {}
) => {
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  const publicJwk = await exportJWK(publicKey);
  const jwks: JSONWebKeySet = {
    keys: [{ ...publicJwk, alg: 'ES256', kid, use: 'sig' }],
  };
  const token = await new SignJWT({ client_id: fixtureClientId, scope: 'read', ...payload })
    .setProtectedHeader({ alg: 'ES256', kid, typ: 'at+jwt', ...protectedHeader })
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(privateKey);

  return { jwks, token };
};

const successfulResponse = (
  token: string,
  extra: Record<string, unknown> = {},
  headers: HeadersInit = {}
) =>
  new Response(
    JSON.stringify({
      access_token: token,
      expires_in: 3600,
      token_type: 'Bearer',
      ...extra,
    }),
    {
      status: 200,
      headers: {
        'cache-control': 'no-store',
        'content-type': 'application/json',
        ...Object.fromEntries(new Headers(headers)),
      },
    }
  );

const captureFetch = (response: Response) => {
  const calls: Array<readonly [URL | RequestInfo, RequestInit | undefined]> = [];
  const requestFetch = (async (input: URL | RequestInfo, init?: RequestInit) => {
    // eslint-disable-next-line @silverhand/fp/no-mutating-methods -- The test records the transport call for an exact wire assertion.
    calls.push([input, init]);
    return response;
  }) as typeof fetch;

  return { calls, requestFetch };
};

const baseRequest: ClientCredentialsRequest = {
  method: 'client_secret_post',
  clientId: fixtureClientId,
  clientSecret: fixtureSecret,
};

describe('Phase 2 client credentials oracle request contract', () => {
  it('constructs registered Basic authentication with OAuth form-component encoding', async () => {
    const { jwks, token } = await createSigningFixture('basic-key');
    const { calls, requestFetch } = captureFetch(successfulResponse(token));

    const observation = await observeClientCredentialsToken(
      endpoint,
      jwks,
      {
        method: 'client_secret_basic',
        clientId: 'client id~',
        clientSecret: fixtureSecret,
        resource: 'https://resource.example/api',
        organizationId: 'organization-id',
        scope: 'read write',
      },
      { fetch: requestFetch }
    );

    expect(calls).toHaveLength(1);
    const [input, init] = calls[0]!;
    expect(String(input)).toBe(endpoint);
    expect(init?.method).toBe('POST');
    expect(init?.redirect).toBe('manual');
    expect(new Headers(init?.headers).get('authorization')).toBe(
      `Basic ${Buffer.from(`client+id%7E:${fixtureSecret}`).toString('base64')}`
    );
    expect(String(init?.body)).toBe(
      'grant_type=client_credentials&resource=https%3A%2F%2Fresource.example%2Fapi&organization_id=organization-id&scope=read+write'
    );
    expect(observation.jwt?.claims.client_id).toBe(fixtureClientId);
  });

  it('constructs registered POST authentication without an Authorization header', async () => {
    const { jwks, token } = await createSigningFixture('post-key');
    const { calls, requestFetch } = captureFetch(successfulResponse(token));

    await observeClientCredentialsToken(
      endpoint,
      jwks,
      {
        method: 'client_secret_post',
        clientId: 'client id',
        clientSecret: fixtureSecret,
        resource: 'https://resource.example/api',
      },
      { fetch: requestFetch }
    );

    const [, init] = calls[0]!;
    expect(new Headers(init?.headers).has('authorization')).toBe(false);
    expect(String(init?.body)).toBe(
      `grant_type=client_credentials&resource=https%3A%2F%2Fresource.example%2Fapi&client_id=client+id&client_secret=${fixtureSecret}`
    );
  });

  it('rejects caller Authorization, hidden unknown keys, controls, and oversized UTF-8 fields', async () => {
    const { jwks } = await createSigningFixture('grammar-key');
    const requests: Array<true> = [];
    const requestFetch = (async () => {
      // eslint-disable-next-line @silverhand/fp/no-mutating-methods -- The sentinel proves rejection happens before transport.
      requests.push(true);
      return new Response();
    }) as typeof fetch;
    const requestWithHiddenKey = Object.create(Object.prototype, {
      method: { enumerable: true, value: baseRequest.method },
      clientId: { enumerable: true, value: baseRequest.clientId },
      clientSecret: { enumerable: true, value: baseRequest.clientSecret },
      extra: { enumerable: false, value: 'not-accepted' },
    }) as ClientCredentialsRequest;

    await expect(
      observeClientCredentialsToken(endpoint, jwks, baseRequest, {
        fetch: requestFetch,
        headers: [
          ['Authorization', 'Basic first'],
          ['authorization', 'Basic second'],
        ],
      })
    ).rejects.toMatchObject({
      message: 'Client credentials request rejected',
      name: 'ClientCredentialsClientError',
    });
    await expect(
      observeClientCredentialsToken(endpoint, jwks, baseRequest, {
        fetch: requestFetch,
        headers: [[{ toString: () => 'Authorization' } as unknown as string, 'Basic coercible']],
      })
    ).rejects.toThrow('Client credentials request rejected');
    await expect(
      observeClientCredentialsToken(endpoint, jwks, baseRequest, {
        fetch: requestFetch,
        headers: [['x-invalid', `${fixtureSecret}\nreflected`]],
      })
    ).rejects.toThrow('Client credentials request rejected');
    const invalidHeaderName = `x invalid ${fixtureSecret}`;
    const nativeHeaderError = await observeClientCredentialsToken(endpoint, jwks, baseRequest, {
      fetch: requestFetch,
      headers: [[invalidHeaderName, 'safe-value']],
    }).catch((error_: unknown) => error_);
    expect(nativeHeaderError).toBeInstanceOf(ClientCredentialsClientError);
    expect(String(nativeHeaderError)).toBe(
      'ClientCredentialsClientError: Client credentials request rejected'
    );
    expect(String(nativeHeaderError)).not.toContain(invalidHeaderName);
    expect(String(nativeHeaderError)).not.toContain(fixtureSecret);
    await expect(
      observeClientCredentialsToken(endpoint, jwks, requestWithHiddenKey, { fetch: requestFetch })
    ).rejects.toThrow('Client credentials request rejected');
    const inheritedSecret = `inherited-${fixtureSecret}`;
    const inheritedRequest = Object.create({
      get method() {
        throw new Error(inheritedSecret);
      },
      clientId: fixtureClientId,
      clientSecret: fixtureSecret,
    }) as ClientCredentialsRequest;
    const inheritedError = await observeClientCredentialsToken(endpoint, jwks, inheritedRequest, {
      fetch: requestFetch,
    }).catch((error_: unknown) => error_);
    expect(inheritedError).toBeInstanceOf(ClientCredentialsClientError);
    expect(String(inheritedError)).toBe(
      'ClientCredentialsClientError: Client credentials request rejected'
    );
    expect(String(inheritedError)).not.toContain(inheritedSecret);
    expect(String(inheritedError)).not.toContain(fixtureSecret);
    const optionSecret = `option-${fixtureSecret}`;
    const trappedOptions = Object.create(Object.prototype, {
      fetch: {
        enumerable: true,
        get() {
          throw new Error(optionSecret);
        },
      },
    }) as unknown as ClientCredentialsRequestOptions;
    const optionError = await observeClientCredentialsToken(
      endpoint,
      jwks,
      baseRequest,
      trappedOptions
    ).catch((error_: unknown) => error_);
    expect(optionError).toBeInstanceOf(ClientCredentialsClientError);
    expect(String(optionError)).toBe(
      'ClientCredentialsClientError: Client credentials request rejected'
    );
    expect(String(optionError)).not.toContain(optionSecret);
    expect(String(optionError)).not.toContain(fixtureSecret);
    const trappedHeader = ['safe-name', 'safe-value'];
    // eslint-disable-next-line @silverhand/fp/no-mutating-methods -- The accessor trap verifies tuple reads remain inside the fixed-error boundary.
    Object.defineProperty(trappedHeader, 0, {
      get() {
        throw new Error(`header-${fixtureSecret}`);
      },
    });
    const headerTrapError = await observeClientCredentialsToken(endpoint, jwks, baseRequest, {
      fetch: requestFetch,
      headers: [trappedHeader as [string, string]],
    }).catch((error_: unknown) => error_);
    expect(headerTrapError).toBeInstanceOf(ClientCredentialsClientError);
    expect(String(headerTrapError)).toBe(
      'ClientCredentialsClientError: Client credentials request rejected'
    );
    expect(String(headerTrapError)).not.toContain(fixtureSecret);
    await expect(
      observeClientCredentialsToken(
        endpoint,
        jwks,
        { ...baseRequest, clientSecret: 'redacted' },
        { fetch: requestFetch }
      )
    ).rejects.toThrow('Client credentials request rejected');
    await expect(
      observeClientCredentialsToken(endpoint, jwks, {
        ...baseRequest,
        scope: 'read\u0085write',
      })
    ).rejects.toThrow('Client credentials request rejected');
    await expect(
      observeClientCredentialsToken(endpoint, jwks, {
        ...baseRequest,
        clientSecret: 'é'.repeat(2049),
      })
    ).rejects.toThrow('Client credentials request rejected');
    expect(requests).toHaveLength(0);
  });

  it('removes credentials, token fields, cookie fields, and embedded values from success output', async () => {
    const compactLookingValue = 'prefix abc.def.ghi suffix';
    const basicCredential = Buffer.from(`${fixtureClientId}:${fixtureSecret}`).toString('base64');
    const authorization = `Basic ${basicCredential}`;
    const { jwks, token } = await createSigningFixture(
      'sanitizer-key',
      {
        authorization: fixtureSecret,
        cookie: 'session=private',
        unrelatedEcho: 'private',
        basicCredential,
        [fixtureSecret]: 'secret-key',
        'abc.def.ghi': 'token-key',
        nested: { echoed: fixtureSecret, compact: compactLookingValue },
      },
      {
        authorization: fixtureSecret,
        cookie: 'header-cookie',
        unrelatedEcho: 'private',
        basicCredential,
        [fixtureSecret]: 'secret-key',
        'abc.def.ghi': 'token-key',
      }
    );
    const { requestFetch } = captureFetch(
      successfulResponse(
        token,
        {
          client_secret: fixtureSecret,
          cookie: 'response-cookie',
          unrelatedEcho: 'private',
          basicCredential,
          [fixtureSecret]: 'secret-key',
          'abc.def.ghi': 'token-key',
          nested: { echoed: fixtureSecret, authorization, compact: compactLookingValue },
        },
        {
          'x-echoed-token': token,
          'set-cookie': 'sid="private"',
          'abc.def.ghi': 'token-header',
          [fixtureSecret]: 'secret-header-name',
        }
      )
    );
    const observation = await observeClientCredentialsToken(
      endpoint,
      jwks,
      { ...baseRequest, method: 'client_secret_basic' },
      { fetch: requestFetch }
    );
    const serialized = JSON.stringify(observation);
    const normalized = serialized.toLowerCase();

    expect(serialized).not.toContain(token);
    expect(serialized).not.toContain(fixtureSecret);
    expect(normalized).not.toContain(fixtureSecret.toLowerCase());
    expect(serialized).not.toContain(authorization);
    expect(serialized).not.toContain(basicCredential);
    expect(serialized).not.toContain(compactLookingValue);
    expect(normalized).not.toContain('access_token');
    expect(normalized).not.toContain('client_secret');
    expect(normalized).not.toContain('authorization');
    expect(normalized).not.toContain('cookie');
    expect(observation.body).toMatchObject({ expires_in: 3600, token_type: 'Bearer' });
    expect(observation.body.unrelatedEcho).toBe('<redacted>');
    expect(observation.jwt?.claims.unrelatedEcho).toBe('<redacted>');
    expect(observation.body.basicCredential).toBe('<redacted>');
    expect(observation.jwt?.claims.basicCredential).toBe('<redacted>');
    expect(observation.jwt?.header.unrelatedEcho).toBe('<redacted>');
    expect(observation.jwt?.header.basicCredential).toBe('<redacted>');
    expect(observation.jwt?.signatureSha256).toBe(
      createHash('sha256')
        .update(base64url.decode(token.split('.')[2]!))
        .digest('hex')
    );
  });

  it('retains bounded non-sensitive error response data while sanitizing recursively', async () => {
    const { jwks } = await createSigningFixture('error-key');
    const compactLookingValue = 'prefix abc.def.ghi suffix';
    const response = new Response(
      JSON.stringify({
        error: 'invalid_client',
        error_description: 'ordinary diagnostic',
        client_secret: fixtureSecret,
        cookie: 'sid=private',
        unrelatedEcho: 'private',
        nested: {
          authorization: 'Basic private',
          compact: compactLookingValue,
          labeled: 'Authorization: Basic unrelated',
        },
      }),
      {
        status: 401,
        headers: {
          'content-type': 'application/json',
          'set-cookie': 'sid="private"',
          'x-safe': 'retained',
        },
      }
    );

    const observation = await observeClientCredentialsToken(endpoint, jwks, baseRequest, {
      fetch: (async () => response) as typeof fetch,
    });
    const serialized = JSON.stringify(observation);

    expect(observation).toEqual({
      status: 401,
      headers: { 'content-type': 'application/json', 'x-safe': 'retained' },
      body: {
        error: 'invalid_client',
        error_description: 'ordinary diagnostic',
        unrelatedEcho: '<redacted>',
        nested: { compact: '<redacted>', labeled: '<redacted>' },
      },
    });
    expect(serialized).not.toContain(fixtureSecret);
    expect(serialized).not.toContain(compactLookingValue);
    expect(serialized.toLowerCase()).not.toContain('cookie');
    expect(serialized.toLowerCase()).not.toContain('authorization');

    const textObservation = await observeClientCredentialsToken(endpoint, jwks, baseRequest, {
      fetch: (async () =>
        new Response('Authorization: Basic unrelated\nCookie: sid=other', {
          status: 401,
          headers: { 'content-type': 'text/plain' },
        })) as typeof fetch,
    });
    expect(textObservation.body).toEqual({ text: '<redacted>' });
    expect(JSON.stringify(textObservation)).not.toContain('Authorization');
    expect(JSON.stringify(textObservation)).not.toContain('Cookie');

    const quotedCookieObservation = await observeClientCredentialsToken(
      endpoint,
      jwks,
      baseRequest,
      {
        fetch: (async () =>
          new Response('{"echo":"alpha,beta"}', {
            status: 401,
            headers: {
              'content-type': 'application/json',
              'set-cookie': 'sid="alpha,beta"',
            },
          })) as typeof fetch,
      }
    );
    expect(quotedCookieObservation.body).toEqual({ echo: '<redacted>' });
    expect(JSON.stringify(quotedCookieObservation)).not.toContain('alpha,beta');

    const readCancellations: Array<true> = [];
    const trappedResponse = {
      status: 500,
      headers: new Headers({ 'content-type': 'application/json' }),
      body: {
        getReader: () => ({
          read: async () => {
            throw new Error(`read-${fixtureSecret}`);
          },
          cancel: async () => {
            // eslint-disable-next-line @silverhand/fp/no-mutating-methods -- The test records cancellation after a reader failure.
            readCancellations.push(true);
          },
          releaseLock: () => readCancellations.length,
        }),
        cancel: async () => readCancellations.length,
      },
    } as unknown as Response;
    const readError = await observeClientCredentialsToken(endpoint, jwks, baseRequest, {
      fetch: (async () => trappedResponse) as typeof fetch,
    }).catch((error_: unknown) => error_);
    expect(readError).toBeInstanceOf(ClientCredentialsClientError);
    expect(String(readError)).toBe(
      'ClientCredentialsClientError: Client credentials response rejected'
    );
    expect(String(readError)).not.toContain(fixtureSecret);
    expect(readCancellations).toHaveLength(1);
  });

  it('cancels response streams when body or header bounds reject the response', async () => {
    const { jwks } = await createSigningFixture('bounds-key');
    const bodyCancellations: Array<true> = [];
    const oversizedBody = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('1234'));
        controller.enqueue(new TextEncoder().encode('5678'));
      },
      cancel() {
        // eslint-disable-next-line @silverhand/fp/no-mutating-methods -- The test records stream cancellation.
        bodyCancellations.push(true);
      },
    });

    await expect(
      observeClientCredentialsToken(endpoint, jwks, baseRequest, {
        fetch: (async () => new Response(oversizedBody)) as typeof fetch,
        maximumBodyBytes: 4,
      })
    ).rejects.toThrow('Client credentials response rejected');
    expect(bodyCancellations).toHaveLength(1);

    const headerCancellations: Array<true> = [];
    const unreadBody = new ReadableStream<Uint8Array>({
      cancel() {
        // eslint-disable-next-line @silverhand/fp/no-mutating-methods -- The test records stream cancellation.
        headerCancellations.push(true);
      },
    });

    await expect(
      observeClientCredentialsToken(endpoint, jwks, baseRequest, {
        fetch: (async () =>
          new Response(unreadBody, { headers: { 'x-oversized': '0123456789' } })) as typeof fetch,
        maximumHeaderBytes: 8,
      })
    ).rejects.toThrow('Client credentials response rejected');
    expect(headerCancellations).toHaveLength(1);

    const contentLengthCancellations: Array<true> = [];
    const contentLengthBody = new ReadableStream<Uint8Array>({
      cancel() {
        // eslint-disable-next-line @silverhand/fp/no-mutating-methods -- The test records early content-length cancellation.
        contentLengthCancellations.push(true);
      },
    });
    await expect(
      observeClientCredentialsToken(endpoint, jwks, baseRequest, {
        fetch: (async () =>
          new Response(contentLengthBody, {
            headers: { 'content-length': '100' },
          })) as typeof fetch,
        maximumBodyBytes: 4,
      })
    ).rejects.toThrow('Client credentials response rejected');
    expect(contentLengthCancellations).toHaveLength(1);

    await Promise.all(
      ['', '+4', '-0', '0x10', '1e2', '4, 5'].map(async (malformedLength) => {
        const cancellations: Array<true> = [];
        const malformedLengthBody = new ReadableStream<Uint8Array>({
          cancel() {
            // eslint-disable-next-line @silverhand/fp/no-mutating-methods -- The test records malformed content-length cancellation.
            cancellations.push(true);
          },
        });
        await expect(
          observeClientCredentialsToken(endpoint, jwks, baseRequest, {
            fetch: (async () =>
              new Response(malformedLengthBody, {
                headers: { 'content-length': malformedLength },
              })) as typeof fetch,
            maximumBodyBytes: 128,
          })
        ).rejects.toThrow('Client credentials response rejected');
        expect(cancellations).toHaveLength(1);
      })
    );

    const omittedHeaderCancellations: Array<true> = [];
    const omittedHeaderBody = new ReadableStream<Uint8Array>({
      cancel() {
        // eslint-disable-next-line @silverhand/fp/no-mutating-methods -- The test records omitted-header bound cancellation.
        omittedHeaderCancellations.push(true);
      },
    });
    await expect(
      observeClientCredentialsToken(endpoint, jwks, baseRequest, {
        fetch: (async () =>
          new Response(omittedHeaderBody, {
            headers: { 'set-cookie': 'x'.repeat(128) },
          })) as typeof fetch,
        maximumHeaderBytes: 32,
      })
    ).rejects.toThrow('Client credentials response rejected');
    expect(omittedHeaderCancellations).toHaveLength(1);

    const neverSettlingBody = new ReadableStream<Uint8Array>({
      cancel: async () =>
        new Promise<never>((resolve) => {
          if (typeof resolve !== 'function') {
            throw new TypeError('unreachable cancellation control');
          }
        }),
    });
    const boundedCancellation = observeClientCredentialsToken(endpoint, jwks, baseRequest, {
      fetch: (async () =>
        new Response(neverSettlingBody, {
          headers: { 'x-oversized': 'x'.repeat(128) },
        })) as typeof fetch,
      maximumHeaderBytes: 32,
    });
    await expect(
      Promise.race([
        boundedCancellation,
        new Promise((_resolve, reject) => {
          setTimeout(() => {
            reject(new Error('cancel timeout control failed'));
          }, 500);
        }),
      ])
    ).rejects.toThrow('Client credentials response rejected');
  });

  it('counts raw Unicode header bytes before redaction', async () => {
    const { jwks } = await createSigningFixture('unicode-header-key');

    await expect(
      observeClientCredentialsToken(endpoint, jwks, baseRequest, {
        fetch: (async () =>
          new Response(null, {
            status: 400,
            headers: { 'x-detail': 'é'.repeat(8) },
          })) as typeof fetch,
        maximumHeaderBytes: 24,
      })
    ).rejects.toThrow('Client credentials response rejected');
  });

  it.each([
    ['non-JSON body', new Response('not-json', { status: 200 })],
    ['missing access token', new Response('{"token_type":"Bearer"}', { status: 200 })],
    ['non-compact access token', successfulResponse('not-a-compact-token')],
  ])('rejects a malformed successful %s with a fixed error', async (_label, response) => {
    const { jwks } = await createSigningFixture('malformed-key');

    await expect(
      observeClientCredentialsToken(endpoint, jwks, baseRequest, {
        fetch: (async () => response) as typeof fetch,
      })
    ).rejects.toMatchObject({
      message: 'Client credentials response rejected',
      name: 'ClientCredentialsClientError',
    });
  });

  it('fails closed when a successful compact JWT is not verified by the pinned JWKS', async () => {
    const signed = await createSigningFixture('signing-key');
    const pinned = await createSigningFixture('different-key');
    const { requestFetch } = captureFetch(successfulResponse(signed.token));

    await expect(
      observeClientCredentialsToken(endpoint, pinned.jwks, baseRequest, { fetch: requestFetch })
    ).rejects.toMatchObject({
      message: 'Client credentials JWT verification failed',
      name: 'ClientCredentialsClientError',
    });
  });

  it('pins a closed JWKS snapshot before the request can mutate caller-owned keys', async () => {
    const pinned = await createSigningFixture('shared-key');
    const attacker = await createSigningFixture('shared-key');
    const requestFetch = (async () => {
      // eslint-disable-next-line @silverhand/fp/no-mutation -- The attacker mutation proves the client pinned a pre-request JWKS snapshot.
      pinned.jwks.keys[0] = attacker.jwks.keys[0]!;
      return successfulResponse(attacker.token);
    }) as typeof fetch;

    await expect(
      observeClientCredentialsToken(endpoint, pinned.jwks, baseRequest, { fetch: requestFetch })
    ).rejects.toThrow('Client credentials JWT verification failed');
  });

  it('rejects private or symmetric JWKS material before sending a request', async () => {
    const { jwks } = await createSigningFixture('public-key');
    const requests: Array<true> = [];
    const requestFetch = (async () => {
      // eslint-disable-next-line @silverhand/fp/no-mutating-methods -- The sentinel proves invalid key material is rejected before transport.
      requests.push(true);
      return new Response();
    }) as typeof fetch;

    await expect(
      observeClientCredentialsToken(
        endpoint,
        { keys: [{ ...jwks.keys[0]!, d: 'private' }] },
        baseRequest,
        { fetch: requestFetch }
      )
    ).rejects.toThrow('Client credentials request rejected');
    await expect(
      observeClientCredentialsToken(
        endpoint,
        { keys: [{ kty: 'oct', k: 'symmetric' }] },
        baseRequest,
        { fetch: requestFetch }
      )
    ).rejects.toThrow('Client credentials request rejected');
    expect(requests).toHaveLength(0);
  });

  it('uses a fixed secret-safe error when fetch fails', async () => {
    const { jwks, token } = await createSigningFixture('fetch-key');
    const authorization = `Basic ${Buffer.from(`${fixtureClientId}:${fixtureSecret}`).toString(
      'base64'
    )}`;
    const failingFetch = (async () => {
      throw new Error(`${fixtureSecret} ${authorization} ${token}`);
    }) as typeof fetch;
    const error = await observeClientCredentialsToken(
      endpoint,
      jwks,
      { ...baseRequest, method: 'client_secret_basic' },
      { fetch: failingFetch }
    ).catch((error_: unknown) => error_);

    expect(error).toBeInstanceOf(ClientCredentialsClientError);
    expect(String(error)).toBe('ClientCredentialsClientError: Client credentials request failed');
    expect(JSON.stringify(error)).not.toContain(fixtureSecret);
    expect(String(error)).not.toContain(token);
    expect(String(error)).not.toContain(authorization);

    const responseTrap = new Proxy(new Response('{}'), {
      get(_target, property) {
        if (property === 'headers') {
          throw new Error(`response-${fixtureSecret}`);
        }
        return Reflect.get(_target, property, _target) as unknown;
      },
    });
    const responseError = await observeClientCredentialsToken(endpoint, jwks, baseRequest, {
      fetch: (async () => responseTrap) as typeof fetch,
    }).catch((error_: unknown) => error_);
    expect(responseError).toBeInstanceOf(ClientCredentialsClientError);
    expect(String(responseError)).toBe(
      'ClientCredentialsClientError: Client credentials response rejected'
    );
    expect(String(responseError)).not.toContain(fixtureSecret);

    const cancellationTrapResponse = {
      get body() {
        return {
          get cancel() {
            throw new Error(`cancel-${fixtureSecret}`);
          },
          getReader: () => 'unreachable',
        };
      },
      get headers() {
        throw new Error(`headers-${fixtureSecret}`);
      },
      status: 500,
    } as unknown as Response;
    const cancellationTrapError = await observeClientCredentialsToken(endpoint, jwks, baseRequest, {
      fetch: (async () => cancellationTrapResponse) as typeof fetch,
    }).catch((error_: unknown) => error_);
    expect(cancellationTrapError).toBeInstanceOf(ClientCredentialsClientError);
    expect(String(cancellationTrapError)).toBe(
      'ClientCredentialsClientError: Client credentials response rejected'
    );
    expect(String(cancellationTrapError)).not.toContain(fixtureSecret);

    const statusReads: number[] = [];
    const changingStatusResponse = new Proxy(
      new Response('{"error":"invalid_client"}', {
        status: 401,
        headers: { 'content-type': 'application/json' },
      }),
      {
        get(target, property) {
          if (property === 'status') {
            // eslint-disable-next-line @silverhand/fp/no-mutating-methods -- The test records and varies an untrusted getter across reads.
            statusReads.push(statusReads.length + 1);
            return statusReads.length === 1 ? 401 : fixtureSecret;
          }
          return Reflect.get(target, property, target) as unknown;
        },
      }
    );
    const statusObservation = await observeClientCredentialsToken(endpoint, jwks, baseRequest, {
      fetch: (async () => changingStatusResponse) as typeof fetch,
    });
    expect(statusObservation.status).toBe(401);
    expect(statusReads).toEqual([1]);
    expect(JSON.stringify(statusObservation)).not.toContain(fixtureSecret);
  });
});
/* eslint-enable max-lines */
