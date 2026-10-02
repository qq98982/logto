/* eslint-disable @silverhand/fp/no-mutating-methods -- The request recorder is local test evidence. */
import { observeVerificationCode } from './verification-code.js';

const target = {
  label: 'candidate' as const,
  coreUrl: 'https://candidate.example/',
  adminUrl: 'https://candidate-admin.example/',
};

describe('Phase 2 verification-code request boundary', () => {
  it('projects a generated Experience handle without retaining it', async () => {
    const calls: Request[] = [];
    const requestFetch = (async (input: URL | RequestInfo, init?: RequestInit) => {
      calls.push(new Request(input, init));
      return new Response(JSON.stringify({ verificationId: 'generated-secret-handle' }), {
        status: 200,
        headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
      });
    }) as typeof fetch;

    const projection = await observeVerificationCode(
      {
        target,
        surface: 'experience',
        operation: 'request',
        identifier: 'owner@example.invalid',
        event: 'SignIn',
        cookie: 'interaction=opaque',
        clientId: 'browser-client',
      },
      requestFetch
    );

    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe(
      'https://candidate.example/api/experience/verification/verification-code'
    );
    expect(calls[0]?.headers.get('cookie')).toBe('interaction=opaque');
    expect(calls[0]?.headers.get('aster-app-id')).toBe('browser-client');
    expect(projection).toEqual({
      status: 200,
      contentType: 'application/json',
      cacheControl: 'no-store',
      outcome: 'created',
      handleField: 'verificationId',
      expiresAt: false,
    });
    expect(JSON.stringify(projection)).not.toContain('generated-secret-handle');
  });

  it('sends Account bearer authorization and accepts its distinct response vocabulary', async () => {
    const requestFetch = (async (_input: URL | RequestInfo, init?: RequestInit) => {
      expect(new Headers(init?.headers).get('authorization')).toBe('Bearer opaque-account-token');
      return new Response(
        JSON.stringify({
          verificationRecordId: 'generated-account-handle',
          expiresAt: '2026-10-02T12:00:00.000Z',
        }),
        { status: 201, headers: { 'content-type': 'application/json' } }
      );
    }) as typeof fetch;

    await expect(
      observeVerificationCode(
        {
          target,
          surface: 'account',
          operation: 'request',
          identifier: 'owner@example.invalid',
          bearer: 'opaque-account-token',
        },
        requestFetch
      )
    ).resolves.toMatchObject({
      status: 201,
      outcome: 'created',
      handleField: 'verificationRecordId',
      expiresAt: true,
    });
  });

  it('projects fixed errors and never publishes submitted code, handle, recipient, or bearer', async () => {
    const secretCode = '654321';
    const secretHandle = 'secret-verification-handle';
    const bearer = 'secret-bearer';
    const recipient = 'private@example.invalid';
    const requestFetch = (async () =>
      new Response(
        JSON.stringify({
          code: 'verification_code.code_mismatch',
          message: 'The verification request could not be completed.',
        }),
        { status: 400, headers: { 'content-type': 'application/json' } }
      )) as typeof fetch;

    const projection = await observeVerificationCode(
      {
        target,
        surface: 'account',
        operation: 'verify',
        identifier: recipient,
        handle: secretHandle,
        code: secretCode,
        bearer,
      },
      requestFetch
    );
    const published = JSON.stringify(projection);
    expect(projection).toMatchObject({
      status: 400,
      outcome: 'error',
      error: 'verification_code.code_mismatch',
    });
    for (const secret of [secretCode, secretHandle, bearer, recipient]) {
      expect(published).not.toContain(secret);
    }
  });

  it('rejects response bodies outside the closed created, verified, empty, and error shapes', async () => {
    const requestFetch = (async () =>
      new Response(JSON.stringify({ verificationId: 'handle', unexpected: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })) as typeof fetch;

    await expect(
      observeVerificationCode(
        {
          target,
          surface: 'experience',
          operation: 'request',
          identifier: 'owner@example.invalid',
          event: 'SignIn',
          cookie: 'interaction=opaque',
          clientId: 'browser-client',
        },
        requestFetch
      )
    ).rejects.toThrow('Invalid Phase 2 verification-code observation');
  });

  it('accepts only the exact controlled SMTP diagnostic data without publishing it', async () => {
    const referenceMessage =
      'Error occurred in connector: {"message":"Message failed: 550 controlled rejection"}';
    const response = (data: unknown) =>
      (async () =>
        new Response(
          JSON.stringify({ code: 'connector.general', message: referenceMessage, data }),
          { status: 400, headers: { 'content-type': 'application/json' } }
        )) as typeof fetch;
    const input = {
      target,
      surface: 'account' as const,
      operation: 'request' as const,
      identifier: 'owner@example.invalid',
      bearer: 'opaque-account-token',
    };

    const projection = await observeVerificationCode(
      input,
      response({ message: 'Message failed: 550 controlled rejection' })
    );
    expect(projection).toMatchObject({
      status: 400,
      error: 'connector.general',
      message: referenceMessage,
    });
    expect(projection.data).toEqual({ message: 'Message failed: 550 controlled rejection' });
    await expect(
      observeVerificationCode(input, response({ message: 'unknown provider diagnostic' }))
    ).rejects.toThrow('Invalid Phase 2 verification-code observation');
  });
});
/* eslint-enable @silverhand/fp/no-mutating-methods */
