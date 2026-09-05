/* eslint-disable max-lines -- Projection coverage keeps the complete composite envelope and its security regressions together. */
import { SignJWT, exportJWK, generateKeyPair } from 'jose';

import { SymbolTable } from '../../symbol-table.js';
import { createDifferentialEvidence } from '../evidence.js';
import { oracleCommit, phase0HarnessCommit } from '../model.js';
import { normalizeHeaders } from '../normalizers.js';

import {
  phase1ProjectionModuleIds,
  projectAccountObservation,
  projectAuthorizationObservation,
  projectConcurrencyObservation,
  projectConsentErrorObservation,
  projectConsentObservation,
  projectConsoleObservation,
  projectCookieObservation,
  projectCorsObservation,
  projectDiscoveryObservation,
  projectExperienceErrorObservation,
  projectHttpObservation,
  projectManagementObservation,
  projectOrganizationTokenObservation,
  projectRedirectObservation,
  projectSemanticStateObservation,
  projectTokenErrorObservation,
  projectTokenObservation,
  projectUserInfoObservation,
  verifyObservedJwt,
  type RawHttpObservation,
} from './index.js';

const context = {
  target: {
    label: 'candidate' as const,
    coreUrl: 'https://candidate.example.com/',
    adminUrl: 'https://candidate-console.example.com/',
  },
  symbols: new SymbolTable(),
};

const raw = (body: unknown): RawHttpObservation => ({
  status: 200,
  headers: [
    ['x-repeat', 'one'],
    ['X-Repeat', 'two'],
  ],
  body,
  semanticState: { grants: [] },
  sideEffects: { writes: 0 },
});

describe('phase 1 projections', () => {
  it('exports the exact eighteen focused projection modules', () => {
    expect(phase1ProjectionModuleIds).toEqual([
      'account',
      'authorization',
      'concurrency',
      'consent',
      'consent-error',
      'console',
      'cookie',
      'cors',
      'discovery',
      'experience-error',
      'http',
      'management',
      'organization-token',
      'redirect',
      'semantic-state',
      'token',
      'token-error',
      'userinfo',
    ]);
  });

  it('returns faithful JSON with complete duplicate header occurrences and no credentials', () => {
    const projection = projectHttpObservation(
      {
        status: 303,
        headers: [
          ['x-repeat', 'one'],
          ['X-Repeat', 'two'],
          ['content-type', 'application/json; charset=UTF-8'],
          ['set-cookie', 'interaction=private-cookie; Path=/; Secure; HttpOnly'],
          ['location', 'https://client.example/callback?code=private-code'],
        ],
        body: { accepted: true, endpoint: 'https://candidate.example.com/oidc/token' },
        semanticState: { grants: [] },
        sideEffects: { writes: 1 },
      },
      context
    );

    expect(projection.headers['x-repeat']).toEqual(['one', 'two']);
    expect(projection.mediaType).toMatchObject({ type: 'application', subtype: 'json' });
    expect(projection.error).toBeNull();
    expect(projection.body).toEqual({ accepted: true, endpoint: { $url: 0 } });
    expect(projection.urls).toEqual([
      {
        scheme: 'https',
        origin: '<target.core-url>',
        path: '/oidc/token',
        query: {},
        fragment: '',
        redactedParameters: [],
      },
    ]);
    expect(projection.cookies).toHaveLength(1);
    expect(projection.redirect).toMatchObject({ path: '/callback' });
    expect(projection.redirect?.origin).toBe('https://client.example');
    expect(projection.semanticState).toEqual({ grants: [] });
    expect(JSON.stringify(projection)).not.toMatch(/private-(?:cookie|code)/u);
  });

  it('canonicalizes configured issuer origins while keeping foreign issuers exact', () => {
    const targetProjection = projectHttpObservation(
      raw({
        issuer: 'https://candidate.example.com/oidc',
        iss: 'https://candidate-console.example.com/oidc',
      }),
      context
    );
    const foreignProjection = projectHttpObservation(
      raw({ issuer: 'https://foreign.example/oidc', iss: 'https://other.example/oidc' }),
      context
    );

    expect(targetProjection.body).toEqual({
      issuer: '<target.core-url>/oidc',
      iss: '<target.admin-url>/oidc',
    });
    expect(targetProjection.urls.map(({ origin, path }) => ({ origin, path }))).toEqual([
      { origin: '<target.core-url>', path: '/oidc' },
      { origin: '<target.admin-url>', path: '/oidc' },
    ]);
    expect(foreignProjection.body).toEqual({
      issuer: 'https://foreign.example/oidc',
      iss: 'https://other.example/oidc',
    });
    for (const nearMiss of [
      'https://candidate.example.com:443/oidc',
      'http://candidate.example.com/oidc',
      'https://candidate.example.com.attacker.test/oidc',
    ]) {
      expect(projectHttpObservation(raw({ issuer: nearMiss }), context).body).toEqual({
        issuer: nearMiss,
      });
    }
    expect(() =>
      projectHttpObservation(
        raw({ metadata: { issuer: 'https://candidate.example.com/oidc?code=private' } }),
        context
      )
    ).toThrow('Invalid phase 1 HTTP projection');
  });

  it('preserves validated nested header projections without bypassing credential scans', () => {
    const headers = normalizeHeaders(
      [
        ['x-upstream', 'https://foreign.example/resource'],
        [
          'www-authenticate',
          'Bearer realm="https://candidate-console.example.com/oidc", error="invalid_token"',
        ],
      ],
      context
    );
    const projection = projectHttpObservation(raw({ nested: { headers } }), context);

    expect(projection.body).toEqual({ nested: { headers } });
    expect(headers['www-authenticate']).toMatchObject([
      {
        challenges: [
          {
            parameters: [
              { name: 'realm', value: '<target.admin-url>/oidc', quoted: true },
              { name: 'error', value: 'invalid_token', quoted: true },
            ],
          },
        ],
      },
    ]);
    expect(() =>
      projectHttpObservation(
        raw({
          nested: {
            headers: { 'x-upstream': ['https://client.example/callback?code=private-code'] },
          },
        }),
        context
      )
    ).toThrow('Invalid phase 1 HTTP projection');
  });

  it('rejects non-faithful body values with a fixed diagnostic', () => {
    expect(() =>
      projectHttpObservation(
        {
          status: 200,
          headers: [],
          body: new Date(),
          semanticState: {},
          sideEffects: {},
        },
        context
      )
    ).toThrow('Invalid phase 1 HTTP projection');
  });

  it('rejects nested credential fields before a projection can escape', () => {
    expect(() =>
      projectHttpObservation(raw({ profile: { client_secret: 'private-value' } }), context)
    ).toThrow('Invalid phase 1 HTTP projection');
  });

  it('rejects raw ephemeral fields and credential-bearing issuer URLs', () => {
    for (const body of [
      { code: 'private-code' },
      { state: 'private-state' },
      { verificationId: 42 },
      { verificationCode: 123_456 },
      { issuer: 'https://private-user:private-password@issuer.example' },
      { nested: { jwk: { kty: 'oct', k: 'private-key-material' } } },
    ]) {
      expect(() => projectHttpObservation(raw(body), context)).toThrow(
        'Invalid phase 1 HTTP projection'
      );
    }
    expect(projectHttpObservation(raw({ verificationCode: true }), context).body).toEqual({
      verificationCode: true,
    });
  });

  it('projects a raw redirect without exposing its authorization code', () => {
    const projection = projectRedirectObservation(
      raw('https://client.example/callback?code=private-code&state=private-state'),
      context
    );
    expect(projection.body).toMatchObject({ path: '/callback' });
    expect(JSON.stringify(projection)).not.toContain('private-');
  });

  it('projects consent resume credentials only as one-time symbols', () => {
    const resumeUrl = 'https://candidate.example.com/oidc/auth/private-resume';
    const projection = projectConsentObservation(
      {
        ...raw({ redirectTo: resumeUrl }),
        headers: [['location', resumeUrl]],
      },
      context
    );

    expect(projection.redirect).toMatchObject({
      path: '/oidc/auth/{one-time-resume-credential}',
      resumeCredential: '<redirect.resume-credential.1>',
    });
    expect(projection.headers.location).toEqual([projection.redirect]);
    expect(projection.body).toMatchObject({
      redirectTo: { origin: '<target.core-url>' },
    });
    expect(JSON.stringify(projection)).not.toContain('private-resume');
  });

  it('auto-detects an unhinted target resume Location without leaking its path credential', () => {
    const resumeUrl = 'https://candidate.example.com/oidc/auth/unhinted-private-resume';
    const projection = projectHttpObservation(
      { ...raw({ accepted: true }), headers: [['location', resumeUrl]] },
      context
    );

    expect(projection.redirect?.path).toBe('/oidc/auth/{one-time-resume-credential}');
    expect(projection.redirect?.resumeCredential).toMatch(/^<redirect\.resume-credential\.\d+>$/u);
    expect(projection.headers.location).toEqual([projection.redirect]);
    expect(JSON.stringify(projection)).not.toContain('unhinted-private-resume');
  });

  it('requires every focused projector to return the complete observable envelope', () => {
    const projections = [
      projectAccountObservation(raw({ accepted: true }), context),
      projectAuthorizationObservation(raw({ accepted: true }), context),
      projectConcurrencyObservation(
        raw([
          { kind: 'success', winner: true },
          { kind: 'error', winner: false },
        ]),
        context
      ),
      projectConsentObservation(raw({ accepted: true }), context),
      projectConsentErrorObservation(raw({ error: 'invalid_request' }), context),
      projectConsoleObservation(raw({ accepted: true }), context),
      projectCookieObservation(raw(['interaction=value; Path=/; HttpOnly']), context),
      projectCorsObservation(raw({ accepted: true }), context),
      projectDiscoveryObservation(raw({ issuer: context.target.coreUrl }), context),
      projectExperienceErrorObservation(raw({ error: 'invalid_request' }), context),
      projectHttpObservation(raw({ accepted: true }), context),
      projectManagementObservation(raw({ accepted: true }), context),
      projectOrganizationTokenObservation(raw({ token_type: 'Bearer' }), context),
      projectRedirectObservation(raw('https://client.example/callback?code=private-code'), context),
      projectSemanticStateObservation(raw({ accepted: true }), context),
      projectTokenObservation(raw({ token_type: 'Bearer' }), context),
      projectTokenErrorObservation(raw({ error: 'invalid_grant' }), context),
      projectUserInfoObservation(raw({ sub: 'subject-1' }), context),
    ];

    for (const projection of projections) {
      expect(Object.keys(projection).toSorted()).toEqual([
        'body',
        'cookies',
        'error',
        'generatedIds',
        'headers',
        'mediaType',
        'outcomes',
        'persistedState',
        'redirect',
        'semanticState',
        'sideEffects',
        'status',
        'tokens',
        'urls',
      ]);
      expect(projection.headers['x-repeat']).toEqual(['one', 'two']);
      expect(projection.semanticState).toEqual({ grants: [] });
      expect(projection.sideEffects).toEqual({ writes: 0 });
    }
  });

  it('publishes stable concurrent results at the locked outcomes path', () => {
    const projection = projectConcurrencyObservation(
      raw([
        { kind: 'success', attempt: 'b' },
        { kind: 'error', attempt: 'a' },
      ]),
      context
    );

    expect(projection.body).toEqual({ $observation: 'outcomes' });
    expect(projection.outcomes).toEqual([
      { attempt: 'a', kind: 'error' },
      { attempt: 'b', kind: 'success' },
    ]);
  });

  it('normalizes runtime fixture IDs in focused bodies state and side effects', () => {
    const runtimeId = 'runtime-user-7f1a';
    context.symbols.bind('fixture.user.subject', runtimeId);
    const projection = projectManagementObservation(
      {
        ...raw({ id: runtimeId, description: `prefix ${runtimeId} suffix` }),
        semanticState: { subjectId: runtimeId },
        sideEffects: { affectedUserId: runtimeId },
      },
      context
    );

    expect(projection.body).toEqual({
      description: `prefix ${runtimeId} suffix`,
      id: '<fixture.user.subject>',
    });
    expect(projection.semanticState).toEqual({ subjectId: '<fixture.user.subject>' });
    expect(projection.sideEffects).toEqual({ affectedUserId: '<fixture.user.subject>' });
  });

  it('applies only caller-declared entity timestamp pointers', () => {
    const projection = projectManagementObservation(
      raw([{ createdAt: 1_000_000, updatedAt: 1_030_000, metadata: { createdAt: 990_000 } }]),
      context,
      { scenarioId: 'management.application-read', stepId: 'first-party' }
    );

    expect(projection.body).toEqual([
      {
        createdAt: { $timestamp: 1000, $toleranceSeconds: 30 },
        updatedAt: 1_030_000,
        metadata: { createdAt: 990_000 },
      },
    ]);
  });

  it('permits the contract-declared token family generated-ID metadata', () => {
    const projection = projectSemanticStateObservation(
      {
        ...raw({ families: 1 }),
        generatedIds: { tokenFamily: '<token-family.1>' },
      },
      context
    );

    expect(projection.generatedIds).toEqual({ tokenFamily: '<token-family.1>' });
  });

  it('normalizes the authorization session timestamp at its emitted semanticState path', () => {
    const projection = projectSemanticStateObservation(
      {
        ...raw({ observed: true }),
        semanticState: { session: { updatedAt: 1_000_000 } },
      },
      context,
      { scenarioId: 'authorization.password-pkce-consent', stepId: 'state' }
    );

    expect(projection.semanticState).toEqual({
      session: { updatedAt: { $timestamp: 1000, $toleranceSeconds: 30 } },
    });
  });

  it('verifies and lifts JWT observations while removing raw nonce credentials', async () => {
    const tokenContext = {
      target: context.target,
      symbols: new SymbolTable(),
    };
    const { privateKey, publicKey } = await generateKeyPair('RS256');
    const publicJwk = { ...(await exportJWK(publicKey)), kid: 'runtime-key', alg: 'RS256' };
    const compact = await new SignJWT({
      iss: 'https://issuer.example',
      aud: 'urn:api',
      scope: 'read',
      iat: 1000,
      exp: 4600,
      auth_time: 950,
      nonce: 'private-nonce',
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'runtime-key' })
      .sign(privateKey);
    const proof = await verifyObservedJwt(compact, { keys: [publicJwk] });

    expect(JSON.stringify(proof)).not.toContain(compact);
    expect(() =>
      projectTokenObservation(raw({ access_token: compact, token_type: 'Bearer' }), tokenContext, {
        coordinates: { scenarioId: 'token.authorization-code', stepId: 'token' },
      })
    ).toThrow('Invalid phase 1 token projection');
    const segments = compact.split('.');
    const signature = segments[2] ?? '';
    const tampered = `${segments[0]}.${segments[1]}.${signature.startsWith('A') ? 'B' : 'A'}${signature.slice(1)}`;
    await expect(verifyObservedJwt(tampered, { keys: [publicJwk] })).rejects.toThrow(
      'Invalid phase 1 observed JWT signature'
    );
    const projection = projectTokenObservation(
      raw({ access_token: compact, token_type: 'Bearer' }),
      tokenContext,
      {
        coordinates: { scenarioId: 'token.authorization-code', stepId: 'token' },
        verifiedJwts: [proof],
      }
    );

    expect(projection.body).toMatchObject({ access: { $observation: 0 }, tokenType: 'Bearer' });
    expect(projection.tokens).toEqual([
      {
        kind: 'access',
        format: 'jwt',
        signatureVerified: true,
        header: { alg: 'RS256', kid: '<signing-key.kid.1>' },
        claims: {
          iss: 'https://issuer.example',
          aud: 'urn:api',
          scope: 'read',
          iat: { $timestamp: 1000, $toleranceSeconds: 30 },
          exp: { $timestamp: 4600, $toleranceSeconds: 30 },
          auth_time: { $timestamp: 950, $toleranceSeconds: 30 },
          tokenLifetimeSeconds: 3600,
        },
      },
    ]);
    expect(JSON.stringify(projection)).not.toContain('private-nonce');
    expect(JSON.stringify(projection)).not.toContain('"nonce"');
    expect(
      createDifferentialEvidence({
        scenarioId: 'token.authorization-code',
        provenance: { referenceCommit: oracleCommit, harnessCommit: phase0HarnessCommit },
        oracle: {
          target: 'oracle',
          observations: [{ stepId: 'token', kind: 'http', value: projection }],
        },
        candidate: {
          target: 'candidate',
          observations: [{ stepId: 'token', kind: 'http', value: projection }],
        },
        differences: [],
      }).oracle.observations[0]?.value
    ).toMatchObject({ tokens: projection.tokens });

    const refreshProjection = projectTokenObservation(
      raw({ access_token: compact, token_type: 'Bearer' }),
      tokenContext,
      {
        coordinates: { scenarioId: 'token.refresh-rotation', stepId: 'refresh-token' },
        verifiedJwts: [proof],
      }
    );
    expect(refreshProjection.tokens[0]).toMatchObject({
      claims: {
        iat: { $timestamp: 1000, $toleranceSeconds: 30 },
        exp: { $timestamp: 4600, $toleranceSeconds: 30 },
        auth_time: { $timestamp: 950, $toleranceSeconds: 30 },
      },
    });
  });

  it('keeps a three-segment non-JWT access token opaque without a JWT proof', () => {
    const projection = projectTokenObservation(
      raw({ access_token: 'not-json.payload.signature', token_type: 'Bearer' }),
      { target: context.target, symbols: new SymbolTable() }
    );

    expect(projection.tokens).toEqual([
      {
        kind: 'access',
        format: 'opaque',
        characterCount: 'not-json.payload.signature'.length,
      },
    ]);
  });
});

/* eslint-enable max-lines */
