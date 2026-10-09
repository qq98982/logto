/* eslint-disable max-lines, max-params, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The tracked JavaScript launcher is intentionally exercised through its native ESM exports, closed diagnostics, five-part execution dependency, and mutable call-order controls. */
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, lstat, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

import {
  computeRuntimeBundleIdentity,
  computeRuntimeBundleManifest,
  createRuntimeBootstrap,
  createRuntimeHookImport,
  executeVerifiedPhase2Entry,
  diagnosticForPhase2Child,
  diagnosticForPhase2ChildResult,
  diagnosticForPhase2Batch,
  readPhase2GoogleProviderEnvironment,
  readPhase2WechatProviderEnvironment,
  launchPhase2,
  launchPhase2Batch,
  writeClosedChildDiagnostic,
} from './launcher.mjs';
import { computePhase2RuntimeBundleIdentity } from './provenance.js';

const executeFile = promisify(execFile);

const browserEnvironmentKeys = [
  'HOME',
  'PLAYWRIGHT_BROWSERS_PATH',
  'TMPDIR',
  'XDG_RUNTIME_DIR',
] as const;
const originalBrowserEnvironment = Object.fromEntries(
  browserEnvironmentKeys.map((key) => [key, process.env[key]])
);
let browserEnvironmentRoot = '';

beforeAll(async () => {
  browserEnvironmentRoot = await mkdtemp('/var/tmp/henry-build/phase2-launcher-browser-');
  const runDirectory = path.join(browserEnvironmentRoot, 'aster-phase2-live', 'run.test');
  const values = {
    HOME: path.join(runDirectory, 'home'),
    PLAYWRIGHT_BROWSERS_PATH: path.join(browserEnvironmentRoot, 'aster-playwright-browsers'),
    TMPDIR: path.join(runDirectory, 'browser-tmp'),
    XDG_RUNTIME_DIR: path.join(runDirectory, 'xdg-runtime'),
  };
  await Promise.all(
    Object.values(values).map(async (value) => mkdir(value, { mode: 0o700, recursive: true }))
  );
  for (const [key, value] of Object.entries(values)) {
    process.env[key] = value;
  }
});

afterAll(async () => {
  for (const key of browserEnvironmentKeys) {
    const value = originalBrowserEnvironment[key];
    if (value === undefined) {
      Reflect.deleteProperty(process.env, key);
    } else {
      process.env[key] = value;
    }
  }
  await rm(browserEnvironmentRoot, { force: true, recursive: true });
});

describe('Phase 2 tracked launcher', () => {
  it('writes only a closed cleanup diagnostic into the owned temporary root', async () => {
    const root = await mkdtemp('/var/tmp/henry-build/phase2-closed-diagnostic-');
    const diagnostic =
      'Phase 2 client credentials command failed (candidate-fixture-cleanup-first).\n';
    expect(writeClosedChildDiagnostic(['differential', '--temp-root', root], diagnostic)).toBe(
      true
    );
    const file = path.join(root, '.closed-child-diagnostic');
    await expect(readFile(file, 'utf8')).resolves.toBe(diagnostic);
    const state = await lstat(file);
    expect(state.nlink).toBe(1);
    expect(state.mode % 512).toBe(0o600);
    expect(writeClosedChildDiagnostic(['differential', '--temp-root', root], 'private')).toBe(
      false
    );
    await rm(root, { recursive: true });
  });
  it('passes closed custom JWT failure details through the child result boundary', () => {
    for (const stage of [
      'candidate-custom-jwt-19:http-500',
      'oracle-custom-jwt-19:issuance-token-http',
      'candidate-custom-jwt-19:issuance-bridge-http-502',
    ]) {
      const stderr = `Phase 2 client credentials command failed (${stage}).\n`;
      expect(diagnosticForPhase2Child(stderr)).toBe(stderr);
      expect(
        diagnosticForPhase2ChildResult({ code: 1, signal: null, timedOut: false, stderr })
      ).toBe(stderr);
    }
    for (const stderr of [
      'Phase 2 client credentials command failed (candidate-custom-jwt-19:http-999).\n',
      'Phase 2 client credentials command failed (candidate-custom-jwt-19:issuance-private-secret).\n',
      'Phase 2 client credentials command failed (candidate-custom-jwt-19:http-500).\nprivate-secret',
    ]) {
      expect(diagnosticForPhase2Child(stderr)).toBe(
        'Phase 2 client credentials launcher failed.\n'
      );
      const closedPrefix = stderr.endsWith('\nprivate-secret')
        ? 'Phase 2 client credentials command failed (candidate-custom-jwt-19:http-500).\n'
        : '';
      expect(
        diagnosticForPhase2ChildResult({ code: 1, signal: null, timedOut: false, stderr })
      ).toBe(
        `${closedPrefix}Phase 2 client credentials launcher child failed (stderr-bytes-${String(Buffer.byteLength(stderr))}-sha256-${createHash('sha256').update(stderr).digest('hex')}).\n`
      );
    }
  });

  it('identifies only closed batch failure modes', async () => {
    expect(diagnosticForPhase2Batch(new Error('differential'))).toBe(
      'Phase 2 client credentials batch failed (differential).\n'
    );
    expect(diagnosticForPhase2Batch(new Error('differential\nsecret'))).toBe(
      'Phase 2 client credentials launcher failed.\n'
    );
    expect(diagnosticForPhase2Batch(new TypeError('Invalid Phase 2 launcher'))).toBe(
      'Phase 2 client credentials launcher failed.\n'
    );
    const head = '1'.repeat(40);
    const tree = '2'.repeat(40);
    const sha256 = '3'.repeat(64);
    const calls: string[] = [];
    await expect(
      launchPhase2Batch([['oracle'], ['differential']], {
        inspect: async () => ({ head, tree }),
        build: async () => {
          calls.push('build');
        },
        identity: async () => ({
          sha256,
          moduleCount: 1,
          entryUrl: 'file:///private/lib/compatibility/phase-2/cli.js',
          libraryRootUrl: 'file:///private/lib/',
          modules: { 'file:///private/lib/compatibility/phase-2/cli.js': sha256 },
        }),
        execute: async (_entry: string, command: readonly string[]) => {
          calls.push(command[0] ?? 'unknown');
          return command[0] === 'differential' ? 1 : 0;
        },
      })
    ).rejects.toThrow('differential');
    expect(calls).toEqual(['build', 'oracle', 'differential']);
  });
  // eslint-disable-next-line complexity -- This table exercises the complete closed diagnostic grammar.
  it('forwards only closed scenario failure identifiers from the child', () => {
    for (const stage of [
      'prepare',
      'approval',
      'issuance',
      'evidence-open',
      'evidence-values',
      'evidence-validation',
      'evidence-lease',
      'driver-unclassified',
    ]) {
      const message = `Phase 2 client credentials command failed (candidate-invariant-device-7-${stage}).\n`;
      expect(diagnosticForPhase2Child(message)).toBe(message);
      expect(diagnosticForPhase2Child(`${message}private-value`)).toBe(
        'Phase 2 client credentials launcher failed.\n'
      );
    }
    expect(
      diagnosticForPhase2Child(
        'Phase 2 client credentials command failed (candidate/client-credentials.basic-explicit-resource).\n'
      )
    ).toBe(
      'Phase 2 client credentials command failed (candidate/client-credentials.basic-explicit-resource).\n'
    );
    expect(
      diagnosticForPhase2Child(
        'Phase 2 client credentials command failed (candidate/client-credentials.basic-explicit-resource).\nprivate-key'
      )
    ).toBe('Phase 2 client credentials launcher failed.\n');
    expect(
      diagnosticForPhase2Child(
        'Phase 2 client credentials command failed (candidate/client-credentials.injected-secret).\n'
      )
    ).toBe('Phase 2 client credentials launcher failed.\n');
    expect(
      diagnosticForPhase2Child('Phase 2 client credentials command failed (candidate-fixture).\n')
    ).toBe('Phase 2 client credentials command failed (candidate-fixture).\n');
    for (const diagnostic of [
      'candidate-fixture-provision',
      'candidate-fixture-readiness',
      'candidate-fixture-public-jwks',
      'candidate-admin-consumer-unknown',
      'candidate-fixture-cleanup',
      'candidate-fixture-body-cleanup',
      ...Array.from({ length: 6 }, (_, index) => `oracle-custom-jwt-fetch-${index}`),
      ...Array.from({ length: 6 }, (_, index) => `candidate-custom-jwt-fetch-${index}`),
      ...Array.from({ length: 5 }, (_, index) => `candidate-invariant-legacy-${index}`),
    ]) {
      const message = `Phase 2 client credentials command failed (${diagnostic}).\n`;
      expect(diagnosticForPhase2Child(message)).toBe(message);
    }
    for (const diagnostic of [
      'candidate-custom-jwt-fetch-6',
      'candidate-custom-jwt-fetch-01',
      'candidate-custom-jwt-fetch-0-private',
      'candidate-invariant-legacy-5',
      'candidate-invariant-legacy-00',
      'candidate-invariant-legacy-0-private-secret',
    ]) {
      expect(
        diagnosticForPhase2Child(`Phase 2 client credentials command failed (${diagnostic}).\n`)
      ).toBe('Phase 2 client credentials launcher failed.\n');
    }
    expect(
      diagnosticForPhase2Child(
        'Phase 2 client credentials command failed (candidate-custom-jwt-fetch-0).\nprivate'
      )
    ).toBe('Phase 2 client credentials launcher failed.\n');
    expect(
      diagnosticForPhase2Child(
        'Phase 2 client credentials command failed (candidate-admin-bearer-management-refresh).\n'
      )
    ).toBe(
      'Phase 2 client credentials command failed (candidate-admin-bearer-management-refresh).\n'
    );
    for (const suffix of [':private\n', '\nprivate', '-private).\n']) {
      expect(
        diagnosticForPhase2Child(
          `Phase 2 client credentials command failed (candidate-admin-bearer-jwks).${suffix}`
        )
      ).toBe('Phase 2 client credentials launcher failed.\n');
    }
    expect(
      diagnosticForPhase2Child(
        'Phase 2 client credentials command failed (differential-cleanup).\n'
      )
    ).toBe('Phase 2 client credentials command failed (differential-cleanup).\n');
    expect(
      diagnosticForPhase2Child(
        'Phase 2 client credentials command failed (differential-target-verify).\n'
      )
    ).toBe('Phase 2 client credentials command failed (differential-target-verify).\n');
    expect(
      diagnosticForPhase2Child(
        'Phase 2 client credentials command failed (oracle/token-status.public-access-active).\n'
      )
    ).toBe(
      'Phase 2 client credentials command failed (oracle/token-status.public-access-active).\n'
    );
    expect(
      diagnosticForPhase2Child(
        'Phase 2 client credentials command failed (oracle/token-status.public-refresh-active).\n'
      )
    ).toBe(
      'Phase 2 client credentials command failed (oracle/token-status.public-refresh-active).\n'
    );
    expect(
      diagnosticForPhase2Child(
        'Phase 2 client credentials command failed (oracle/token-status.unregistered).\n'
      )
    ).toBe('Phase 2 client credentials launcher failed.\n');
    expect(
      diagnosticForPhase2Child(
        'Phase 2 client credentials command failed (candidate/common.native.code-pkce).\n'
      )
    ).toBe('Phase 2 client credentials command failed (candidate/common.native.code-pkce).\n');
    expect(
      diagnosticForPhase2Child(
        'Phase 2 client credentials command failed (candidate/common.native.code-pkce:private).\n'
      )
    ).toBe('Phase 2 client credentials launcher failed.\n');
    expect(
      diagnosticForPhase2Child(
        'Phase 2 client credentials command failed (candidate/common.email.password-sign-in).\n'
      )
    ).toBe(
      'Phase 2 client credentials command failed (candidate/common.email.password-sign-in).\n'
    );
    expect(
      diagnosticForPhase2Child(
        'Phase 2 client credentials command failed (candidate/common.email.password-sign-in:private).\n'
      )
    ).toBe('Phase 2 client credentials launcher failed.\n');
    expect(
      diagnosticForPhase2Child(
        'Phase 2 client credentials command failed (candidate/common.email.code-sign-in).\n'
      )
    ).toBe('Phase 2 client credentials command failed (candidate/common.email.code-sign-in).\n');
    expect(
      diagnosticForPhase2Child(
        'Phase 2 client credentials command failed (candidate/common.email.code-sign-in:private).\n'
      )
    ).toBe('Phase 2 client credentials launcher failed.\n');
    for (const side of ['oracle', 'candidate']) {
      const message = `Phase 2 client credentials command failed (${side}/common.email.code-registration).\n`;
      expect(diagnosticForPhase2Child(message)).toBe(message);
    }
    expect(
      diagnosticForPhase2Child(
        'Phase 2 client credentials command failed (candidate/common.email.code-registration:private).\n'
      )
    ).toBe('Phase 2 client credentials launcher failed.\n');
    expect(
      diagnosticForPhase2Child(
        'Phase 2 client credentials command failed (candidate/common.email.code-registration-extra).\n'
      )
    ).toBe('Phase 2 client credentials launcher failed.\n');
    for (const id of [
      'device-authorization.urlencoded-success',
      'device-token.concurrent-reference-multi-winner',
      'device-discovery.oauth',
    ]) {
      const message = `Phase 2 client credentials command failed (candidate/${id}).\n`;
      expect(diagnosticForPhase2Child(message)).toBe(message);
    }
    for (const stage of [
      'lifecycle-request',
      'lifecycle-response',
      'token-response',
      'credential-lease',
      'projection',
      'scenario',
    ]) {
      const message = `Phase 2 client credentials command failed (oracle/device-token.refresh-resource-selection:${stage}).\n`;
      expect(diagnosticForPhase2Child(message)).toBe(message);
    }
    const projectionField =
      'Phase 2 client credentials command failed (candidate/device-verification.already-used-code:projection-cookies).\n';
    expect(diagnosticForPhase2Child(projectionField)).toBe(projectionField);
    const consentSequenceProjectionField =
      'Phase 2 client credentials command failed (candidate/device-consent.first-party-matching-grant-required:projection-completion-cookies).\n';
    expect(diagnosticForPhase2Child(consentSequenceProjectionField)).toBe(
      consentSequenceProjectionField
    );
    for (const stage of [
      'id-claimKeys',
      'id-claimTypes-email_verified',
      'id-signature',
      'id-other',
    ]) {
      const message = `Phase 2 client credentials command failed (candidate/device-token.id-token-signature-and-claims:projection-${stage}).\n`;
      expect(diagnosticForPhase2Child(message)).toBe(message);
    }
    const claimKeysDifference =
      'Phase 2 client credentials command failed (candidate/device-token.refresh-organization-selection:projection-id-claimKeys).\n' +
      'Phase 2 device ID claimKeys differ (only on oracle: acr,amr,organizations; only on candidate: none).\n';
    expect(diagnosticForPhase2Child(claimKeysDifference)).toBe(claimKeysDifference);
    expect(
      diagnosticForPhase2ChildResult({
        timedOut: false,
        signal: null,
        code: 1,
        stdout: '',
        stderr: claimKeysDifference,
      })
    ).toBe(claimKeysDifference);
    for (const message of [
      claimKeysDifference.replace('organizations', 'private-token'),
      claimKeysDifference.replace('projection-id-claimKeys', 'projection-id-signature'),
      claimKeysDifference + 'private-value\n',
    ]) {
      expect(diagnosticForPhase2Child(message)).toBe(
        'Phase 2 client credentials launcher failed.\n'
      );
    }
    for (const stage of [
      'approval',
      'approval-authorize',
      'approval-capture',
      'approval-verify',
      'approval-experience-open',
      'approval-password',
      'approval-identification',
      'approval-experience-submit',
      'approval-resume-initial',
      'approval-consent-read',
      'approval-consent-write',
      'approval-resume-final',
      'transition',
      'verification-get',
      'verification-post',
    ]) {
      const message = `Phase 2 client credentials command failed (candidate/device-verification.already-used-code:${stage}).\n`;
      expect(diagnosticForPhase2Child(message)).toBe(message);
    }
    const lifecycleMessage =
      'Phase 2 client credentials command failed (candidate/device-token-status.access-revocation:projection-sequence-siblingAfter-headers).\n';
    expect(diagnosticForPhase2Child(lifecycleMessage)).toBe(lifecycleMessage);
    expect(
      diagnosticForPhase2ChildResult({
        timedOut: false,
        signal: null,
        code: 1,
        stdout: '',
        stderr: lifecycleMessage,
      })
    ).toBe(lifecycleMessage);
    const sessionExpiryMessage =
      'Phase 2 client credentials command failed (oracle/device-token.session-bound-expiry:projection-sequence-after-oauthError).\n';
    expect(diagnosticForPhase2Child(sessionExpiryMessage)).toBe(sessionExpiryMessage);
    for (const message of [
      'Phase 2 client credentials command failed (oracle/device-token.refresh-resource-selection:unknown-marker).\n',
      'Phase 2 client credentials command failed (oracle/device-token.refresh-resource-selection:credential-lease:private-marker).\n',
      'Phase 2 client credentials command failed (oracle/device-token.unregistered:credential-lease).\n',
      'Phase 2 client credentials command failed (oracle/device-token.refresh-resource-selection:credential-lease).\nextra-marker',
      'Phase 2 client credentials command failed (candidate/device-verification.already-used-code:projection-private).\n',
      'Phase 2 client credentials command failed (candidate/device-verification.already-used-code:projection-cookies:private-marker).\n',
      'Phase 2 client credentials command failed (candidate/device-consent.first-party-matching-grant-required:projection-completion-private).\n',
      'Phase 2 client credentials command failed (candidate/device-token.id-token-signature-and-claims:projection-id-claimTypes-private-token).\n',
      'Phase 2 client credentials command failed (candidate/device-token.id-token-signature-and-claims:projection-id-signature:private-marker).\n',
      'Phase 2 client credentials command failed (candidate/device-verification.already-used-code:approval:private-marker).\n',
      'Phase 2 client credentials command failed (candidate/device-verification.already-used-code:approval-password:private-marker).\n',
      'Phase 2 client credentials command failed (candidate/device-token-status.access-revocation:projection-sequence-private-headers).\n',
      'Phase 2 client credentials command failed (candidate/device-token-status.access-revocation:projection-sequence-siblingAfter-private).\n',
      'Phase 2 client credentials command failed (candidate/device-token-status.access-revocation:projection-sequence-siblingAfter-headers:private-marker).\n',
    ]) {
      expect(diagnosticForPhase2Child(message)).toBe(
        'Phase 2 client credentials launcher failed.\n'
      );
    }
    expect(
      diagnosticForPhase2Child(
        'Phase 2 client credentials command failed (candidate/device-token.unregistered).\n'
      )
    ).toBe('Phase 2 client credentials launcher failed.\n');
    expect(
      diagnosticForPhase2Child(
        'Phase 2 client credentials command failed (oracle-status-token-http).\n'
      )
    ).toBe('Phase 2 client credentials command failed (oracle-status-token-http).\n');
    expect(
      diagnosticForPhase2Child(
        'Phase 2 client credentials command failed (candidate-status-bridge-http-200).\n'
      )
    ).toBe('Phase 2 client credentials command failed (candidate-status-bridge-http-200).\n');
    expect(
      diagnosticForPhase2Child(
        'Phase 2 client credentials command failed (candidate-status-bridge-http-503).\n'
      )
    ).toBe('Phase 2 client credentials command failed (candidate-status-bridge-http-503).\n');
    expect(
      diagnosticForPhase2Child(
        'Phase 2 client credentials command failed (candidate-status-bridge-http-private).\n'
      )
    ).toBe('Phase 2 client credentials launcher failed.\n');
    expect(
      diagnosticForPhase2Child(
        'Phase 2 client credentials command failed (candidate-status-comparison-body).\n'
      )
    ).toBe('Phase 2 client credentials command failed (candidate-status-comparison-body).\n');
    expect(
      diagnosticForPhase2Child(
        'Phase 2 client credentials command failed (candidate-status-comparison-body-scope).\n'
      )
    ).toBe('Phase 2 client credentials command failed (candidate-status-comparison-body-scope).\n');
    expect(
      diagnosticForPhase2Child(
        'Phase 2 client credentials command failed (candidate-status-case-8-body).\n'
      )
    ).toBe('Phase 2 client credentials command failed (candidate-status-case-8-body).\n');
    expect(
      diagnosticForPhase2Child(
        'Phase 2 client credentials command failed (candidate-status-scope-1-short-full).\n'
      )
    ).toBe('Phase 2 client credentials command failed (candidate-status-scope-1-short-full).\n');
    expect(
      diagnosticForPhase2Child(
        'Phase 2 client credentials command failed (differential-private).\n'
      )
    ).toBe('Phase 2 client credentials launcher failed.\n');
    expect(
      diagnosticForPhase2Child('Phase 2 client credentials command failed (candidate-private).\n')
    ).toBe('Phase 2 client credentials launcher failed.\n');
  });
  it('forwards only closed sanitizer substage diagnostics from the child', () => {
    for (const prefix of ['oracle', 'candidate']) {
      for (const suffix of [
        'target',
        'discovery',
        'controls',
        'ids',
        'client-0',
        'client-175',
        'device-0',
        'device-175',
        'native-176',
        'email-177',
        'code-178',
      ]) {
        const message = `Phase 2 client credentials command failed (${prefix}-sanitizer-${suffix}).\n`;
        expect(diagnosticForPhase2Child(message)).toBe(message);
      }
    }

    for (const suffix of [
      'client-00',
      'client-176',
      'device-01',
      'device-176',
      'native-175',
      'code-177',
      'code-178-private',
      'native-177',
      'target-extra',
      'private-value',
    ]) {
      expect(
        diagnosticForPhase2Child(
          `Phase 2 client credentials command failed (oracle-sanitizer-${suffix}).\n`
        )
      ).toBe('Phase 2 client credentials launcher failed.\n');
    }
    expect(
      diagnosticForPhase2Child(
        'Phase 2 client credentials command failed (oracle-sanitizer-target).\nprivate-value'
      )
    ).toBe('Phase 2 client credentials launcher failed.\n');
  });
  it('forwards only exact closed custom JWT stage diagnostics from the child', () => {
    for (const target of ['oracle', 'candidate']) {
      for (const suffix of ['', '-0', '-23']) {
        const message = `Phase 2 client credentials command failed (${target}-custom-jwt${suffix}).\n`;
        expect(diagnosticForPhase2Child(message)).toBe(message);
        expect(
          diagnosticForPhase2ChildResult({
            code: 1,
            signal: null,
            stdout: '',
            stderr: message,
            timedOut: false,
          })
        ).toBe(message);
        expect(diagnosticForPhase2Child(`${message}private-value`)).toBe(
          'Phase 2 client credentials launcher failed.\n'
        );
      }
      for (const suffix of ['-24', '-01', '-0-private']) {
        expect(
          diagnosticForPhase2Child(
            `Phase 2 client credentials command failed (${target}-custom-jwt${suffix}).\n`
          )
        ).toBe('Phase 2 client credentials launcher failed.\n');
      }
    }
  });
  it('forwards only exact custom JWT device refresh stages for scenario 22', () => {
    for (const target of ['oracle', 'candidate']) {
      for (const stage of [
        'authorize',
        'approval-authorize',
        'approval-capture',
        'approval-verify',
        'approval-experience-open',
        'approval-password',
        'approval-identification',
        'approval-experience-submit',
        'approval-resume-initial',
        'approval-consent-read',
        'approval-consent-write',
        'approval-resume-final',
        'token-poll',
        'initial-lease',
        'refresh-request',
        'refresh-http',
        'jwt-verify',
        'projection',
      ]) {
        const message = `Phase 2 client credentials command failed (${target}-custom-jwt-22:${stage}).\n`;
        expect(diagnosticForPhase2Child(message)).toBe(message);
      }
    }
    for (const diagnostic of [
      'oracle-custom-jwt-21:authorize',
      'candidate-custom-jwt-23:projection',
      'oracle-custom-jwt-22:unknown',
      'oracle-custom-jwt-22:approval-unknown',
      'oracle-custom-jwt-22:approval-password:private-value',
      'candidate-custom-jwt-22:jwt-verify:private-value',
    ]) {
      expect(
        diagnosticForPhase2Child(`Phase 2 client credentials command failed (${diagnostic}).\n`)
      ).toBe('Phase 2 client credentials launcher failed.\n');
    }
  });
  it('forwards only closed device candidate-invariant stages from the child', () => {
    for (const stage of [
      'candidate-invariant-device-0',
      'candidate-invariant-device-1-row-missing',
      'candidate-invariant-device-1-schema-query',
      'candidate-invariant-device-2-foreign-poll-authorization-pending',
      'candidate-invariant-device-2-abort',
      'candidate-invariant-device-2-response',
      'candidate-invariant-device-7',
      'candidate-invariant-device-7-scan-query',
      'candidate-invariant-device-7-normalized-match',
    ]) {
      const message = `Phase 2 client credentials command failed (${stage}).\n`;
      expect(diagnosticForPhase2Child(message)).toBe(message);
    }
    for (const stage of [
      'candidate-invariant-device-8',
      'candidate-invariant-device-private',
      'candidate-invariant-device-1-unknown',
      'candidate-invariant-device-2-unknown',
      'candidate-invariant-device-7-unknown',
      'candidate-invariant-device-7-normalized-match:private-marker',
      'oracle-invariant-device-1-row-missing',
      'oracle-invariant-device-0',
    ]) {
      expect(
        diagnosticForPhase2Child(`Phase 2 client credentials command failed (${stage}).\n`)
      ).toBe('Phase 2 client credentials launcher failed.\n');
    }
  });
  it('classifies abnormal child results without forwarding child output', () => {
    expect(
      diagnosticForPhase2ChildResult({
        code: null,
        signal: 'SIGTERM',
        stdout: 'private stdout',
        stderr: 'private stderr',
        timedOut: true,
      })
    ).toBe('Phase 2 client credentials launcher child failed (timeout).\n');
    expect(
      diagnosticForPhase2ChildResult({
        code: null,
        signal: 'SIGKILL',
        stdout: '',
        stderr: '',
        timedOut: false,
      })
    ).toBe('Phase 2 client credentials launcher child failed (signal).\n');
    expect(
      diagnosticForPhase2ChildResult({
        code: 1,
        signal: null,
        stdout: '',
        stderr: 'private stderr',
        timedOut: false,
      })
    ).toBe(
      `Phase 2 client credentials launcher child failed (stderr-bytes-${String(Buffer.byteLength('private stderr'))}-sha256-${createHash('sha256').update('private stderr').digest('hex')}).\n`
    );
    expect(
      diagnosticForPhase2ChildResult({
        code: 7,
        signal: null,
        stdout: 'private stdout',
        stderr: '',
        timedOut: false,
      })
    ).toBe('Phase 2 client credentials launcher child failed (exit-code).\n');
    const named =
      'Phase 2 client credentials command failed (oracle/client-credentials.basic-explicit-resource).\n';
    expect(
      diagnosticForPhase2ChildResult({
        code: 1,
        signal: null,
        stdout: '',
        stderr: named,
        timedOut: false,
      })
    ).toBe(named);
  });
  it.each([
    'oracle/common.email.password-registration',
    'candidate/common.password.recovery',
    'oracle/common.google.existing-owner',
    'oracle-common-ready-password-registration-controls-incomplete-identification',
    'candidate-common-ready-recovery-flow-new-password-reset',
    'oracle-common-ready-google-wrong-state-provider',
    'oracle-common-ready-wechat-web-context-after-flow',
  ])('preserves exact new Common child diagnostic %s', (detail) => {
    const diagnostic = `Phase 2 client credentials command failed (${detail}).\n`;
    expect(
      diagnosticForPhase2ChildResult({
        code: 1,
        signal: null,
        stdout: '',
        stderr: diagnostic,
        timedOut: false,
      })
    ).toBe(diagnostic);
    const privateDiagnostic = `Phase 2 client credentials command failed (${detail}:private-token).\n`;
    expect(
      diagnosticForPhase2ChildResult({
        code: 1,
        signal: null,
        stdout: '',
        stderr: privateDiagnostic,
        timedOut: false,
      })
    ).not.toBe(privateDiagnostic);
  });

  it.each([
    'unverified-email-control-profile-route',
    'occupied-email-control-link-complete',
    'unverified-email-control-unknown-identification-422',
    'occupied-email-control-rejected-resume-303-session.interaction_not_found',
    'occupied-email-control-invalid-status-identification-422-user.missing_profile',
    'unverified-email-control-disallowed-error-identification-404-session.identity_conflict',
  ])('preserves closed Google registration control diagnostic %s', (stage) => {
    const diagnostic = `Phase 2 client credentials command failed (oracle-common-ready-google-registration-${stage}).\n`;
    expect(diagnosticForPhase2Child(diagnostic)).toBe(diagnostic);
    expect(diagnosticForPhase2Child(`${diagnostic}private-token`)).not.toContain('private-token');
  });

  it('preserves only multi-line diagnostics whose every line is independently closed', () => {
    const google =
      'Phase 2 client credentials command failed (oracle-common-ready-google-registration-occupied-email-owner).\n';
    const cleanup =
      'Phase 2 client credentials command failed (oracle-common-ready-google-registration-cleanup).\n';
    expect(diagnosticForPhase2Child(`${google}${cleanup}`)).toBe(`${google}${cleanup}`);
    expect(diagnosticForPhase2Child(`${google}private-token\n`)).not.toContain('private-token');
  });

  it('preserves closed lines and hashes the rest of mixed child stderr', () => {
    const known =
      'Phase 2 client credentials command failed (oracle-common-ready-google-registration-occupied-email-owner).\n';
    const stderr = `${known}private-token\n`;
    const result: unknown = diagnosticForPhase2ChildResult({
      code: 1,
      signal: null,
      stdout: '',
      stderr,
      timedOut: false,
    });
    expect(result).toContain(known);
    expect(result).toContain(`stderr-bytes-${String(Buffer.byteLength(stderr))}-sha256-`);
    expect(result).not.toContain('private-token');
  });

  it.each([
    ['wrong-state-status-o200-c400', true],
    ['wrong-state-error-ounknown-cguard.invalid_input', true],
    ['replay-second-status-o400-c404', true],
    ['replay-second-error-oconnector.general-csession.verification_session_not_found', true],
    ['contract-otrue-cfalse', true],
    ['replay-second-status-o400-c999', false],
    ['replay-second-error-oconnector.general-cprivate-token', false],
  ] as const)('preserves only validated Google comparison values %s', (detail, accepted) => {
    const value = `Phase 2 client credentials command failed (candidate-google-projection-${detail}).\n`;
    const result: unknown = diagnosticForPhase2Child(value);
    expect(result === value).toBe(accepted);
    expect(result).not.toContain('private-token');
    expect(diagnosticForPhase2Child(`${value}private-token`)).not.toContain('private-token');
  });

  it.each([
    ['google-registration-projection-unverified-email-status-o200-c400', true],
    [
      'google-registration-projection-occupied-email-error-ouser.email_already_in_use-cguard.invalid_input',
      true,
    ],
    ['wechat-web-projection-contract-otrue-cfalse', true],
    [
      'wechat-web-projection-no-union-id-error-oconnector.wechat_unionid_required-cprivate-token',
      false,
    ],
    ['google-registration-projection-unverified-email-status-o200-c999', false],
  ] as const)('preserves only bounded new Common comparison values %s', (detail, accepted) => {
    const value = `Phase 2 client credentials command failed (candidate-${detail}).\n`;
    expect(diagnosticForPhase2Child(value) === value).toBe(accepted);
    expect(diagnosticForPhase2Child(`${value}private-token`)).not.toContain('private-token');
  });

  it.each([
    'unverified-email-control',
    'unverified-email-owner',
    'occupied-email-control',
    'occupied-email-owner',
    'control-publication',
  ] as const)('retains only closed registration stage %s', (stage) => {
    const value = `Phase 2 client credentials command failed (oracle-common-ready-google-registration-${stage}).\n`;
    expect(diagnosticForPhase2Child(value)).toBe(value);
    expect(diagnosticForPhase2Child(`${value}private-token`)).not.toContain('private-token');
  });

  it('matches the runtime closure algorithm used inside the built CLI', async () => {
    const entry = path.resolve('lib/compatibility/phase-2/cli.js');
    await expect(computeRuntimeBundleIdentity(entry)).resolves.toEqual(
      await computePhase2RuntimeBundleIdentity(entry)
    );
  });

  it.each(['google', 'wechat'] as const)(
    'passes only paired owned %s provider paths within the same run directory',
    async (provider) => {
      const readEnvironment =
        provider === 'google'
          ? readPhase2GoogleProviderEnvironment
          : readPhase2WechatProviderEnvironment;
      const keys = [
        `ASTER_PHASE2_ORACLE_${provider.toUpperCase()}_PROVIDER_INPUT`,
        `ASTER_PHASE2_CANDIDATE_${provider.toUpperCase()}_PROVIDER_INPUT`,
      ] as const;
      const previous = keys.map((key) => process.env[key]);
      const runDirectory = path.dirname(process.env.HOME ?? '/missing-home');
      const paths = keys.map((_key, index) =>
        path.join(
          runDirectory,
          `${provider}-provider`,
          index === 0 ? 'oracle' : 'candidate',
          'provider-input.json'
        )
      );
      try {
        await Promise.all(
          paths.map(async (file) => {
            await mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
            await writeFile(file, '{}', { mode: 0o600 });
          })
        );
        for (const [index, key] of keys.entries()) {
          process.env[key] = paths[index];
        }
        expect(await readEnvironment({ HOME: process.env.HOME })).toEqual(
          Object.fromEntries(keys.map((key, index) => [key, paths[index]]))
        );
        process.env[keys[1]] = '/var/tmp/henry-build/unselected-provider-input.json';
        await expect(readEnvironment({ HOME: process.env.HOME })).rejects.toThrow(
          'Invalid Phase 2 launcher'
        );
        Reflect.deleteProperty(process.env, keys[1]);
        await expect(readEnvironment({ HOME: process.env.HOME })).rejects.toThrow(
          'Invalid Phase 2 launcher'
        );
        process.env[keys[1]] = paths[1];
        await chmod(paths[0] ?? '', 0o644);
        await expect(readEnvironment({ HOME: process.env.HOME })).rejects.toThrow(
          'Invalid Phase 2 launcher'
        );
      } finally {
        for (const [index, key] of keys.entries()) {
          const value = previous[index];
          if (value === undefined) {
            Reflect.deleteProperty(process.env, key);
          } else {
            process.env[key] = value;
          }
        }
        await rm(path.join(runDirectory, `${provider}-provider`), { recursive: true, force: true });
      }
    }
  );

  it('builds only between equal clean HEAD checks and passes a closed expected identity', async () => {
    const calls: string[] = [];
    const head = '1'.repeat(40);
    const tree = '2'.repeat(40);
    const digest = '3'.repeat(64);
    const manifest = {
      sha256: digest,
      moduleCount: 1,
      entryUrl: 'file:///private/lib/compatibility/phase-2/cli.js',
      libraryRootUrl: 'file:///private/lib/',
      modules: { 'file:///private/lib/compatibility/phase-2/cli.js': digest },
    };
    await expect(
      launchPhase2(['oracle'], {
        inspect: async () => {
          calls.push('inspect');
          return { head, tree };
        },
        build: async () => {
          calls.push('build');
        },
        identity: async () => {
          calls.push('identity');
          return manifest;
        },
        execute: async (
          _entry: string,
          args: readonly string[],
          environment: Record<string, string>,
          receivedManifest: typeof manifest,
          capability: string
        ) => {
          calls.push('execute');
          expect(args).toEqual(['oracle']);
          expect(capability).toMatch(/^[0-9a-f]{64}$/u);
          expect(receivedManifest).toBe(manifest);
          expect(environment).toEqual({
            ASTER_PHASE2_HARNESS_HEAD: head,
            ASTER_PHASE2_HARNESS_TREE: tree,
            ASTER_PHASE2_RUNTIME_BUNDLE_SHA256: digest,
            HOME: process.env.HOME,
            LC_ALL: 'C',
            PATH: '/usr/bin:/bin',
            PLAYWRIGHT_BROWSERS_PATH: process.env.PLAYWRIGHT_BROWSERS_PATH,
            TMPDIR: process.env.TMPDIR,
            XDG_RUNTIME_DIR: process.env.XDG_RUNTIME_DIR,
          });
          return 0;
        },
      })
    ).resolves.toBe(0);
    expect(calls).toEqual(['inspect', 'build', 'inspect', 'identity', 'execute']);
  });

  it('builds one verified bundle for a batch and issues a distinct capability per command', async () => {
    const calls: string[] = [];
    const capabilities = new Set<string>();
    const head = '4'.repeat(40);
    const tree = '5'.repeat(40);
    const digest = '6'.repeat(64);
    const manifest = {
      sha256: digest,
      moduleCount: 1,
      entryUrl: 'file:///private/lib/compatibility/phase-2/cli.js',
      libraryRootUrl: 'file:///private/lib/',
      modules: { 'file:///private/lib/compatibility/phase-2/cli.js': digest },
    };
    const commands = Object.freeze([
      Object.freeze(['oracle']),
      Object.freeze(['differential']),
      Object.freeze(['candidate-invariants']),
    ]);

    await expect(
      launchPhase2Batch(commands, {
        inspect: async () => {
          calls.push('inspect');
          return { head, tree };
        },
        build: async () => {
          calls.push('build');
        },
        identity: async () => {
          calls.push('identity');
          return manifest;
        },
        execute: async (
          _entry: string,
          args: readonly string[],
          environment: Record<string, string>,
          receivedManifest: typeof manifest,
          capability: string
        ) => {
          calls.push(`execute:${args[0]}`);
          expect(environment.ASTER_PHASE2_RUNTIME_BUNDLE_SHA256).toBe(digest);
          expect(receivedManifest).toBe(manifest);
          expect(capability).toMatch(/^[0-9a-f]{64}$/u);
          capabilities.add(capability);
          return 0;
        },
      })
    ).resolves.toBe(0);
    expect(calls).toEqual([
      'inspect',
      'build',
      'inspect',
      'identity',
      'execute:oracle',
      'execute:differential',
      'execute:candidate-invariants',
    ]);
    expect(capabilities.size).toBe(3);
  });

  it('passes only the four validated browser paths through the real child boundary', async () => {
    const observed: Array<Record<string, unknown>> = [];
    const previousMarker = process.env.ASTER_PRIVATE_MARKER;
    const previousPassword = process.env.PGPASSWORD;
    process.env.ASTER_PRIVATE_MARKER = 'private-marker';
    process.env.PGPASSWORD = 'private-password';
    try {
      await expect(
        launchPhase2Batch([['oracle']], {
          inspect: async () => ({ head: 'a'.repeat(40), tree: 'b'.repeat(40) }),
          build: async (): Promise<undefined> => undefined,
          identity: async () => ({
            sha256: 'c'.repeat(64),
            moduleCount: 1,
            entryUrl: 'file:///private/lib/compatibility/phase-2/cli.js',
            libraryRootUrl: 'file:///private/lib/',
            modules: { 'file:///private/lib/compatibility/phase-2/cli.js': 'c'.repeat(64) },
          }),
          execute: async (
            _entry: string,
            _args: readonly string[],
            environment: Record<string, string>
          ) => {
            const { stdout } = await executeFile(
              process.execPath,
              [
                '--eval',
                `process.stdout.write(JSON.stringify({
                  HOME: process.env.HOME,
                  PLAYWRIGHT_BROWSERS_PATH: process.env.PLAYWRIGHT_BROWSERS_PATH,
                  TMPDIR: process.env.TMPDIR,
                  XDG_RUNTIME_DIR: process.env.XDG_RUNTIME_DIR,
                  ASTER_PRIVATE_MARKER: process.env.ASTER_PRIVATE_MARKER,
                  PGPASSWORD: process.env.PGPASSWORD,
                }))`,
              ],
              { env: environment }
            );
            observed.push(JSON.parse(stdout) as Record<string, unknown>);
            return 0;
          },
        })
      ).resolves.toBe(0);
    } finally {
      if (previousMarker === undefined) {
        Reflect.deleteProperty(process.env, 'ASTER_PRIVATE_MARKER');
      } else {
        process.env.ASTER_PRIVATE_MARKER = previousMarker;
      }
      if (previousPassword === undefined) {
        Reflect.deleteProperty(process.env, 'PGPASSWORD');
      } else {
        process.env.PGPASSWORD = previousPassword;
      }
    }
    expect(observed).toEqual([
      {
        HOME: process.env.HOME,
        PLAYWRIGHT_BROWSERS_PATH: process.env.PLAYWRIGHT_BROWSERS_PATH,
        TMPDIR: process.env.TMPDIR,
        XDG_RUNTIME_DIR: process.env.XDG_RUNTIME_DIR,
      },
    ]);
  });

  it.each([
    ['missing', 'HOME', undefined],
    ['relative', 'PLAYWRIGHT_BROWSERS_PATH', 'relative/cache'],
    ['escaped', 'TMPDIR', '/var/tmp/henry-build/phase2-launcher-browser-outside'],
  ] as const)('rejects a %s browser path before child execution', async (_case, key, value) => {
    let executions = 0;
    const previous = process.env[key];
    if (value === undefined) {
      Reflect.deleteProperty(process.env, key);
    } else {
      process.env[key] = value;
      if (path.isAbsolute(value)) {
        await mkdir(value, { mode: 0o700, recursive: true });
      }
    }
    try {
      await expect(
        launchPhase2Batch([['oracle']], {
          inspect: async () => ({ head: 'd'.repeat(40), tree: 'e'.repeat(40) }),
          build: async (): Promise<undefined> => undefined,
          identity: async () => ({
            sha256: 'f'.repeat(64),
            moduleCount: 1,
            entryUrl: 'file:///private/lib/compatibility/phase-2/cli.js',
            libraryRootUrl: 'file:///private/lib/',
            modules: { 'file:///private/lib/compatibility/phase-2/cli.js': 'f'.repeat(64) },
          }),
          execute: async () => {
            executions += 1;
            return 0;
          },
        })
      ).rejects.toThrow('Invalid Phase 2 launcher');
    } finally {
      if (previous === undefined) {
        Reflect.deleteProperty(process.env, key);
      } else {
        process.env[key] = previous;
      }
      if (value !== undefined && path.isAbsolute(value)) {
        await rm(value, { force: true, recursive: true });
      }
    }
    expect(executions).toBe(0);
  });

  it('pins one verified runtime across sequential batches using the same dependencies', async () => {
    const calls: string[] = [];
    const head = '7'.repeat(40);
    const tree = '8'.repeat(40);
    const digest = '9'.repeat(64);
    const manifest = {
      sha256: digest,
      moduleCount: 1,
      entryUrl: 'file:///private/lib/compatibility/phase-2/cli.js',
      libraryRootUrl: 'file:///private/lib/',
      modules: { 'file:///private/lib/compatibility/phase-2/cli.js': digest },
    };
    const receivedManifests: Array<typeof manifest> = [];
    const environments: Array<Record<string, string>> = [];
    const dependencies = {
      inspect: async () => {
        calls.push('inspect');
        return { head, tree };
      },
      build: async (): Promise<undefined> => {
        calls.push('build');
      },
      identity: async () => {
        calls.push('identity');
        return { ...manifest, modules: { ...manifest.modules } };
      },
      execute: async (
        _entry: string,
        args: readonly string[],
        environment: Record<string, string>,
        receivedManifest: typeof manifest
      ) => {
        calls.push(`execute:${args[0]}`);
        environments.push(environment);
        receivedManifests.push(receivedManifest);
        return 0 as const;
      },
    };

    await expect(launchPhase2Batch([['oracle']], dependencies)).resolves.toBe(0);
    await expect(launchPhase2Batch([['differential']], dependencies)).resolves.toBe(0);

    expect(calls).toEqual([
      'inspect',
      'build',
      'inspect',
      'identity',
      'execute:oracle',
      'inspect',
      'identity',
      'execute:differential',
    ]);
    expect(receivedManifests[1]).toBe(receivedManifests[0]);
    expect(environments[1]).toBe(environments[0]);
  });

  it('isolates prepared runtimes by dependency object', async () => {
    const builds: string[] = [];
    const createDependencies = (name: string) => ({
      inspect: async () => ({ head: '3'.repeat(40), tree: '4'.repeat(40) }),
      build: async (): Promise<undefined> => {
        builds.push(name);
      },
      identity: async () => ({
        sha256: '5'.repeat(64),
        moduleCount: 1,
        entryUrl: 'file:///private/lib/compatibility/phase-2/cli.js',
        libraryRootUrl: 'file:///private/lib/',
        modules: { 'file:///private/lib/compatibility/phase-2/cli.js': '5'.repeat(64) },
      }),
      execute: async () => 0 as const,
    });

    await expect(launchPhase2Batch([['oracle']], createDependencies('first'))).resolves.toBe(0);
    await expect(launchPhase2Batch([['oracle']], createDependencies('second'))).resolves.toBe(0);

    expect(builds).toEqual(['first', 'second']);
  });

  it('shares one in-flight preparation across concurrent batches', async () => {
    let releaseBuild: (() => void) | undefined;
    let announceBuild: (() => void) | undefined;
    const buildBlocked = new Promise<void>((resolve) => {
      releaseBuild = resolve;
    });
    const buildStarted = new Promise<void>((resolve) => {
      announceBuild = resolve;
    });
    const calls: string[] = [];
    const digest = '6'.repeat(64);
    const dependencies = {
      inspect: async () => {
        calls.push('inspect');
        return { head: '7'.repeat(40), tree: '8'.repeat(40) };
      },
      build: async (): Promise<undefined> => {
        calls.push('build');
        announceBuild?.();
        await buildBlocked;
      },
      identity: async () => {
        calls.push('identity');
        return {
          sha256: digest,
          moduleCount: 1,
          entryUrl: 'file:///private/lib/compatibility/phase-2/cli.js',
          libraryRootUrl: 'file:///private/lib/',
          modules: { 'file:///private/lib/compatibility/phase-2/cli.js': digest },
        };
      },
      execute: async (_entry: string, args: readonly string[]) => {
        calls.push(`execute:${args[0]}`);
        return 0 as const;
      },
    };

    const oracle = launchPhase2Batch([['oracle']], dependencies);
    const differential = launchPhase2Batch([['differential']], dependencies);
    await buildStarted;
    expect(calls).toEqual(['inspect', 'build']);
    releaseBuild?.();

    await expect(Promise.all([oracle, differential])).resolves.toEqual([0, 0]);
    expect(calls).toEqual([
      'inspect',
      'build',
      'inspect',
      'identity',
      'execute:oracle',
      'execute:differential',
    ]);
  });

  it('clears a rejected in-flight preparation so a later batch can retry', async () => {
    let builds = 0;
    let executions = 0;
    const digest = '9'.repeat(64);
    const dependencies = {
      inspect: async () => ({ head: 'a'.repeat(40), tree: 'b'.repeat(40) }),
      build: async (): Promise<undefined> => {
        builds += 1;
        if (builds === 1) {
          throw new Error('build failed');
        }
      },
      identity: async () => ({
        sha256: digest,
        moduleCount: 1,
        entryUrl: 'file:///private/lib/compatibility/phase-2/cli.js',
        libraryRootUrl: 'file:///private/lib/',
        modules: { 'file:///private/lib/compatibility/phase-2/cli.js': digest },
      }),
      execute: async () => {
        executions += 1;
        return 0 as const;
      },
    };

    await expect(launchPhase2Batch([['oracle']], dependencies)).rejects.toThrow('build failed');
    await expect(launchPhase2Batch([['oracle']], dependencies)).resolves.toBe(0);
    expect(builds).toBe(2);
    expect(executions).toBe(1);
  });

  it('rejects clean source drift between sequential batches before execution', async () => {
    let inspections = 0;
    let executions = 0;
    const dependencies = {
      inspect: async () => {
        inspections += 1;
        return {
          head: (inspections < 3 ? 'a' : 'b').repeat(40),
          tree: 'c'.repeat(40),
        };
      },
      build: async (): Promise<undefined> => {
        // The first preparation build is intentionally successful.
      },
      identity: async () => ({
        sha256: 'd'.repeat(64),
        moduleCount: 1,
        entryUrl: 'file:///private/lib/compatibility/phase-2/cli.js',
        libraryRootUrl: 'file:///private/lib/',
        modules: { 'file:///private/lib/compatibility/phase-2/cli.js': 'd'.repeat(64) },
      }),
      execute: async () => {
        executions += 1;
        return 0 as const;
      },
    };

    await expect(launchPhase2Batch([['oracle']], dependencies)).resolves.toBe(0);
    await expect(launchPhase2Batch([['differential']], dependencies)).rejects.toThrow(
      'Invalid Phase 2 launcher'
    );
    expect(executions).toBe(1);
  });

  it('rejects runtime bundle drift between sequential batches before execution', async () => {
    let identities = 0;
    let executions = 0;
    const dependencies = {
      inspect: async () => ({ head: 'e'.repeat(40), tree: 'f'.repeat(40) }),
      build: async (): Promise<undefined> => {
        // The first preparation build is intentionally successful.
      },
      identity: async () => {
        identities += 1;
        const digest = (identities === 1 ? '1' : '2').repeat(64);
        return {
          sha256: digest,
          moduleCount: 1,
          entryUrl: 'file:///private/lib/compatibility/phase-2/cli.js',
          libraryRootUrl: 'file:///private/lib/',
          modules: { 'file:///private/lib/compatibility/phase-2/cli.js': digest },
        };
      },
      execute: async () => {
        executions += 1;
        return 0 as const;
      },
    };

    await expect(launchPhase2Batch([['oracle']], dependencies)).resolves.toBe(0);
    await expect(launchPhase2Batch([['differential']], dependencies)).rejects.toThrow(
      'Invalid Phase 2 launcher'
    );
    expect(executions).toBe(1);
  });

  it('rejects a HEAD substitution across the clean rebuild boundary', async () => {
    let inspection = 0;
    let executions = 0;
    const execute = async () => {
      executions += 1;
      return 0 as const;
    };
    await expect(
      launchPhase2(['oracle'], {
        inspect: async () => {
          inspection += 1;
          return {
            head: (inspection === 1 ? '1' : '2').repeat(40),
            tree: '3'.repeat(40),
          };
        },
        build: async () => {
          // The injected build boundary is intentionally successful.
        },
        identity: async () => ({
          sha256: '4'.repeat(64),
          moduleCount: 1,
          entryUrl: 'file:///private/lib/compatibility/phase-2/cli.js',
          libraryRootUrl: 'file:///private/lib/',
          modules: {
            'file:///private/lib/compatibility/phase-2/cli.js': '4'.repeat(64),
          },
        }),
        execute,
      })
    ).rejects.toThrow('Invalid Phase 2 launcher');
    expect(executions).toBe(0);
  });

  it('rejects a malicious loaded module before it can restore itself or execute side effects', async () => {
    const root = await mkdtemp('/var/tmp/henry-build/phase2-load-hook-');
    const libraryRoot = path.join(root, 'lib');
    const entryDirectory = path.join(libraryRoot, 'compatibility/phase-2');
    const entry = path.join(entryDirectory, 'entry.js');
    const modulePath = path.join(libraryRoot, 'runtime-module.js');
    const sideEffect = path.join(root, 'malicious-side-effect');
    const originalModule = 'export const value = "safe";\n';
    const capability = '5'.repeat(64);
    try {
      await mkdir(entryDirectory, { recursive: true, mode: 0o700 });
      await writeFile(path.join(root, 'package.json'), '{"type":"module"}\n');
      await writeFile(modulePath, originalModule);
      await writeFile(
        entry,
        `import { value } from "../../runtime-module.js";\nexport const runPhase2CliMain = async (args, receivedCapability) => {\n  if (globalThis[Symbol.for('aster.phase2.runtime-capability')] !== receivedCapability) throw new Error('missing runtime capability');\n  process.stdout.write(JSON.stringify(args) + ':' + value);\n  return 0;\n};\n`
      );
      const manifest = await computeRuntimeBundleManifest(entry);
      const registerImport = createRuntimeHookImport(manifest, capability);
      const bootstrap = createRuntimeBootstrap(manifest.entryUrl, capability);
      await expect(
        executeFile(
          process.execPath,
          [
            '--import',
            registerImport,
            '--input-type=module',
            '--eval',
            `await import(${JSON.stringify(bootstrap)})`,
            '--',
            'oracle',
            '--profile',
            '/private/profile.json',
          ],
          {
            env: { LC_ALL: 'C', PATH: '/usr/bin:/bin' },
            timeout: 5000,
          }
        )
      ).resolves.toMatchObject({
        stdout: '["oracle","--profile","/private/profile.json"]:safe',
      });

      const maliciousModule = `import { writeFileSync } from 'node:fs';\nwriteFileSync(${JSON.stringify(
        sideEffect
      )}, 'executed');\nwriteFileSync(${JSON.stringify(modulePath)}, ${JSON.stringify(
        originalModule
      )});\nexport const value = 'evil';\n`;
      await writeFile(modulePath, maliciousModule);
      await expect(
        executeFile(
          process.execPath,
          [
            '--import',
            registerImport,
            '--input-type=module',
            '--eval',
            `await import(${JSON.stringify(bootstrap)})`,
            '--',
            'oracle',
            '--profile',
            '/private/profile.json',
          ],
          {
            env: { LC_ALL: 'C', PATH: '/usr/bin:/bin' },
            timeout: 5000,
          }
        )
      ).rejects.toBeDefined();
      await expect(lstat(sideEffect)).rejects.toMatchObject({ code: 'ENOENT' });
      await expect(readFile(modulePath, 'utf8')).resolves.toBe(maliciousModule);
    } finally {
      await rm(root, { force: true, recursive: true });
    }
  });

  it('executes the compiled re-export entry through the trusted bootstrap and rejects direct node execution', async () => {
    const entry = path.resolve('lib/compatibility/phase-2/cli.js');
    const manifest = await computeRuntimeBundleManifest(entry);
    const result: unknown = await executeVerifiedPhase2Entry(
      entry,
      [],
      { LC_ALL: 'C', PATH: '/usr/bin:/bin' },
      manifest,
      '6'.repeat(64)
    );
    expect(result).toMatchObject({
      code: 1,
      signal: null,
      stderr: 'Invalid Phase 2 arguments.\n',
      stdout: '',
      timedOut: false,
    });

    const direct = await executeFile(process.execPath, [entry], {
      env: { LC_ALL: 'C', PATH: '/usr/bin:/bin' },
      timeout: 5000,
    }).catch((error: unknown) => error as { stderr?: string });
    expect(direct).toMatchObject({ stderr: 'Invalid Phase 2 arguments.\n' });
  });
});

/* eslint-enable max-lines, max-params, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
