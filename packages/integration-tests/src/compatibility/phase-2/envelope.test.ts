/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment -- Negative controls deliberately forge forbidden public provenance fields. */
import { createPhase2EvidenceEnvelope, type Phase2TargetProvenance } from './envelope.js';
import { phase2ExpectedProfileAuthority, type Phase2ProfileRegistries } from './profile.js';
import type { Phase2SourceIdentity } from './provenance.js';

const profile: Phase2ProfileRegistries = {
  ...phase2ExpectedProfileAuthority,
  differentialScenarios: [],
  candidateInvariantScenarios: [],
  discovery: { grantTypesSupportedAppend: ['client_credentials'], stillAbsent: [] },
};
const harness: Phase2SourceIdentity = {
  repositoryRoot: '/private/repo',
  repositoryDev: '1',
  repositoryIno: '2',
  clean: true,
  public: {
    repositoryUrl: 'https://github.com/qq98982/logto.git',
    headCommit: '3'.repeat(40),
    headTree: '4'.repeat(40),
    runtimeBundleSha256: 'a'.repeat(64),
  },
  runtimeEntryPath: '/private/repo/packages/integration-tests/lib/compatibility/phase-2/cli.js',
};
const target = (kind: 'oracle' | 'candidate'): Phase2TargetProvenance => ({
  sourceCommit: kind === 'oracle' ? '6852a7b8c8984c5c12b2061e8c51faa310a36412' : '5'.repeat(40),
  imageDigest:
    kind === 'oracle'
      ? 'sha256:76a9977bfc5ea3ed5b7623b879c27256670e377e27b987e8af99b53d55b30bbd'
      : `sha256:${'6'.repeat(64)}`,
  topology: { primaryRole: `${kind}-primary-core`, foreignRole: `${kind}-foreign-core` },
  drivers: {
    state: { role: 'state-driver', sha256: '7'.repeat(64) },
    ...(kind === 'candidate'
      ? {
          fixture: { role: 'fixture-executable' as const, sha256: '8'.repeat(64) },
          invariant: { role: 'invariant-driver' as const, sha256: '9'.repeat(64) },
        }
      : {}),
  },
});

describe('Phase 2 public provenance envelope', () => {
  it('publishes only semantic provenance and enforces mode bindings', () => {
    const value = createPhase2EvidenceEnvelope({
      mode: 'differential',
      profile,
      harness,
      oracle: target('oracle'),
      candidate: target('candidate'),
      payload: { ok: true },
    });
    const text = JSON.stringify(value);
    expect(text).not.toContain('/private');
    expect(text).not.toMatch(/container|projectName|socket|repositoryRoot|"dev"|"ino"|"uid"/u);
    expect(value.provenance.harness.runtimeBundleSha256).toBe('a'.repeat(64));
    expect(value.sanitizerSuccess).toBe(true);
  });
  it('rejects source/image substitution and local capability leakage', () => {
    expect(() =>
      createPhase2EvidenceEnvelope({
        mode: 'oracle',
        profile,
        harness,
        oracle: target('candidate'),
        payload: { ok: true },
      })
    ).toThrow();
    expect(() =>
      createPhase2EvidenceEnvelope({
        mode: 'differential',
        profile,
        harness,
        oracle: target('oracle'),
        candidate: { ...target('oracle') },
        payload: { ok: true },
      })
    ).toThrow();
    for (const planted of [
      { path: '/private/driver' },
      { socketPath: '/private/control.sock' },
      { containerId: 'a'.repeat(64) },
      { projectName: 'private-project' },
    ]) {
      expect(() =>
        createPhase2EvidenceEnvelope({
          mode: 'oracle',
          profile,
          harness,
          oracle: { ...target('oracle'), ...planted } as any,
          payload: { ok: true },
        })
      ).toThrow();
    }
    expect(() =>
      createPhase2EvidenceEnvelope({
        mode: 'oracle',
        profile,
        harness,
        oracle: target('oracle'),
        payload: { sha256: 'a'.repeat(64) },
      })
    ).toThrow();
  });
});
/* eslint-enable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment */
