/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-assign, @silverhand/fp/no-mutating-methods, @typescript-eslint/ban-types, @typescript-eslint/consistent-type-assertions -- Hostile authority fixtures deliberately construct accessors, custom prototypes, and post-mint mutations. */
import {
  assertAuthorizedPhase1Run,
  authorizePhase1RunForTesting,
  type Phase1RunAuthorization,
} from '../cli.js';
import type { Phase1Profile } from '../profile-types.js';

import {
  assertValidatedPhase1ConformanceRuntimeContext,
  createPhase1ConformanceGateRuntimeContext,
} from './context.js';

const harnessCommit = '1'.repeat(40);
const candidateImageDigest = `sha256:${'2'.repeat(64)}`;

const authorization = (): Phase1RunAuthorization =>
  authorizePhase1RunForTesting(
    Object.freeze({
      mode: 'runtime-candidate',
      profile: Object.freeze({
        phase1Harness: Object.freeze({ commit: harnessCommit }),
      }) as Phase1Profile,
      profileSha256: '3'.repeat(64),
      schemaSha256: '4'.repeat(64),
      provenance: Object.freeze({
        kind: 'review-candidate' as const,
        harnessCommit,
        publishable: false as const,
      }),
      protectedExecution: undefined,
      controls: Object.freeze({
        recordOracle: false,
        observationControls: true,
        discoveryExtraControl: true,
        candidateInvariantControls: true,
      }),
      conformanceGate: true as const,
    })
  );

const mintHostileAuthorization = (value: object): Phase1RunAuthorization =>
  authorizePhase1RunForTesting(value as Phase1RunAuthorization);

const input = () => ({
  authorization: authorization(),
  candidateImageDigest,
  evidenceDirectory: '/var/tmp/henry-build/phase1/evidence',
  repositoryRoot: '/home/henry/repo/logto',
  conformanceRoot: '/var/tmp/henry-build/phase1/conformance',
});

describe('Phase 1 conformance runtime context', () => {
  it('brands the exact candidate-only gate authority without compatibility topology', () => {
    const source = input();
    const context = createPhase1ConformanceGateRuntimeContext(source);

    expect(Object.keys(context)).toEqual([
      'authorization',
      'candidateImageDigest',
      'evidenceDirectory',
      'repositoryRoot',
      'conformanceRoot',
    ]);
    expect(context.authorization.conformanceGate).toBe(true);
    expect(context.authorization).not.toBe(source.authorization);
    expect(context.candidateImageDigest).toBe(candidateImageDigest);
    expect(Object.isFrozen(context)).toBe(true);
    expect(Object.isFrozen(context.authorization)).toBe(true);
    expect(Object.isFrozen(context.authorization.controls)).toBe(true);
    expect(Object.isFrozen(context.authorization.provenance)).toBe(true);
    expect(Object.isFrozen(context.authorization.profile)).toBe(true);
    expect(Object.isFrozen(context.authorization.profile.phase1Harness)).toBe(true);
    expect(() => {
      assertAuthorizedPhase1Run(context.authorization);
    }).not.toThrow();
    expect(() => {
      assertValidatedPhase1ConformanceRuntimeContext(context);
    }).not.toThrow();
    expect(() => {
      assertValidatedPhase1ConformanceRuntimeContext({ ...context });
    }).toThrow(/^Invalid Phase 1 conformance runtime context$/u);
  });

  it.each([
    [
      'candidate digest',
      (value: ReturnType<typeof input>) => ({ ...value, candidateImageDigest: '' }),
    ],
    [
      'evidence root',
      (value: ReturnType<typeof input>) => ({ ...value, evidenceDirectory: 'relative' }),
    ],
    [
      'repository root',
      (value: ReturnType<typeof input>) => ({ ...value, repositoryRoot: 'relative' }),
    ],
    [
      'conformance root',
      (value: ReturnType<typeof input>) => ({ ...value, conformanceRoot: 'relative' }),
    ],
  ] as const)('fails closed when the required %s is missing', (_name, mutate) => {
    expect(() => createPhase1ConformanceGateRuntimeContext(mutate(input()))).toThrow(
      /^Invalid Phase 1 conformance runtime context$/u
    );
  });

  it('rejects another gate or an unbranded authorization', () => {
    const base = input();
    const conflicting = authorizePhase1RunForTesting(
      Object.freeze({
        ...base.authorization,
        differentialGate: true as const,
      }) as Phase1RunAuthorization
    );

    expect(() =>
      createPhase1ConformanceGateRuntimeContext({ ...base, authorization: conflicting })
    ).toThrow(/^Invalid Phase 1 conformance runtime context$/u);
    expect(() =>
      createPhase1ConformanceGateRuntimeContext({
        ...base,
        authorization: { ...base.authorization },
      })
    ).toThrow(/^Invalid Phase 1 conformance runtime context$/u);
    const publishable = authorizePhase1RunForTesting(
      Object.freeze({
        ...base.authorization,
        provenance: Object.freeze({
          kind: 'review-candidate',
          harnessCommit,
          publishable: true,
        }),
      }) as unknown as Phase1RunAuthorization
    );

    expect(() =>
      createPhase1ConformanceGateRuntimeContext({ ...base, authorization: publishable })
    ).toThrow(/^Invalid Phase 1 conformance runtime context$/u);
  });

  it('rejects accessor and Proxy authorization capabilities', () => {
    const base = authorization();
    let storedGate = false;
    const accessor = { ...base } as Record<string, unknown>;

    Object.defineProperty(accessor, 'conformanceGate', {
      enumerable: true,
      get: () => !storedGate,
      set: (value: boolean) => {
        storedGate = value;
      },
    });
    Object.freeze(accessor);
    const proxy = new Proxy(base, {});

    for (const hostile of [mintHostileAuthorization(accessor), mintHostileAuthorization(proxy)]) {
      expect(() =>
        createPhase1ConformanceGateRuntimeContext({ ...input(), authorization: hostile })
      ).toThrow(/^Invalid Phase 1 conformance runtime context$/u);
    }
  });

  it('rejects inherited competing gates and post-mint mutation', () => {
    const base = authorization();
    const inherited = Object.assign(Object.create({ browserGate: true }), base) as object;
    const mutable = { ...base, conformanceGate: false } as unknown as Phase1RunAuthorization & {
      conformanceGate: boolean;
    };
    const mintedMutable = mintHostileAuthorization(mutable);

    Object.freeze(inherited);
    mutable.conformanceGate = true;

    for (const hostile of [mintHostileAuthorization(inherited), mintedMutable]) {
      expect(() =>
        createPhase1ConformanceGateRuntimeContext({ ...input(), authorization: hostile })
      ).toThrow(/^Invalid Phase 1 conformance runtime context$/u);
    }
  });

  it('rejects mutable nested controls and provenance', () => {
    const base = authorization();
    const mutableControls = mintHostileAuthorization(
      Object.freeze({ ...base, controls: { ...base.controls } })
    );
    const mutableProvenance = mintHostileAuthorization(
      Object.freeze({ ...base, provenance: { ...base.provenance } })
    );

    for (const hostile of [mutableControls, mutableProvenance]) {
      expect(() =>
        createPhase1ConformanceGateRuntimeContext({ ...input(), authorization: hostile })
      ).toThrow(/^Invalid Phase 1 conformance runtime context$/u);
    }
  });

  it('snapshots mutable profile authority before post-context mutation', () => {
    const base = authorization();
    const mutableProfile = {
      phase1Harness: { commit: harnessCommit },
    };
    const source = mintHostileAuthorization(
      Object.freeze({ ...base, profile: mutableProfile as unknown as Phase1Profile })
    );
    const context = createPhase1ConformanceGateRuntimeContext({
      ...input(),
      authorization: source,
    });

    mutableProfile.phase1Harness.commit = '9'.repeat(40);

    expect(context.authorization).not.toBe(source);
    expect(context.authorization.profile.phase1Harness.commit).toBe(harnessCommit);
    expect(Object.isFrozen(context.authorization.profile)).toBe(true);
    expect(Object.isFrozen(context.authorization.profile.phase1Harness)).toBe(true);
  });

  it('rejects accessor profile authority before snapshotting', () => {
    const base = authorization();
    const phase1Harness = {} as Record<string, unknown>;

    Object.defineProperty(phase1Harness, 'commit', {
      enumerable: true,
      get: () => harnessCommit,
    });
    const source = mintHostileAuthorization(
      Object.freeze({
        ...base,
        profile: { phase1Harness },
      })
    );

    expect(() =>
      createPhase1ConformanceGateRuntimeContext({ ...input(), authorization: source })
    ).toThrow(/^Invalid Phase 1 conformance runtime context$/u);
  });
});

/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-assign, @silverhand/fp/no-mutating-methods, @typescript-eslint/ban-types, @typescript-eslint/consistent-type-assertions */
