import {
  assertPhase1PublicArtifactValue,
  canonicalPhase1ArtifactBytes,
  hashPhase1ArtifactBytes,
  phase1EvidenceFileNames,
} from './artifact-contract.js';
import { phase1ConformanceAdapterControlIds } from './conformance/runner.js';
import { phase1PublicAdapterIds, phase1PublicArtifactFiles } from './public-record-schema.js';

const scenarioCredentialArtifact = ({
  scenarioId,
  stepId,
  value,
}: Readonly<{ scenarioId: string; stepId: string; value: unknown }>) => ({
  scenarios: [
    {
      id: scenarioId,
      oracle: { value: { steps: { [stepId]: { value } } } },
      candidate: { value: { steps: {} } },
      differences: [],
    },
  ],
});

describe('Phase 1 artifact authority', () => {
  it('preserves the declared closed field order and writes exactly one trailing newline', () => {
    const left = canonicalPhase1ArtifactBytes({
      z: [{ second: 2, first: 1 }],
      a: { right: true, left: false },
    });
    const right = canonicalPhase1ArtifactBytes({
      a: { left: false, right: true },
      z: [{ first: 1, second: 2 }],
    });
    const reorderedArray = canonicalPhase1ArtifactBytes({
      a: { left: false, right: true },
      z: [
        { second: 2, first: 1 },
        { first: 1, second: 2 },
      ],
    });

    expect(Buffer.from(left).toString('utf8')).toBe(
      '{"z":[{"second":2,"first":1}],"a":{"right":true,"left":false}}\n'
    );
    expect(hashPhase1ArtifactBytes(left)).not.toBe(hashPhase1ArtifactBytes(right));
    expect(hashPhase1ArtifactBytes(left)).not.toBe(hashPhase1ArtifactBytes(reorderedArray));
  });

  it('shares the exact public artifact and conformance adapter registries', () => {
    expect(phase1PublicArtifactFiles).toBe(phase1EvidenceFileNames);
    expect(phase1PublicAdapterIds).toBe(phase1ConformanceAdapterControlIds);
  });

  it('allows only contract-approved logical resume credentials at exact step paths', () => {
    const valid = {
      scenarios: [
        {
          id: 'authorization.password-pkce-consent',
          oracle: {
            value: {
              steps: {
                'consent-post': {
                  value: {
                    redirect: { resumeCredential: '<redirect.resume-credential.2>' },
                    body: {
                      redirectTo: { resumeCredential: '<redirect.resume-credential.2>' },
                    },
                  },
                },
                submit: {
                  value: {
                    redirect: { resumeCredential: '<redirect.resume-credential.1>' },
                    body: {
                      redirectTo: { resumeCredential: '<redirect.resume-credential.1>' },
                    },
                  },
                },
              },
            },
          },
          candidate: { value: { steps: {} } },
          differences: [],
        },
      ],
    };

    expect(() => {
      assertPhase1PublicArtifactValue(valid);
    }).not.toThrow();
    for (const invalid of [
      {
        scenarios: [
          {
            id: 'interaction.password-rejected',
            oracle: {
              value: {
                steps: {
                  'consent-post': {
                    value: {
                      redirect: { resumeCredential: '<redirect.resume-credential.1>' },
                    },
                  },
                },
              },
            },
            candidate: { value: { steps: {} } },
            differences: [],
          },
        ],
      },
      scenarioCredentialArtifact({
        scenarioId: 'authorization.password-pkce-consent',
        stepId: 'identify',
        value: { redirect: { resumeCredential: '<redirect.resume-credential.1>' } },
      }),
      scenarioCredentialArtifact({
        scenarioId: 'authorization.password-pkce-consent',
        stepId: 'identify',
        value: {
          body: {
            redirectTo: { resumeCredential: '<redirect.resume-credential.1>' },
          },
        },
      }),
      scenarioCredentialArtifact({
        scenarioId: 'authorization.password-pkce-consent',
        stepId: 'submit',
        value: {
          body: { redirectTo: { resumeCredential: 'runtime-resume-value' } },
        },
      }),
      {
        scenarios: [
          {
            id: 'interaction.password-rejected',
            oracle: {
              value: {
                steps: {
                  submit: {
                    value: {
                      body: {
                        redirectTo: { resumeCredential: '<redirect.resume-credential.1>' },
                      },
                    },
                  },
                },
              },
            },
            candidate: { value: { steps: {} } },
            differences: [],
          },
        ],
      },
      {
        scenarios: [
          {
            id: 'authorization.password-pkce-consent',
            oracle: {
              value: {
                steps: {
                  'consent-post': {
                    value: { redirect: { resumeCredential: 'runtime-resume-value' } },
                  },
                },
              },
            },
            candidate: { value: { steps: {} } },
            differences: [],
          },
        ],
      },
      {
        scenarios: [
          {
            id: 'authorization.password-pkce-consent',
            oracle: {
              value: {
                steps: {
                  'consent-post': {
                    value: {
                      redirect: [{ resumeCredential: '<redirect.resume-credential.1>' }],
                    },
                  },
                },
              },
            },
            candidate: { value: { steps: {} } },
            differences: [],
          },
        ],
      },
      {
        planResults: [
          {
            result: {
              value: {
                steps: {
                  'consent-post': {
                    value: {
                      redirect: { resumeCredential: '<redirect.resume-credential.1>' },
                    },
                  },
                },
              },
            },
          },
        ],
      },
      { redirect: { resumeCredential: '<redirect.resume-credential.1>' } },
    ]) {
      expect(() => {
        assertPhase1PublicArtifactValue(invalid);
      }).toThrow();
    }
  });
});
