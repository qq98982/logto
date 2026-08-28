import { z } from 'zod';

const jsonPrimitiveGuard = z.union([z.string(), z.number(), z.boolean(), z.null()]);
export const jsonValueGuard: z.ZodType<unknown> = z.lazy(() =>
  z.union([jsonPrimitiveGuard, z.array(jsonValueGuard), z.record(jsonValueGuard)])
);

export const targetConfigGuard = z.object({
  label: z.enum(['oracle', 'candidate']),
  coreUrl: z.string().url(),
  adminUrl: z.string().url(),
});

export const capabilityGuard = z.object({
  id: z.string().min(1),
  surface: z.enum([
    'management-api',
    'experience-api',
    'user-api',
    'oidc',
    'connector',
    'integration-test',
    'manual',
  ]),
  source: z.string().min(1),
  existingEvidence: z.array(z.string()),
});

export const capabilityManifestGuard = z.object({
  schemaVersion: z.literal(1),
  referenceCommit: z.literal('6852a7b8c8984c5c12b2061e8c51faa310a36412'),
  capabilities: z.array(capabilityGuard),
});

export const observationGuard = z.object({
  stepId: z.string().min(1),
  kind: z.enum([
    'http',
    'redirect',
    'cookie-metadata',
    'jwt-header',
    'jwt-claims',
    'semantic-state',
  ]),
  value: jsonValueGuard,
});

export const targetEvidenceGuard = z.object({
  target: z.enum(['oracle', 'candidate']),
  observations: z.array(observationGuard),
});

export const differenceGuard = z.object({
  path: z.string(),
  oracle: jsonValueGuard.optional(),
  candidate: jsonValueGuard.optional(),
});

export const scenarioEvidenceGuard = z.object({
  schemaVersion: z.literal(1),
  scenarioId: z.string().min(1),
  oracle: targetEvidenceGuard.extend({ target: z.literal('oracle') }),
  candidate: targetEvidenceGuard.extend({ target: z.literal('candidate') }),
  differences: z.array(differenceGuard),
});

export const runEvidenceGuard = z.object({
  schemaVersion: z.literal(1),
  referenceCommit: z.literal('6852a7b8c8984c5c12b2061e8c51faa310a36412'),
  oracleImageDigest: z.string().regex(/^sha256:[\da-f]{64}$/),
  candidateImageDigest: z.string().regex(/^sha256:[\da-f]{64}$/),
  scenarios: z.array(
    z.object({ scenarioId: z.string().min(1), differenceCount: z.number().int().nonnegative() })
  ),
  negativeControl: z.object({ differencePath: z.string().startsWith('/') }),
});

export type TargetConfig = z.infer<typeof targetConfigGuard>;
export type CapabilityManifest = z.infer<typeof capabilityManifestGuard>;
export type Observation = z.infer<typeof observationGuard>;
export type TargetEvidence = z.infer<typeof targetEvidenceGuard>;
export type Difference = z.infer<typeof differenceGuard>;
export type ScenarioEvidence = z.infer<typeof scenarioEvidenceGuard>;
export type RunEvidence = z.infer<typeof runEvidenceGuard>;
