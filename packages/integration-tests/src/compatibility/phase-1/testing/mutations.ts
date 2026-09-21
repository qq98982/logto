/* eslint-disable @typescript-eslint/ban-types -- Explicit null values exercise the schema's design-state lock branch. */
export const syntheticSchemaSourceCommit = '1111111111111111111111111111111111111111';
export const syntheticSchemaSha256 =
  'c8abf06e10801edad7ccbef2a4d70b544b20eab86945f27692c1d6a8ed61720f';
export const syntheticHarnessCommit = '2222222222222222222222222222222222222222';

export type SyntheticProfile = {
  schemaVersion: 1;
  profileSchema: {
    sourceCommit: string | null;
    sha256: string | null;
  };
  phase1Harness: {
    commit: string | null;
  };
  metadata: {
    label: string;
    nested: {
      enabled: boolean;
    };
  };
  items: Array<{ id: string; name: string }>;
  transport: { kind: 'http'; url: string } | { kind: 'queue'; topic: string };
};

export const createLockedSyntheticProfile = (): SyntheticProfile => ({
  schemaVersion: 1,
  profileSchema: {
    sourceCommit: syntheticSchemaSourceCommit,
    sha256: syntheticSchemaSha256,
  },
  phase1Harness: { commit: syntheticHarnessCommit },
  metadata: {
    label: 'synthetic loader contract',
    nested: { enabled: true },
  },
  items: [{ id: 'one', name: 'First item' }],
  transport: { kind: 'http', url: 'https://example.invalid/callback' },
});

export const createDesignSyntheticProfile = (): SyntheticProfile => ({
  ...createLockedSyntheticProfile(),
  profileSchema: { sourceCommit: null, sha256: null },
  phase1Harness: { commit: null },
});

export const createNestedDuplicateProfileSource = () =>
  JSON.stringify(createLockedSyntheticProfile()).replace(
    '"nested":{"enabled":true}',
    '"nested":{"enabled":true,"\\u0065nabled":false}'
  );

/* eslint-enable @typescript-eslint/ban-types */
