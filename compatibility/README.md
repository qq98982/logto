# Aster compatibility lab

The phase-0 compatibility lab compares two isolated deployments of the same pinned open-source
reference implementation. The reference commit is
`6852a7b8c8984c5c12b2061e8c51faa310a36412`. The compatibility boundary covers the runnable
open-source repository at that commit and excludes the proprietary Cloud backend.

The oracle always uses an image built from the pinned commit. By default, the candidate is another
instance of that image with independent PostgreSQL, Redis, and message state. This mirror pairing
proves that the lab itself is deterministic before a different candidate implementation is used.

## Run the lab

From the repository root, run:

```bash
bash .scripts/compatibility/run.sh
```

The script owns the complete lifecycle: it checks the frozen source pin, creates private runtime
state, builds the oracle, starts both isolated targets, checks the inventory, runs the controls,
finalizes evidence, runs the opt-in Jest smoke test, captures private service logs, and removes the
containers and volumes. Ports `3101`, `3201`, `3102`, and `3202` must be free.

The default run root is `/var/tmp/henry-build/aster-compatibility`. Each invocation creates a
private `run.*` directory beneath it and prints that directory on exit. Do not use `/dev/shm` for
the run root, container graph storage, evidence, or logs.

A custom `ASTER_RUN_ROOT` must be an absolute, canonical, non-symlink directory owned by the
current user with mode `0700`. If it does not exist, its canonical parent must already exist; the
script creates the run root with mode `0700`. For example:

```bash
install -d -m 0700 /var/tmp/henry-build/aster-local
ASTER_RUN_ROOT=/var/tmp/henry-build/aster-local bash .scripts/compatibility/run.sh
```

Do not provide fixed service credentials. The lifecycle script generates ephemeral values for each
run and does not write them to evidence.

## Inventory

`compatibility/baseline-manifest.json` is the deterministic schema-version-1 inventory. It combines
runtime OpenAPI operations, advertised OIDC capabilities, connector factories, existing integration
test files, and the reviewed non-HTTP entries in `compatibility/manual-capabilities.json`.

A normal lab run performs these exact checks after building the integration-test package, exporting
the live target configuration, and changing from the repository root to
`packages/integration-tests`:

```bash
cd packages/integration-tests
pnpm compatibility:inventory --target oracle --check
pnpm compatibility:inventory --target candidate --check
```

To intentionally regenerate the committed manifest from the oracle, run this from the repository
root:

```bash
ASTER_WRITE_BASELINE=1 bash .scripts/compatibility/run.sh
```

Inside that same prepared live environment and package directory, the wrapper converts the explicit
request into the only permitted low-level write command:

```bash
ASTER_ALLOW_MANIFEST_WRITE=1 pnpm compatibility:inventory --target oracle --write
```

`--write` is rejected for the candidate and is also rejected unless
`ASTER_ALLOW_MANIFEST_WRITE=1`. Review the resulting manifest diff and then rerun the lab without
`ASTER_WRITE_BASELINE` so both targets pass `--check`. Baseline writes are never enabled in CI.

## Controls and scenarios

The compatibility CLI imports one frozen default scenario registry. In phase 0 it contains the
`discovery` and `password-code` scenarios. The CLI and the Jest smoke test both consume this same
registry, so adding a scenario to the registry automatically includes it in the positive run,
finalized run evidence, and smoke test.

The commands in this section are the low-level commands executed within one `run.sh` lifecycle; they
are not standalone repo-root invocations. Before running them, `run.sh` has started both targets,
exported the live target URLs, image digests, repository root, and private evidence directory, and
changed to `packages/integration-tests`. With that package-directory context and prepared live
environment, the positive control is:

```bash
pnpm compatibility:run
```

It executes every default scenario against both targets, writes sanitized per-scenario evidence,
and exits `0` only when every comparison has zero differences.

The injected negative control is:

```bash
pnpm compatibility:run --fault-injection discovery-issuer
```

It first requires matching live discovery observations, changes only the in-memory candidate issuer,
and must exit `2` after reporting exactly `/observations/0/value/issuer`. It does not modify either
service and does not overwrite the positive evidence. `run.sh` treats that exact exit status as the
expected success condition, then finalizes the run with:

```bash
pnpm compatibility:run --finalize-run \
  --negative-control-path /observations/0/value/issuer
```

The live Jest reference-parity test is opt-in. Without `ASTER_RUN_DUAL_TARGET=1` its live cases are
skipped. `run.sh` opts in after both controls and finalization with the four target URLs it owns:

```bash
ASTER_RUN_DUAL_TARGET=1 \
  pnpm test:only -i --config=jest.config.compatibility.js \
  ./lib/compatibility/tests/reference-parity.test.js
```

## Evidence and privacy

Local runtime artifacts are stored under
`/var/tmp/henry-build/aster-compatibility/run.*/`. CI instead sets the run root to
`${{ runner.temp }}/aster-compatibility-evidence`, because runner temporary storage has a separate
lifecycle from workstation build storage.

Only these JSON evidence files are publishable:

- `evidence/discovery.json` and `evidence/password-code.json`: schema version, scenario ID,
  normalized oracle and candidate observations, and semantic differences.
- `evidence/negative-control.json`: schema version, the `discovery-issuer` injection name, and the
  precise difference path.
- `evidence/run.json`: schema version, pinned reference commit, exact oracle and candidate image
  digests, per-scenario difference counts, and the negative-control difference path.

The committed `baseline-manifest.json` has its own schema: schema version, reference commit, and
sorted capability records containing `id`, `surface`, `source`, and `existingEvidence`.

Evidence must never contain a raw password, authorization code, access token, refresh token, ID
token, cookie value, connector secret, or private key. Public OIDC metadata labels and enum values
such as `refresh_token` describe protocol capabilities and are not credentials. Evidence review
must therefore use the structural sanitizer implemented by the evidence writer, which checks both
JSON structure and credential-shaped values; a naive field-name grep cannot distinguish public
metadata from secret material.

Service, Compose, and private Podman logs remain beside the `evidence/` directory in the private run
directory. They can contain operational detail that is unsuitable for artifacts. Never commit or
upload those logs, and never upload a complete run root. CI uploads only
`run.*/evidence/*.json`.

## Candidate replacement

Later phases replace only the candidate image:

```bash
ASTER_CANDIDATE_IMAGE=registry.example/aster-candidate:reviewed-digest \
  bash .scripts/compatibility/run.sh
```

`ASTER_CANDIDATE_IMAGE` changes the `aster-candidate` service image. It does not change the pinned
oracle build, the scenario registry, target URLs, state isolation, generated ephemeral service
credentials, comparison rules, or evidence policy. Prefer an immutable digest for acceptance runs.

## Frozen baseline

The source pin is intentional. Before starting services, `run.sh` compares runtime source with the
pinned commit and fails when non-lab runtime inputs drift. This prevents ordinary product changes
from silently redefining compatibility. Updating the baseline requires an explicit, reviewed process
that selects a new reference commit, updates every pin, regenerates the inventory, reruns both
controls and the existing product suites, and records new acceptance evidence.

Because the baseline is frozen, this workflow must not be made a required check for unrelated
product branches. Such branches may intentionally differ from the reference and would fail the pin
gate. Expanding required-check coverage requires the baseline-update process first.

## Phase-0 exit criteria

Phase 0 is complete only when all of the following are true:

1. The reference commit is fixed at `6852a7b8c8984c5c12b2061e8c51faa310a36412`.
2. A deterministic manifest inventories runtime OpenAPI operations, OIDC advertised capabilities,
   connector factories, existing integration-test files, and manually enumerated non-HTTP behavior.
3. Two isolated instances of the same reference image complete discovery and password
   authorization-code scenarios with zero unexplained differences.
4. A built-in negative control changes one candidate observation and makes the comparator fail with
   a precise JSON path.
5. Evidence contains no raw password, authorization code, refresh token, access token, ID token,
   cookie value, connector secret, or private key.
6. The existing integration-test API, Experience, and Console commands retain their current
   behavior.
7. CI runs the positive control and negative control and uploads only sanitized evidence.

## Troubleshooting

On success or failure, use the final `[aster] evidence:` path printed by the script. Inspect the
private `*-oracle.log`, `*-candidate.log`, `compose-down.log`, `compose-ps.txt`, or
`podman-service.log` files in that run directory as applicable. Keep the directory at mode `0700`,
share only the minimum redacted diagnostic needed, and delete it when no longer required. Do not
move logs into `compatibility/`, commit them, attach them to CI artifacts, or paste credential-bearing
log content into an issue.
