# Phase-0 compatibility acceptance

## Status and scope

Local Phase-0 acceptance passed on 2026-08-29 for the runnable open-source repository. The
compatibility boundary excludes the proprietary Cloud backend. The hosted CI observation remains
pending because the branch is local and has not been pushed; no GitHub-hosted workflow or artifact
run is claimed.

## Reference and runtime identity

| Item                          | Observed value                                                            |
| ----------------------------- | ------------------------------------------------------------------------- |
| Validated implementation HEAD | `28f6237700c6b5a1a5d32d6d9bb9a1d8bb77cdda`                                |
| Clean regression checkout     | `86bcf75908f34a2af789b77ff36b92730d2f76b4`                                |
| Acceptance checkout state     | Clean before every final command                                          |
| Reference commit              | `6852a7b8c8984c5c12b2061e8c51faa310a36412`                                |
| Oracle image ID               | `sha256:9192b78e3629f1096428b0833bd1b95a2b07f1d041a6da0728dff712c526b9a6` |
| Candidate image ID            | `sha256:9192b78e3629f1096428b0833bd1b95a2b07f1d041a6da0728dff712c526b9a6` |

The oracle and candidate used independent runtime state while running the same reference image.

## Capability inventory

The schema-version-1 baseline contains 667 capabilities.

| Surface          |   Count |
| ---------------- | ------: |
| connector        |      55 |
| experience-api   |      37 |
| integration-test |     229 |
| management-api   |     275 |
| manual           |      15 |
| oidc             |      18 |
| user-api         |      38 |
| **Total**        | **667** |

## Scenarios and control

| Execution                     | Observed result                                                         | Status               |
| ----------------------------- | ----------------------------------------------------------------------- | -------------------- |
| `discovery`                   | 0 differences                                                           | Passed               |
| `password-code`               | 0 differences                                                           | Passed               |
| Injected negative control     | Exact difference at `/observations/0/value/issuer`; comparator exited 2 | Detected as required |
| Outer lab lifecycle           | Converted the expected inner exit 2 to exit 0                           | Passed               |
| Live compatibility Jest check | 3 of 3 tests passed                                                     | Passed               |

## Commands and attempts

Every listed command returned outer exit status 0. The package gates and compatibility lab ran at
validated implementation HEAD `28f623770`; all three integration commands were then rerun from the
clean regression checkout `86bcf7590`. That checkout differs from the implementation HEAD only by
this acceptance record.

| Command                                                     | Acceptance attempt      | Result                                                                           |                  Wall duration |
| ----------------------------------------------------------- | ----------------------- | -------------------------------------------------------------------------------- | -----------------------------: |
| `pnpm --filter @logto/integration-tests check`              | Final                   | Passed                                                                           |                         4.11 s |
| `pnpm --filter @logto/integration-tests lint`               | Final                   | Passed with no errors and 8 existing warnings                                    |                        23.45 s |
| `pnpm --filter @logto/integration-tests build`              | Final                   | Passed                                                                           |                         1.15 s |
| `pnpm --filter @logto/integration-tests test:compatibility` | Final                   | 9 suites passed, 1 skipped; 540 tests passed, 3 skipped                          |                         5.80 s |
| `./.scripts/compatibility/run.sh`                           | Final                   | Positive and negative controls passed; live Jest 3/3                             |                       120.39 s |
| `actionlint .github/workflows/compatibility-test.yml`       | Final                   | Passed with v1.7.12; release attestation verified                                |                         0.01 s |
| `./.scripts/integration/run.sh api`                         | Post-record clean rerun | 176 suites passed, 4 skipped; 1,310 tests passed, 50 skipped; 9 snapshots passed | 575.15 s total; 340.416 s Jest |
| `./.scripts/integration/run.sh experience`                  | Post-record clean rerun | 26 suites passed, 1 skipped; 129 tests passed, 2 skipped                         | 534.87 s total; 507.454 s Jest |
| `./.scripts/integration/run.sh console`                     | Post-record clean rerun | 18 suites passed, 3 skipped; 144 tests passed, 9 skipped                         | 480.59 s total; 287.329 s Jest |

Workstation Podman required active healthcheck polling and a private Compose v5 adapter; repository
commands were unchanged. The API run required a loopback host database mapping for three direct
database suites. Its first post-record invocation stopped before Jest when the Podman image build
hit a transient `pnpm` `ENOTEMPTY` error; the clean retry passed.

The UI runs used `CI=1` and Puppeteer Chrome 131.0.6778.87 installed under
`/var/tmp/henry-build/puppeteer`. Before the post-record verification, the first Experience setup
stopped before Jest because the browser was absent, and a later WebAuthn attempt had two failures;
the final pre-record attempt passed within the upstream maximum-three-attempt workflow policy. The
post-record clean rerun passed on its first Jest attempt, including WebAuthn.

Console required a bridge-preserving container-loopback proxy on port 9998, propagation of the SSRF
test switch, and deletion of the two fixed admin seed users before Jest. Commit `28f623770` changed
connector selection from an unstable first factory ID to the visible group name. The complete
Console command then passed both immediately after the fix and again from the clean regression
checkout.

## Evidence, privacy, and cleanup

Final sanitized evidence is stored at
`/var/tmp/henry-build/aster-compatibility/run.T3xs5y/evidence`. The directory mode is `0700`; its four
JSON files are each mode `0600`. The structural sanitizer passed. No service, API, browser, or
Compose logs are embedded in this record.

Lifecycle cleanup passed with no remaining lab listeners or resources. Existing pre-run container
IDs and states were verified unchanged.

## CI status

The GitHub workflow is committed and configured, its local lifecycle command passed, and actionlint
v1.7.12 reported no errors. Because the branch is local and unpushed, a hosted workflow run and
sanitized artifact upload have not been observed. Phase-0 exit criterion 7 therefore still needs
that external acceptance observation; it is not Phase 1 work.

## Remaining Phase 1 prerequisites

- non-spoofable RLS context
- admin/data-tenant split
- compatibility-host isolation

## Residual risks

- The upstream integration workflow permits up to three attempts, so a passing final Experience
  attempt does not eliminate intermittent browser-suite risk.
- Hosted cold-run duration and runner-specific behavior remain unmeasured until the branch is pushed.
