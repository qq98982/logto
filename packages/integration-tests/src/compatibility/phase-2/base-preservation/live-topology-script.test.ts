/* eslint-disable max-lines, no-await-in-loop, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- The source-contract and security failure harnesses stay together so the complete live runner contract remains auditable. */
import { execFile } from 'node:child_process';
import {
  chmod,
  chown,
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rm,
  stat,
  symlink,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

const executeFile = promisify(execFile);
const repositoryRoot = path.resolve(process.cwd(), '../..');
const runnerPath = path.join(
  repositoryRoot,
  '.scripts/compatibility/run-phase2-base-preservation.sh'
);
const acceptedPhase1Runner = '.scripts/compatibility/run-phase1-runtime-candidate.sh';
let source = '';
let temporaryRoot = '';

const createAsterCheckout = async (
  name: string,
  origin = 'https://github.com/qq98982/aster.git'
): Promise<string> => {
  const root = path.join(temporaryRoot, name);
  await mkdir(root, { mode: 0o700 });
  await executeFile('/usr/bin/git', ['init', '--quiet'], { cwd: root });
  await writeFile(path.join(root, 'sentinel.txt'), `${name}\n`);
  await executeFile('/usr/bin/git', ['add', '--', 'sentinel.txt'], { cwd: root });
  await executeFile(
    '/usr/bin/git',
    [
      '-c',
      'user.name=Phase2 Test',
      '-c',
      'user.email=phase2@example.invalid',
      '-c',
      'commit.gpgsign=false',
      'commit',
      '--quiet',
      '-m',
      'fixture',
    ],
    { cwd: root }
  );
  await executeFile('/usr/bin/git', ['remote', 'add', 'origin', origin], { cwd: root });

  return root;
};

describe('Phase 2 base-preservation live runner', () => {
  beforeAll(async () => {
    source = await readFile(runnerPath, 'utf8');
    temporaryRoot = await mkdtemp('/var/tmp/henry-build/phase2-base-runner-test-');
  });

  afterAll(async () => {
    await rm(temporaryRoot, { force: true, recursive: true });
  });

  it('derives the topology runner only from the exact accepted Phase 1 blob', () => {
    expect(source).toContain('83d08f0821345d1bdc01491152949cc6f044ecfb');
    expect(source).toContain(acceptedPhase1Runner);
    expect(source).toContain('rev-parse "$ACCEPTED_H_COMMIT:$PHASE1_RUNNER_RELATIVE"');
    expect(source).toContain('hash-object --no-filters -- "$PHASE1_RUNNER"');
    expect(source).toContain('transform_phase1_runner');
    expect(source).not.toContain('docker-compose.phase1-runtime-candidate-differential.yml');
  });

  it('binds the negative control to the exact live discovery scenario failure', () => {
    expect(source).not.toContain('raw-phase1-negative-control.stderr');
    expect(source).not.toContain('raw_status');
    expect(source).toContain('compatibility/phase-2/base-preservation/launcher.mjs');
    expect(source).toContain('Phase 1 candidate discovery contains unapproved metadata');
    expect(source).toContain("errorName !== 'Error'");
    expect(source).toContain(".replaceAll('\\\\${', '${')");
    expect(source).toContain('phase-2-base-preservation.json');
    expect(source).not.toContain('Phase 1 differential gate passed');
  });

  it('prepares the derived profile for the current H head without substituting the accepted head', async () => {
    const generated = path.join(temporaryRoot, 'derived-runner.sh');
    const harness = path.join(temporaryRoot, 'transform-harness.sh');
    await writeFile(
      harness,
      `#!/usr/bin/env bash\nset -euo pipefail\nsource ${JSON.stringify(
        runnerPath
      )}\nNODE_BIN="$(command -v node)"\ntransform_phase1_runner ${JSON.stringify(
        path.join(repositoryRoot, acceptedPhase1Runner)
      )} ${JSON.stringify(generated)}\n`,
      { mode: 0o500 }
    );

    await executeFile('/usr/bin/bash', [harness]);
    await executeFile('/usr/bin/bash', ['-n', generated]);
    const generatedSource = await readFile(generated, 'utf8');
    const currentHeadArgument = [
      '--harness-commit "',
      '$',
      '{H_HEAD}" --output "',
      '$',
      '{REVIEW_PROFILE}"',
    ].join('');

    expect(generatedSource).toContain(currentHeadArgument);
    expect(generatedSource).not.toContain(
      '--harness-commit "83d08f0821345d1bdc01491152949cc6f044ecfb"'
    );
    expect(generatedSource).not.toContain('raw-phase1-negative-control');
    const mappedWait = `wait "\${NODE_RUN_PID}" || {
  node_run_status=$?
  case "\${node_run_status}" in
    40) failure_stage=base-preservation-arguments ;;
    41) failure_stage=base-preservation-paths ;;
    42) failure_stage=base-preservation-profile ;;
    43) failure_stage=base-preservation-harness ;;
    44) failure_stage=base-preservation-closure ;;
    45) failure_stage=base-preservation-phase1 ;;
    46) failure_stage=base-preservation-runtime ;;
    47) failure_stage=base-preservation-harness-recheck ;;
    48) failure_stage=base-preservation-publish ;;
    6[0-9]|[7-9][0-9]|1[0-5][0-9]|16[0-9])
      scenario_offset=$((node_run_status - 60))
      scenario_index=$((scenario_offset / 5))
      case "$((scenario_offset % 5))" in
        0) scenario_phase=oracle ;;
        1) scenario_phase=candidate ;;
        2) scenario_phase=artifact ;;
        3) scenario_phase=projection ;;
        4) scenario_phase=compare ;;
      esac
      failure_stage="base-preservation-runtime-scenario-\${scenario_index}-\${scenario_phase}"
      ;;
  esac
  fail
}`;
    expect(generatedSource).toContain(mappedWait);
    expect(generatedSource).toContain('>/dev/null 2>&1 &');
    expect(generatedSource).not.toContain('base-preservation.stderr');
    expect(generatedSource).not.toMatch(/(?:cat|read|grep).*stderr/u);
    const phase1Root = ['$', '{ASTER_ROOT}'].join('');
    const phase2Root = ['$', '{PHASE2_ASTER_ROOT}'].join('');
    const gitAuthority = ['$', '{GIT_AUTHORITY[@]}'].join('');

    expect(generatedSource).toContain(
      `PROFILE_SOURCE="${phase1Root}/compatibility/phase-1-profile.json"`
    );
    expect(generatedSource).toContain(
      `PHASE2_PROFILE_SOURCE="${phase2Root}/compatibility/phase-2-profile.json"`
    );
    expect(generatedSource).toContain(
      `CANDIDATE_SOURCE_COMMIT="$("${gitAuthority}" -C "${phase2Root}" rev-parse HEAD)"`
    );
    expect(generatedSource).toContain(
      'value.provenance?.candidate?.sourceCommit !== process.argv[5]'
    );
    expect(generatedSource).not.toContain(
      `PHASE2_PROFILE_SOURCE="${phase1Root}/compatibility/phase-2-profile.json"`
    );
  });

  it('writes one parseable cleanup descriptor JSON document terminated by LF', async () => {
    const generated = path.join(temporaryRoot, 'descriptor-derived-runner.sh');
    const harness = path.join(temporaryRoot, 'descriptor-transform-harness.sh');
    await writeFile(
      harness,
      `#!/usr/bin/env bash\nset -euo pipefail\nsource ${JSON.stringify(
        runnerPath
      )}\nNODE_BIN="$(command -v node)"\ntransform_phase1_runner ${JSON.stringify(
        path.join(repositoryRoot, acceptedPhase1Runner)
      )} ${JSON.stringify(generated)}\n`,
      { mode: 0o500 }
    );
    await executeFile('/usr/bin/bash', [harness]);
    const generatedSource = await readFile(generated, 'utf8');
    const descriptorMarker = ['$', '{ASTER_PHASE2_BASE_CLEANUP_DESCRIPTOR:?required}'].join('');
    const marker = generatedSource.indexOf(descriptorMarker);
    const heredoc = generatedSource.indexOf("<<'NODE'\n", marker);
    const writerStart = heredoc + "<<'NODE'\n".length;
    const writerEnd = generatedSource.indexOf('\nNODE\n', writerStart);
    expect(marker).toBeGreaterThan(0);
    expect(heredoc).toBeGreaterThan(marker);
    expect(writerEnd).toBeGreaterThan(writerStart);
    const writer = path.join(temporaryRoot, 'descriptor-writer.mjs');
    const descriptor = path.join(temporaryRoot, 'cleanup-descriptor.json');
    const projectName = 'aster-phase1-0123456789abcdef';
    const runRoot = path.join(
      temporaryRoot,
      'aster-phase1-runtime-candidate-differential',
      'run.ABC123'
    );
    await writeFile(writer, generatedSource.slice(writerStart, writerEnd), { mode: 0o400 });

    await executeFile(process.execPath, [writer, descriptor, projectName, runRoot]);
    const [bytes, state] = await Promise.all([readFile(descriptor), stat(descriptor)]);
    expect(bytes.at(-1)).toBe(0x0a);
    expect(bytes.subarray(-2).equals(Buffer.from('\\n'))).toBe(false);
    expect(JSON.parse(bytes.toString('utf8'))).toEqual({
      schemaVersion: 1,
      projectName,
      runRoot,
      ports: [3311, 3411, 3312, 3412, 3321, 3421, 3322, 3422, 3331, 3431, 3341, 3441],
    });
    expect(state.mode % 0o1000).toBe(0o600);
    expect(state.nlink).toBe(1);
    expect(state.uid).toBe(process.getuid?.());
  });

  it('loads two distinct clean canonical Aster roots without changing their roles', async () => {
    const phase1Root = await createAsterCheckout('phase1-authority-root');
    const phase2Root = await createAsterCheckout('phase2-candidate-root');
    const harness = path.join(temporaryRoot, 'root-split-success.sh');
    await writeFile(
      harness,
      `#!/usr/bin/env bash\nset -euo pipefail\nsource ${JSON.stringify(
        runnerPath
      )}\nGIT_BIN=/usr/bin/git\nASTER_PHASE1_ASTER_ROOT=${JSON.stringify(
        phase1Root
      )}\nASTER_PHASE2_ASTER_ROOT=${JSON.stringify(
        phase2Root
      )}\nload_required_aster_roots\nprintf '%s\\n%s\\n' "$PHASE1_ASTER_ROOT" "$PHASE2_ASTER_ROOT"\n`,
      { mode: 0o500 }
    );

    await expect(executeFile('/usr/bin/bash', [harness])).resolves.toMatchObject({
      stdout: `${phase1Root}\n${phase2Root}\n`,
      stderr: '',
    });
  });

  it('rejects a missing, dirty, noncanonical or symlinked Phase 2 candidate root', async () => {
    const phase1Root = await createAsterCheckout('phase1-valid-root');
    const dirtyRoot = await createAsterCheckout('phase2-dirty-root');
    const noncanonicalRoot = await createAsterCheckout(
      'phase2-noncanonical-root',
      'https://example.invalid/aster.git'
    );
    const symlinkTarget = await createAsterCheckout('phase2-symlink-target');
    const symlinkRoot = path.join(temporaryRoot, 'phase2-symlink-root');
    await writeFile(path.join(dirtyRoot, 'dirty.txt'), 'dirty\n');
    await symlink(symlinkTarget, symlinkRoot, 'dir');
    const invalidRoots = [undefined, dirtyRoot, noncanonicalRoot, symlinkRoot];

    for (const [index, invalidRoot] of invalidRoots.entries()) {
      const harness = path.join(temporaryRoot, `root-split-invalid-${index}.sh`);
      await writeFile(
        harness,
        `#!/usr/bin/env bash\nset -euo pipefail\nsource ${JSON.stringify(
          runnerPath
        )}\nGIT_BIN=/usr/bin/git\nASTER_PHASE1_ASTER_ROOT=${JSON.stringify(phase1Root)}\n${
          invalidRoot === undefined
            ? 'unset ASTER_PHASE2_ASTER_ROOT'
            : `ASTER_PHASE2_ASTER_ROOT=${JSON.stringify(invalidRoot)}`
        }\nif load_required_aster_roots; then exit 11; fi\n`,
        { mode: 0o500 }
      );

      await expect(executeFile('/usr/bin/bash', [harness])).resolves.toMatchObject({ stderr: '' });
    }
  });

  it('rejects root conflation instead of falling back to the Phase 1 authority root', async () => {
    const sharedRoot = await createAsterCheckout('shared-aster-root');
    const harness = path.join(temporaryRoot, 'root-conflation-harness.sh');
    await writeFile(
      harness,
      `#!/usr/bin/env bash\nset -euo pipefail\nsource ${JSON.stringify(
        runnerPath
      )}\nGIT_BIN=/usr/bin/git\nASTER_PHASE1_ASTER_ROOT=${JSON.stringify(
        sharedRoot
      )}\nASTER_PHASE2_ASTER_ROOT=${JSON.stringify(
        sharedRoot
      )}\nif load_required_aster_roots; then exit 11; fi\n`,
      { mode: 0o500 }
    );

    await expect(executeFile('/usr/bin/bash', [harness])).resolves.toMatchObject({ stderr: '' });
  });

  it('publishes only after the accepted child runner has completed cleanup', () => {
    const child = source.lastIndexOf('run_transformed_topology "$generated"');
    const finalization = source.lastIndexOf('finalize_cleanup_evidence "$staging/$ARTIFACT_NAME"');
    const publication = source.lastIndexOf('publish_verified_result "$staging"');
    const registration = source.indexOf('PUBLISHED_RESULT="$destination"');
    const move = source.indexOf('/usr/bin/mv --no-clobber --no-target-directory');

    expect(child).toBeGreaterThan(0);
    expect(finalization).toBeGreaterThan(child);
    expect(publication).toBeGreaterThan(finalization);
    expect(registration).toBeGreaterThan(0);
    expect(move).toBeGreaterThan(registration);
    expect(source).toContain('PUBLISHED_IDENTITY="$staging_identity"');
    expect(source).toContain('--no-clobber --no-target-directory');
    expect(source).toContain('aster-phase2-base-preservation-results');
    expect(source).toContain('trap cleanup EXIT');
  });

  it('keeps secrets out of arguments, logs, evidence and shared memory', () => {
    expect(source).not.toContain('/dev/shm');
    expect(source).not.toMatch(/set\s+-x/u);
    expect(source).not.toMatch(/(?:PASSWORD|SECRET_VAULT_KEK|STATUS_API_KEY).*printf/u);
    expect(source).toContain('>/dev/null 2>&1');
    expect(source).toContain('umask 077');
  });

  it('accepts only canonical trusted Node executables with the exact closed-environment version', async () => {
    const directory = path.join(temporaryRoot, 'trusted-node');
    const valid = path.join(directory, 'node-valid');
    const groupWritable = path.join(directory, 'node-group-writable');
    const wrongVersion = path.join(directory, 'node-wrong-version');
    const worldWritable = path.join(directory, 'node-world-writable');
    const foreignGroupWritable = path.join(directory, 'node-foreign-group-writable');
    const linked = path.join(directory, 'node-link');
    const harness = path.join(temporaryRoot, 'trusted-node-harness.sh');
    const validSource = "#!/usr/bin/env bash\nprintf '%s\\n' 'v22.23.2'\n";
    await mkdir(directory, { mode: 0o700 });
    await Promise.all([
      writeFile(valid, validSource, { mode: 0o755 }),
      writeFile(groupWritable, validSource, { mode: 0o775 }),
      writeFile(wrongVersion, "#!/usr/bin/env bash\nprintf '%s\\n' 'v22.23.1'\n", {
        mode: 0o755,
      }),
      writeFile(worldWritable, validSource, { mode: 0o757 }),
      writeFile(foreignGroupWritable, validSource, { mode: 0o775 }),
    ]);
    await Promise.all([
      chmod(valid, 0o755),
      chmod(groupWritable, 0o775),
      chmod(wrongVersion, 0o755),
      chmod(worldWritable, 0o757),
      chmod(foreignGroupWritable, 0o775),
      symlink(valid, linked),
    ]);
    const alternateGroup = process.getgroups?.().find((group) => group !== process.getgid?.());
    expect(alternateGroup).toBeDefined();
    await chown(foreignGroupWritable, process.getuid?.() ?? -1, alternateGroup ?? -1);
    await writeFile(
      harness,
      `#!/usr/bin/env bash\nset -euo pipefail\nsource ${JSON.stringify(
        runnerPath
      )}\n[[ "$(trusted_binary ${JSON.stringify(valid)})" == ${JSON.stringify(
        valid
      )} ]]\n[[ "$(trusted_binary ${JSON.stringify(groupWritable)})" == ${JSON.stringify(
        groupWritable
      )} ]]\n[[ "$(trusted_binary /usr/bin/node)" == /usr/bin/node ]]\n[[ "$(resolve_trusted_node ${JSON.stringify(valid)})" == ${JSON.stringify(
        valid
      )} ]]\nfor invalid in ${JSON.stringify(linked)} ${JSON.stringify(
        worldWritable
      )} ${JSON.stringify(
        foreignGroupWritable
      )}; do if trusted_binary "$invalid" >/dev/null 2>&1; then exit 11; fi; done\nif resolve_trusted_node ${JSON.stringify(
        wrongVersion
      )} >/dev/null 2>&1; then exit 12; fi\nif resolve_trusted_node /usr/bin/node >/dev/null 2>&1; then exit 13; fi\n`,
      { mode: 0o500 }
    );

    await expect(executeFile('/usr/bin/bash', [harness])).resolves.toMatchObject({ stderr: '' });
    expect(source).toContain('NODE_BIN="$(resolve_trusted_node node)"');
    expect(source).toContain('[[ "$version" == \'v22.23.2\' ]]');
    expect(source).toContain("/usr/bin/env -i PATH='/usr/bin:/bin'");
  });

  it('rejects publication unless the staging directory has one private fixed artifact', async () => {
    const stagingRoot = path.join(temporaryRoot, 'staging');
    const resultRoot = path.join(temporaryRoot, 'results');
    const staging = path.join(stagingRoot, 'result.test');
    const harness = path.join(temporaryRoot, 'publish-harness.sh');
    await mkdir(staging, { mode: 0o700, recursive: true });
    await mkdir(resultRoot, { mode: 0o700 });
    await writeFile(path.join(staging, 'wrong.json'), '{}', { mode: 0o600 });
    await writeFile(
      harness,
      `#!/usr/bin/env bash\nset -euo pipefail\nsource ${JSON.stringify(runnerPath)}\nRESULT_ROOT=${JSON.stringify(
        resultRoot
      )}\nSTAGING_ROOT=${JSON.stringify(stagingRoot)}\nif publish_verified_result ${JSON.stringify(
        staging
      )} >/dev/null 2>&1; then exit 11; fi\n`,
      { mode: 0o500 }
    );

    await expect(executeFile('/usr/bin/bash', [harness])).resolves.toMatchObject({ stderr: '' });
  });

  it('atomically records the exact cleanup outcome once and rejects a second modification', async () => {
    const directory = path.join(temporaryRoot, 'finalize');
    const artifact = path.join(directory, 'phase-2-base-preservation.json');
    const harness = path.join(temporaryRoot, 'finalize-harness.sh');
    await mkdir(directory, { mode: 0o700 });
    await writeFile(
      artifact,
      `${JSON.stringify({
        schemaVersion: 1,
        mode: 'phase-2-base-preservation',
        sanitizerSuccess: true,
        rawPhase1NegativeControl: {
          scenarioId: 'discovery.config',
          detected: true,
          errorName: 'Error',
          error: 'Phase 1 candidate discovery contains unapproved metadata',
        },
      })}\n`,
      { mode: 0o600 }
    );
    await writeFile(
      harness,
      `#!/usr/bin/env bash\nset -euo pipefail\nsource ${JSON.stringify(
        runnerPath
      )}\nNODE_BIN="$(command -v node)"\nfinalize_cleanup_evidence ${JSON.stringify(
        artifact
      )}\nif finalize_cleanup_evidence ${JSON.stringify(artifact)}; then exit 11; fi\n`,
      { mode: 0o500 }
    );

    await executeFile('/usr/bin/bash', [harness]);
    const value = JSON.parse(await readFile(artifact, 'utf8')) as Record<string, unknown>;

    expect(value.cleanup).toEqual({
      status: 'verified',
      containersAbsent: true,
      networksAbsent: true,
      volumesAbsent: true,
      runRootAbsent: true,
      portsReleased: [3311, 3411, 3312, 3412, 3321, 3421, 3322, 3422, 3331, 3431, 3341, 3441],
    });
    expect(await readdir(directory)).toEqual(['phase-2-base-preservation.json']);
  });

  it('fails closed when a post-cleanup engine query fails', async () => {
    const buildRoot = path.join(temporaryRoot, 'cleanup-build');
    const runRoot = path.join(
      buildRoot,
      'aster-phase1-runtime-candidate-differential',
      'run.ABC123'
    );
    const descriptor = path.join(temporaryRoot, 'cleanup-descriptor.json');
    const harness = path.join(temporaryRoot, 'cleanup-query-harness.sh');
    await mkdir(buildRoot, { mode: 0o700 });
    await writeFile(
      descriptor,
      `${JSON.stringify({
        schemaVersion: 1,
        projectName: 'aster-phase1-0123456789abcdef',
        runRoot,
        ports: [3311, 3411, 3312, 3412, 3321, 3421, 3322, 3422, 3331, 3431, 3341, 3441],
      })}\n`,
      { mode: 0o600 }
    );
    await writeFile(
      harness,
      `#!/usr/bin/env bash\nset -euo pipefail\nsource ${JSON.stringify(
        runnerPath
      )}\nNODE_BIN="$(command -v node)"\nBUILD_ROOT=${JSON.stringify(
        buildRoot
      )}\nengine_cli() { return 7; }\nassert_ports_released() { return 0; }\nif verify_cleanup_state ${JSON.stringify(
        descriptor
      )}; then exit 11; fi\n`,
      { mode: 0o500 }
    );

    await expect(executeFile('/usr/bin/bash', [harness])).resolves.toMatchObject({ stderr: '' });
  });

  it('accepts cleanup only after the exact run root, project resources and fixed ports are absent', async () => {
    const buildRoot = path.join(temporaryRoot, 'verified-build');
    const runRoot = path.join(
      buildRoot,
      'aster-phase1-runtime-candidate-differential',
      'run.GHI789'
    );
    const descriptor = path.join(temporaryRoot, 'verified-descriptor.json');
    const harness = path.join(temporaryRoot, 'verified-cleanup-harness.sh');
    await mkdir(buildRoot, { mode: 0o700 });
    await writeFile(
      descriptor,
      `${JSON.stringify({
        schemaVersion: 1,
        projectName: 'aster-phase1-0011223344556677',
        runRoot,
        ports: [3311, 3411, 3312, 3412, 3321, 3421, 3322, 3422, 3331, 3431, 3341, 3441],
      })}\n`,
      { mode: 0o600 }
    );
    await writeFile(
      harness,
      `#!/usr/bin/env bash\nset -euo pipefail\nsource ${JSON.stringify(
        runnerPath
      )}\nNODE_BIN="$(command -v node)"\nBUILD_ROOT=${JSON.stringify(
        buildRoot
      )}\nengine_cli() { return 0; }\nassert_ports_released() { [[ "$*" == '3311 3411 3312 3412 3321 3421 3322 3422 3331 3431 3341 3441' ]]; }\nverify_cleanup_state ${JSON.stringify(
        descriptor
      )}\n`,
      { mode: 0o500 }
    );

    await expect(executeFile('/usr/bin/bash', [harness])).resolves.toMatchObject({ stderr: '' });
  });

  it('rejects a successful child cleanup when a labeled project container remains', async () => {
    const buildRoot = path.join(temporaryRoot, 'remaining-build');
    const runRoot = path.join(
      buildRoot,
      'aster-phase1-runtime-candidate-differential',
      'run.DEF456'
    );
    const descriptor = path.join(temporaryRoot, 'remaining-descriptor.json');
    const harness = path.join(temporaryRoot, 'remaining-resource-harness.sh');
    await mkdir(buildRoot, { mode: 0o700 });
    await writeFile(
      descriptor,
      `${JSON.stringify({
        schemaVersion: 1,
        projectName: 'aster-phase1-fedcba9876543210',
        runRoot,
        ports: [3311, 3411, 3312, 3412, 3321, 3421, 3322, 3422, 3331, 3431, 3341, 3441],
      })}\n`,
      { mode: 0o600 }
    );
    await writeFile(
      harness,
      `#!/usr/bin/env bash\nset -euo pipefail\nsource ${JSON.stringify(
        runnerPath
      )}\nNODE_BIN="$(command -v node)"\nBUILD_ROOT=${JSON.stringify(
        buildRoot
      )}\nengine_cli() { if [[ "$1" == ps ]]; then printf '%064d' 0; fi; }\nassert_ports_released() { return 0; }\nif verify_cleanup_state ${JSON.stringify(
        descriptor
      )}; then exit 11; fi\n`,
      { mode: 0o500 }
    );

    await expect(executeFile('/usr/bin/bash', [harness])).resolves.toMatchObject({ stderr: '' });
  });

  it('rejects publication of an artifact without the finalized cleanup proof', async () => {
    const stagingRoot = path.join(temporaryRoot, 'unfinalized-staging');
    const resultRoot = path.join(temporaryRoot, 'unfinalized-results');
    const staging = path.join(stagingRoot, 'result.test');
    const harness = path.join(temporaryRoot, 'unfinalized-publish-harness.sh');
    await mkdir(staging, { mode: 0o700, recursive: true });
    await mkdir(resultRoot, { mode: 0o700 });
    await writeFile(path.join(staging, 'phase-2-base-preservation.json'), '{}\n', {
      mode: 0o600,
    });
    await writeFile(
      harness,
      `#!/usr/bin/env bash\nset -euo pipefail\nsource ${JSON.stringify(runnerPath)}\nRESULT_ROOT=${JSON.stringify(
        resultRoot
      )}\nSTAGING_ROOT=${JSON.stringify(stagingRoot)}\nNODE_BIN="$(command -v node)"\nif publish_verified_result ${JSON.stringify(
        staging
      )} >/dev/null 2>&1; then exit 11; fi\n`,
      { mode: 0o500 }
    );

    await expect(executeFile('/usr/bin/bash', [harness])).resolves.toMatchObject({ stderr: '' });
  });

  it('removes private staging evidence on outer failure while preserving the status', async () => {
    const stagingRoot = path.join(temporaryRoot, 'rollback-staging');
    const resultRoot = path.join(temporaryRoot, 'rollback-results');
    const staging = path.join(stagingRoot, 'result.test');
    const harness = path.join(temporaryRoot, 'rollback-harness.sh');
    await mkdir(staging, { mode: 0o700, recursive: true });
    await mkdir(resultRoot, { mode: 0o700 });
    await writeFile(path.join(staging, 'phase-2-base-preservation.json'), '{"private":true}\n', {
      mode: 0o600,
    });
    await writeFile(
      harness,
      `#!/usr/bin/env bash\nset -euo pipefail\nsource ${JSON.stringify(runnerPath)}\nSTAGING_ROOT=${JSON.stringify(
        stagingRoot
      )}\nRESULT_ROOT=${JSON.stringify(resultRoot)}\nSTAGING_DIR=${JSON.stringify(
        staging
      )}\nSTAGING_IDENTITY="$(capture_path_identity "$STAGING_DIR")"\nWORK_ROOT=''\ntrap cleanup EXIT\nexit 23\n`,
      { mode: 0o500 }
    );

    await expect(executeFile('/usr/bin/bash', [harness])).rejects.toMatchObject({ code: 23 });
    await expect(readFile(path.join(staging, 'phase-2-base-preservation.json'))).rejects.toThrow();
  });

  it('removes per-run staging when cleanup verification fails before staging discovery', async () => {
    const workRoot = path.join(temporaryRoot, 'verification-failure-work');
    const staging = path.join(workRoot, 'staging', 'result.test');
    const artifact = path.join(staging, 'phase-2-base-preservation.json');
    const harness = path.join(temporaryRoot, 'verification-failure-harness.sh');
    await mkdir(staging, { mode: 0o700, recursive: true });
    await writeFile(artifact, '{"private":true}\n', { mode: 0o600 });
    await writeFile(
      harness,
      `#!/usr/bin/env bash\nset -euo pipefail\nsource ${JSON.stringify(runnerPath)}\nWORK_ROOT=${JSON.stringify(
        workRoot
      )}\nSTAGING_ROOT="$WORK_ROOT/staging"\nSTAGING_DIR=''\nRESULT_DIR=''\ntrap cleanup EXIT\nexit 29\n`,
      { mode: 0o500 }
    );

    await expect(executeFile('/usr/bin/bash', [harness])).rejects.toMatchObject({ code: 29 });
    await expect(readFile(artifact)).rejects.toThrow();
  });

  it('rolls back a moved result when execution fails before main registers the result', async () => {
    const stagingRoot = path.join(temporaryRoot, 'post-move-staging');
    const resultRoot = path.join(temporaryRoot, 'post-move-results');
    const staging = path.join(stagingRoot, 'result.test');
    const artifact = path.join(staging, 'phase-2-base-preservation.json');
    const harness = path.join(temporaryRoot, 'post-move-failure-harness.sh');
    await mkdir(staging, { mode: 0o700, recursive: true });
    await mkdir(resultRoot, { mode: 0o700 });
    await writeFile(
      artifact,
      `${JSON.stringify({
        schemaVersion: 1,
        mode: 'phase-2-base-preservation',
        sanitizerSuccess: true,
        rawPhase1NegativeControl: {
          scenarioId: 'discovery.config',
          detected: true,
          errorName: 'Error',
          error: 'Phase 1 candidate discovery contains unapproved metadata',
        },
      })}\n`,
      { mode: 0o600 }
    );
    await writeFile(
      harness,
      `#!/usr/bin/env bash\nset -euo pipefail\nsource ${JSON.stringify(
        runnerPath
      )}\nNODE_BIN="$(command -v node)"\nRESULT_ROOT=${JSON.stringify(
        resultRoot
      )}\nSTAGING_ROOT=${JSON.stringify(stagingRoot)}\nSTAGING_DIR=${JSON.stringify(
        staging
      )}\nSTAGING_IDENTITY="$(capture_path_identity "$STAGING_DIR")"\nRESULT_DIR=''\nRESULT_IDENTITY=''\nWORK_ROOT=''\ntrap cleanup EXIT\nfinalize_cleanup_evidence ${JSON.stringify(
        artifact
      )}\npublish_verified_result "$STAGING_DIR" >/dev/null\n[[ -d "$PUBLISHED_RESULT" ]]\nexit 31\n`,
      { mode: 0o500 }
    );

    await expect(executeFile('/usr/bin/bash', [harness])).rejects.toMatchObject({ code: 31 });
    await expect(readdir(resultRoot)).resolves.toEqual([]);
  });
});

/* eslint-enable max-lines, no-await-in-loop, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
