import { readFileSync, realpathSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const [source, runDir, output] = process.argv.slice(2);
if (!source || !runDir || !output || output !== path.join(runDir, 'podman-differential-compose.json')) {
  throw new Error('invalid private Podman topology paths');
}
const runStat = statSync(runDir);
if (realpathSync(runDir) !== runDir || runStat.uid !== process.getuid() ||
    (runStat.mode & 0o777) !== 0o700) {
  throw new Error('private run directory is not owned and mode 0700');
}

const document = JSON.parse(readFileSync(source, 'utf8'));
const candidates = [
  'candidate-primary-init',
  'candidate-primary-core',
  'candidate-foreign-init',
  'candidate-foreign-core',
  'candidate-fixture-coordinator',
];
const expectedTmpfs = [
  '/tmp:rw,noexec,nosuid,nodev,size=64m,uid=${ASTER_PHASE1_RUNTIME_UID:?required},gid=${ASTER_PHASE1_RUNTIME_GID:?required},mode=0700',
  '/run/aster:rw,noexec,nosuid,nodev,size=16m,uid=${ASTER_PHASE1_RUNTIME_UID:?required},gid=${ASTER_PHASE1_RUNTIME_GID:?required},mode=0700',
];
// Podman's compatibility API drops tmpfs uid/gid; private mounts, fixed nonroot user and umask 077
// allow the conformance modes while preserving the mount flags and size bounds.
const podmanTmpfs = [
  '/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777',
  '/run/aster:rw,noexec,nosuid,nodev,size=16m,mode=0777',
];

for (const name of candidates) {
  const service = document.services[name];
  if (service?.userns_mode !== 'host' || JSON.stringify(service.tmpfs) !== JSON.stringify(expectedTmpfs) ||
      service.user !== '${ASTER_PHASE1_RUNTIME_UID:?required}:${ASTER_PHASE1_RUNTIME_GID:?required}') {
    throw new Error(`unexpected candidate topology: ${name}`);
  }
  service.tmpfs = podmanTmpfs;
  service.userns_mode = 'keep-id';
}

const relativeInitMount = './.scripts/compatibility/phase1-candidate-postgres-init.sh:/docker-entrypoint-initdb.d/010-aster-phase1-hba.sh:ro';
for (const name of ['candidate-primary-postgres', 'candidate-foreign-postgres']) {
  const service = document.services[name];
  if (service?.volumes?.filter((mount) => mount === relativeInitMount).length !== 1) {
    throw new Error(`unexpected postgres init mount: ${name}`);
  }
  service.volumes = service.volumes.map((mount) => mount === relativeInitMount
    ? `${path.join(path.dirname(source), '.scripts/compatibility/phase1-candidate-postgres-init.sh')}:/docker-entrypoint-initdb.d/010-aster-phase1-hba.sh:ro`
    : mount);
}

writeFileSync(output, JSON.stringify(document), { flag: 'wx', mode: 0o600 });
