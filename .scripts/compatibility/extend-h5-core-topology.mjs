import path from 'node:path';

const fail = () => { throw new TypeError('Invalid Common206 H5 core topology'); };
const absolute = (value) => typeof value === 'string' && path.isAbsolute(value) &&
  path.normalize(value) === value && !/[,:\u0000-\u001f\u007f]/u.test(value);

export const extendH5CoreTopology = (raw, options) => {
  const keys = ['candidateConfigFile', 'role'];
  if (!options || Object.keys(options).toSorted().join() !== keys.toSorted().join() ||
      !['oracle', 'candidate'].includes(options.role) || !absolute(options.candidateConfigFile)) fail();
  const document = structuredClone(raw);
  const role = options.role;
  const sourceName = `${role}-primary-core`;
  const serviceName = `${role}-h5-core`;
  const source = document.services?.[sourceName];
  const network = `${role}-primary`;
  if (!source || document.services?.[serviceName] || document.networks?.[network]?.internal !== true) fail();
  const service = structuredClone(source);
  delete service.container_name;
  service.depends_on = structuredClone(source.depends_on ?? {});
  service.environment = { ...source.environment };
  service.networks = { [network]: { ipv4_address: role === 'oracle' ? '172.30.231.14' : '172.30.241.14' } };
  service.ports = ['127.0.0.1::3001'];
  service.restart = 'no';
  if (role === 'oracle') {
    service.environment.ENDPOINT = 'https://localhost:3351';
  } else {
    const originalConfig = source.environment?.ASTER_PHASE1_PRIMARY_CONFIG_FILE;
    if (typeof originalConfig !== 'string' || !Array.isArray(source.volumes)) fail();
    service.environment.ASTER_PHASE1_PRIMARY_CONFIG_FILE = options.candidateConfigFile;
    service.environment.ASTER_PHASE1_DATA_ISSUER = 'https://localhost:3352/oidc';
    service.volumes = source.volumes.map((mount) =>
      mount === `${originalConfig}:${originalConfig}:ro`
        ? `${options.candidateConfigFile}:${options.candidateConfigFile}:ro`
        : mount
    );
    if (!service.volumes.includes(`${options.candidateConfigFile}:${options.candidateConfigFile}:ro`)) fail();
  }
  document.services[serviceName] = service;
  return Object.freeze(document);
};
