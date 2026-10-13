const fail = () => { throw new TypeError('Invalid Common206 password core topology'); };

export const extendPasswordCoreTopology = (raw, options) => {
  const keys = ['role'];
  if (!options || Object.keys(options).toSorted().join() !== keys.toSorted().join() ||
      options.role !== 'oracle') fail();
  const document = structuredClone(raw);
  const role = options.role;
  const sourceName = `${role}-primary-core`;
  const serviceName = `${role}-password-core`;
  const source = document.services?.[sourceName];
  const network = `${role}-primary`;
  if (!source || document.services?.[serviceName] || document.networks?.[network]?.internal !== true) fail();
  const service = structuredClone(source);
  const expectedHealth = 'nc -z localhost 3001 && nc -z localhost 3411';
  if (!service.healthcheck || service.healthcheck.test?.length !== 2 ||
      service.healthcheck.test[0] !== 'CMD-SHELL' || service.healthcheck.test[1] !== expectedHealth) fail();
  service.healthcheck.test = ['CMD-SHELL', 'nc -z localhost 3001'];
  delete service.container_name;
  service.depends_on = structuredClone(source.depends_on ?? {});
  service.environment = { ...source.environment, INTEGRATION_TEST: 'false' };
  service.networks = { [network]: { ipv4_address: '172.30.231.15' } };
  service.ports = ['127.0.0.1::3001'];
  service.restart = 'no';
  service.environment.ENDPOINT = 'https://localhost:3361';
  document.services[serviceName] = service;
  return Object.freeze(document);
};
