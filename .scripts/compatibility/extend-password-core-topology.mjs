const fail = () => { throw new TypeError('Invalid Common206 password core topology'); };

export const extendPasswordCoreTopology = (raw, options) => {
  const keys = ['role'];
  if (!options || Object.keys(options).toSorted().join() !== keys.toSorted().join() ||
      !['oracle', 'candidate'].includes(options.role)) fail();
  const document = structuredClone(raw);
  const role = options.role;
  if (role === 'candidate') {
    const h5 = document.services?.['candidate-h5-core'];
    const source = document.services?.['candidate-primary-smtp'];
    if (!h5 || !source || document.services?.['candidate-password-smtp'] ||
        typeof h5.container_name !== 'string' ||
        !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}-candidate-h5-core$/u.test(h5.container_name) ||
        source.environment?.ASTER_SMTP_CONTROL_SOCKET !== '/run/aster-smtp/verification-smtp.sock' ||
        !Array.isArray(source.volumes) || source.volumes.length !== 1) fail();
    const service = structuredClone(source);
    delete service.container_name;
    delete service.networks;
    delete service.ports;
    service.depends_on = { 'candidate-h5-core': { condition: 'service_healthy' } };
    service.environment.ASTER_SMTP_CONTROL_SOCKET = '/run/aster-smtp/password-verification-smtp.sock';
    service.network_mode = 'service:candidate-h5-core';
    service.restart = 'no';
    service.userns_mode = `container:${h5.container_name}`;
    document.services['candidate-password-smtp'] = service;
    return Object.freeze(document);
  }
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
