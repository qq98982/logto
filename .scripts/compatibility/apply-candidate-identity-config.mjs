import path from 'node:path';
const fail=()=>{throw new TypeError('Invalid Common206 candidate identity configuration');};
const absolute=value=>typeof value==='string'&&value.startsWith('/')&&path.normalize(value)===value&&!/[,:\u0000-\u001f\u007f]/u.test(value);
export const applyCandidateIdentityConfig=(document,options)=>{
 if(!options||!absolute(options.configurationFile)||!absolute(options.caFile))fail();
 const output=structuredClone(document); const core=output.services?.['candidate-primary-core']; if(!core)fail();
 const environment=core.environment??{}; if(Object.hasOwn(environment,'ASTER_ISOLATED_IDENTITY_TRANSPORT_CONFIG'))fail();
 const volumes=core.volumes??[]; if(!Array.isArray(volumes))fail();
 core.environment={...environment,ASTER_ISOLATED_IDENTITY_TRANSPORT_CONFIG:'/run/aster/identity-transports.json'};
 core.volumes=[...volumes,`${options.configurationFile}:/run/aster/identity-transports.json:ro`,`${options.caFile}:/run/aster/identity-fixture-ca.pem:ro`];
 return Object.freeze(output);
};
