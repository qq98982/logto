import { createServer } from 'node:https';
import { request } from 'node:http';
import { readFileSync, lstatSync } from 'node:fs';
const [listen, upstream, cert, key] = process.argv.slice(2);
if (!['3351','3352'].includes(listen) || !/^[1-9][0-9]{0,4}$/.test(upstream) || Number(upstream)>65535) process.exit(1);
for (const file of [cert,key]) { const state=lstatSync(file); if(!file.startsWith('/var/tmp/henry-build/')||!state.isFile()||state.isSymbolicLink()||state.uid!==process.getuid()||(state.mode&0o777)!==0o600)process.exit(1); }
const server=createServer({cert:readFileSync(cert),key:readFileSync(key)},(incoming,outgoing)=>{
 const headers={...incoming.headers,'x-forwarded-proto':'https','x-forwarded-host':incoming.headers.host}; delete headers.forwarded;
 const proxy=request({hostname:'127.0.0.1',port:Number(upstream),method:incoming.method,path:incoming.url,headers},response=>{outgoing.writeHead(response.statusCode??502,response.headers);response.pipe(outgoing);});
 proxy.on('error',()=>{if(!outgoing.headersSent)outgoing.writeHead(502);outgoing.end();}); incoming.on('aborted',()=>proxy.destroy());incoming.pipe(proxy);
});
server.listen(Number(listen),'127.0.0.1');
for(const signal of ['SIGTERM','SIGINT'])process.once(signal,()=>server.close(()=>process.exit(0)));
