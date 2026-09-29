#!/usr/bin/env node
import http from 'node:http';
import path from 'node:path';
import { readFile, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const prefix = root.endsWith(path.sep) ? root : root + path.sep;
const port = Number(process.env.FL_PERF_PORT || 4173);
const mime = new Map([
  ['.css','text/css; charset=utf-8'],['.html','text/html; charset=utf-8'],
  ['.js','text/javascript; charset=utf-8'],['.json','application/json; charset=utf-8'],
  ['.mjs','text/javascript; charset=utf-8'],['.png','image/png'],['.svg','image/svg+xml; charset=utf-8'],
  ['.webmanifest','application/manifest+json; charset=utf-8'],['.ico','image/x-icon'],
  ['.xlsx','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
]);
const server=http.createServer(async (req,res)=>{
  if(!['GET','HEAD'].includes(req.method||'')){res.writeHead(405,{Allow:'GET, HEAD'});res.end();return;}
  let pathname;
  try { pathname=decodeURIComponent(new URL(req.url||'/','http://127.0.0.1').pathname); }
  catch { res.writeHead(400);res.end('Bad request');return; }
  if(pathname==='/') pathname='/index.html';
  let file=path.resolve(root,'.'+pathname);
  if(file!==root && !file.startsWith(prefix)){res.writeHead(403);res.end('Forbidden');return;}
  try{
    let info=await stat(file);
    if(info.isDirectory()) file=path.join(file,'index.html');
    const body=await readFile(file);
    const headers={
      'Content-Type':mime.get(path.extname(file).toLowerCase())||'application/octet-stream',
      'Content-Length':String(body.length),'Cache-Control':'no-store','Service-Worker-Allowed':'/'
    };
    res.writeHead(200,headers); if(req.method==='HEAD')res.end(); else res.end(body);
  }catch(e){res.writeHead(e?.code==='ENOENT'?404:500,{'Content-Type':'text/plain'});res.end(e?.code==='ENOENT'?'Not found':'Server error');}
});
server.listen(port,'127.0.0.1',()=>console.log(`FreightLogic performance server: http://127.0.0.1:${port}`));
for(const sig of ['SIGTERM','SIGINT']) process.on(sig,()=>server.close(()=>process.exit(0)));
