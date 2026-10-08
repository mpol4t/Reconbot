const {test,before,after} = require('node:test');
const assert = require('node:assert/strict'), fs=require('node:fs'),os=require('node:os'),path=require('node:path'),esbuild=require('esbuild');
const root=path.resolve(__dirname,'../..'),scratch=fs.mkdtempSync(path.join(os.tmpdir(),'reconbot-sqlmap-tests-'));
let api;
before(async()=>{
  const file=path.join(scratch,'api.cjs');
  await esbuild.build({stdin:{contents:`export {SqlmapValidation} from './src/main/sqlmapValidation'; export {validateSqlmapRequest} from './src/shared/sqlmap';`,resolveDir:path.join(root,'desktop')},bundle:true,platform:'node',format:'cjs',outfile:file});
  api=require(file);
});
after(()=>fs.rmSync(scratch,{recursive:true,force:true}));
function request(runDir){return {runDir,url:'http://localhost:8082/item?id=1',parameter:'id',method:'GET',body:'',cookie:'',level:1,risk:1,duration:10,timeout:2,delay:0,threads:1};}
test('scope and typed options are checked before process creation',()=>{
  const valid=request(scratch);api.validateSqlmapRequest(valid,'http://localhost:8082');
  for(const value of [{...valid,url:'http://other.test:8082/?id=1'},{...valid,parameter:'id,--dump'},{...valid,risk:3},{...valid,threads:NaN},{...valid,delay:Infinity},{...valid,cookie:'a\nHeader: b'}])assert.throws(()=>api.validateSqlmapRequest(value,'http://localhost:8082'));
});
test('history isolates runs, stale running results are incomplete, and log reads are bounded',async()=>{
  const owner=new api.SqlmapValidation(root),runA=path.join(scratch,'run-a'),runB=path.join(scratch,'run-b');
  const dir=path.join(runA,'validations/sqlmap/job');fs.mkdirSync(dir,{recursive:true});fs.mkdirSync(runB);
  const job={...request(runA),jobDir:dir,jobId:'job',status:'running',evidence:[],startedAt:'2026-10-07',reportPath:path.join(dir,'report.html')};
  fs.writeFileSync(path.join(dir,'result.json'),JSON.stringify(job));fs.writeFileSync(path.join(dir,'sqlmap.log'),'x'.repeat(90000));
  assert.equal(owner.snapshot(runA).jobs[0].status,'inconclusive');assert.equal(owner.snapshot(runA).log.length,65536);
  assert.equal(owner.snapshot(runB).jobs.length,0);
  assert.equal(owner.start(request(runB),runA,'http://localhost:8082').ok,false);
  await owner.dispose();
});
test('actual backend cancellation is durable and concurrent start is rejected',async()=>{
  const shimDir=path.join(scratch,'bin');fs.mkdirSync(shimDir);
  const shim=path.join(shimDir,'sqlmap');fs.writeFileSync(shim,'#!/usr/bin/env python3\nimport sys,time\nif "--version" in sys.argv: print("fixture"); sys.exit(0)\nprint("ready",flush=True)\ntime.sleep(300)\n');fs.chmodSync(shim,0o755);
  const prior=process.env.PATH;process.env.PATH=shimDir+path.delimiter+prior;
  const owner=new api.SqlmapValidation(root),run=path.join(scratch,'run-live');fs.mkdirSync(run);
  try{
    assert.equal(owner.start(request(run),run,'http://localhost:8082').ok,true);
    assert.equal(owner.start(request(run),run,'http://localhost:8082').ok,false);
    const until=Date.now()+6000;while(Date.now()<until&&!owner.snapshot(run).log.includes('ready'))await new Promise(r=>setTimeout(r,100));
    assert.match(owner.snapshot(run).log,/ready/);
    const other=owner.snapshot(path.join(scratch,'run-b'));assert.equal(other.jobs.length,0);assert.equal(other.active.runDir,fs.realpathSync(run));
    assert.equal((await owner.stop()).ok,true);
    const final=owner.snapshot(run);assert.equal(final.active,null);assert.equal(final.jobs[0].status,'cancelled');assert(fs.existsSync(final.jobs[0].reportPath));
  }finally{await owner.dispose();process.env.PATH=prior;}
});

test('immediate stop produces a cancelled report before launching the scanner',async()=>{
  const prior=process.env.PATH;process.env.PATH=path.join(scratch,'bin')+path.delimiter+prior;
  const owner=new api.SqlmapValidation(root),run=path.join(scratch,'run-early');fs.mkdirSync(run);
  try{assert.equal(owner.start(request(run),run,'http://localhost:8082').ok,true);await owner.stop();const job=owner.snapshot(run).jobs[0];assert.equal(job.status,'cancelled');assert(fs.existsSync(job.reportPath));assert.equal(owner.snapshot(run).log,'');}
  finally{await owner.dispose();process.env.PATH=prior;}
});
