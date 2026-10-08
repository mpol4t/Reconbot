const {test,before,after}=require('node:test');
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),http=require('node:http'),esbuild=require('esbuild');
const root=path.resolve(__dirname,'../..'),scratch=fs.mkdtempSync(path.join(os.tmpdir(),'reconbot-auth-unit-'));
let api;
before(async()=>{const output=path.join(scratch,'api.cjs');await esbuild.build({stdin:{contents:`export {WordlistPreferenceStore} from './src/main/wordlistPreferences'; export {AuthenticationValidation} from './src/main/authenticationValidation'; export {validateAuthenticationRequest} from './src/shared/authentication';`,resolveDir:path.join(root,'desktop')},bundle:true,platform:'node',format:'cjs',outfile:output});api=require(output);});
after(()=>fs.rmSync(scratch,{recursive:true,force:true}));
test('wordlist lock persists across store instances and changing requires unlock',()=>{
  const first=path.join(scratch,'first list.txt'),second=path.join(scratch,'second.txt'),file=path.join(scratch,'prefs.json');fs.writeFileSync(first,'one');fs.writeFileSync(second,'two');
  let store=new api.WordlistPreferenceStore(file,root);
  assert.equal(store.save('discovery',{path:first,locked:true}).ok,true);
  store=new api.WordlistPreferenceStore(file,root);assert.equal(store.read().discovery.path,first);assert.equal(store.read().discovery.locked,true);
  assert.equal(store.save('discovery',{path:second,locked:false}).ok,false);
  assert.equal(store.save('discovery',{path:first,locked:false}).ok,true);
  assert.equal(store.save('discovery',{path:second,locked:true}).ok,true);
  assert.equal(new api.WordlistPreferenceStore(file,root).read().discovery.path,second);
});
test('missing saved files can be unlocked and credential slots stay separate',()=>{
  const list=path.join(scratch,'removed.txt'),file=path.join(scratch,'missing-prefs.json');fs.writeFileSync(list,'one');const store=new api.WordlistPreferenceStore(file,root);
  store.save('authUsers',{path:list,locked:true});fs.unlinkSync(list);
  assert.equal(store.read().authUsers.available,false);assert.equal(store.save('authUsers',{path:list,locked:false}).ok,true);assert.equal(store.read().authPasswords.path,'');
  assert.equal(store.save('discovery',{path:scratch,locked:true}).ok,false);assert.equal(store.save('other',{path:list,locked:true}).ok,false);
});
test('corrupt preference storage is reported and not silently overwritten',()=>{
  const file=path.join(scratch,'broken.json');fs.writeFileSync(file,'{broken');const store=new api.WordlistPreferenceStore(file,root);
  assert.throws(()=>store.read());assert.equal(store.save('discovery',{path:path.join(scratch,'first list.txt'),locked:true}).ok,false);assert.equal(fs.readFileSync(file,'utf8'),'{broken');
});
function request(runDir,target){return {runDir,url:target+'/basic',mode:'basic',usernameSource:'single',username:'operator',usernameWordlist:'',passwordWordlist:path.join(scratch,'passwords.txt'),usernameField:'username',passwordField:'password',extraBody:'',successMode:'body',successValue:'Welcome',failureValue:'Invalid credentials',lockoutValue:'account locked',maxAttempts:10,duration:10,timeout:2,delay:0};}
test('scope and form success criteria are checked before any job is created',()=>{
  const value=request(scratch,'http://localhost:8082');api.validateAuthenticationRequest(value,'http://localhost:8082');
  for(const change of [{url:'http://other.test/basic'},{maxAttempts:Infinity},{username:'a:b'},{mode:'form',successValue:''},{mode:'form',extraBody:'username=oops'},{mode:'form',successMode:'location',successValue:'http://other.test/account'}])assert.throws(()=>api.validateAuthenticationRequest({...value,...change},'http://localhost:8082'));
});
test('automatic form comparison accepts blank criteria while explicit modes remain strict',()=>{
  const value={...request(scratch,'http://localhost:8082'),mode:'form',successMode:'auto',successValue:'',failureValue:''};
  api.validateAuthenticationRequest(value,'http://localhost:8082');
  for(const change of [{successMode:'body'},{successMode:'location'},{successMode:'guess'},{failureValue:'xx'},{url:'http://other.test/form'}])assert.throws(()=>api.validateAuthenticationRequest({...value,...change},'http://localhost:8082'));
});
test('comparison candidates remain separate from accepted credentials and matching pages retain all records',()=>{
  const run=path.join(scratch,'candidate-history'),dir=path.join(run,'validations/authentication','candidate');fs.mkdirSync(dir,{recursive:true});
  const attempts=Array.from({length:205},(_,index)=>({username:'operator',password:'wrong-'+index,statusCode:200,outcome:'baseline_match',detail:'reference'}));attempts.push({username:'operator',password:'possible <&> secret',statusCode:200,outcome:'candidate',detail:'manual verification required'});
  const job={...request(run,'http://localhost:8082'),mode:'form',successMode:'auto',jobId:'candidate',jobDir:dir,status:'candidate',attempts,attemptCount:206,plannedAttempts:206,baselineRequests:3,comparisonRequests:2,startedAt:'2026-10-08'};
  fs.writeFileSync(path.join(dir,'result.json'),JSON.stringify(job));fs.writeFileSync(path.join(dir,'summary.json'),JSON.stringify({...job,attempts:[]}));
  const owner=new api.AuthenticationValidation(root),selected=owner.snapshot(run,'candidate',4).jobs[0];
  assert.deepEqual(selected.acceptedAttempts,[]);assert.equal(selected.candidateAttempts[0].password,'possible <&> secret');assert.equal(selected.rejectedCount,205);assert.equal(selected.rejectedAttempts.length,5);assert.equal(selected.rejectedAttempts[4].password,'wrong-204');assert.deepEqual(selected.otherAttempts,[]);
});
test('history transfers only selected attempt details and retains exact full counts',()=>{
  const run=path.join(scratch,'history'),root=path.join(run,'validations/authentication');fs.mkdirSync(root,{recursive:true});
  for(const name of ['a','b']){const dir=path.join(root,name);fs.mkdirSync(dir);const attempts=Array.from({length:250},(_,index)=>({username:'operator',password:'raw-'+index,statusCode:401,outcome:'rejected',detail:'challenge'}));const job={...request(run,'http://localhost:8082'),jobId:name,jobDir:dir,status:'not_accepted',attempts,attemptCount:250,plannedAttempts:250,baselineRequests:1,startedAt:'2026-10-08'};fs.writeFileSync(path.join(dir,'result.json'),JSON.stringify(job));fs.writeFileSync(path.join(dir,'summary.json'),JSON.stringify({...job,attempts:[]}));}
  const owner=new api.AuthenticationValidation(root);const state=owner.snapshot(run,'a');assert.equal(state.jobs.find(job=>job.jobId==='a').attempts.length,100);assert.equal(state.jobs.find(job=>job.jobId==='a').attemptCount,250);assert.equal(state.jobs.find(job=>job.jobId==='a').attempts[0].password,'raw-150');assert.equal(state.jobs.find(job=>job.jobId==='b').attempts.length,0);
  const first=state.jobs.find(job=>job.jobId==='a');assert.equal(first.rejectedCount,250);assert.equal(first.rejectedPages,5);assert.equal(first.rejectedAttempts.length,50);assert.equal(first.rejectedAttempts[0].password,'raw-0');
  const last=owner.snapshot(run,'a',999).jobs.find(job=>job.jobId==='a');assert.equal(last.rejectedPage,4);assert.equal(last.rejectedAttempts[49].password,'raw-249');
  for(const page of [NaN,Infinity,-1,'2'])assert.equal(owner.snapshot(run,'a',page).jobs.find(job=>job.jobId==='a').rejectedPage,0);
  const file=path.join(root,'a','result.json'),job=JSON.parse(fs.readFileSync(file,'utf8'));
  job.attempts.push({username:'operator',password:'correct <&> password',statusCode:200,outcome:'accepted',detail:'criterion matched'});job.status='accepted';fs.writeFileSync(file,JSON.stringify(job));
  const paged=owner.snapshot(run,'a',2).jobs.find(job=>job.jobId==='a');assert.equal(paged.acceptedAttempts[0].password,'correct <&> password');assert.equal(paged.rejectedAttempts[0].password,'raw-100');assert.equal(paged.rejectedCount,250);
});
test('real backend completes Basic login, preserves ownership and cancels early/live',async()=>{
  const server=http.createServer((req,res)=>{res.setHeader('www-authenticate','Basic realm="fixture"');res.statusCode=req.headers.authorization==='Basic '+Buffer.from('operator:secret').toString('base64')?200:401;res.end(res.statusCode===200?'Welcome':'Invalid credentials');});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const target='http://127.0.0.1:'+server.address().port;
  fs.writeFileSync(path.join(scratch,'passwords.txt'),'wrong\nsecret\n');const runA=path.join(scratch,'run-a'),runB=path.join(scratch,'run-b');fs.mkdirSync(runA);fs.mkdirSync(runB);
  const owner=new api.AuthenticationValidation(root),value=request(runA,target);
  const until=async predicate=>{const end=Date.now()+6000;while(Date.now()<end){const state=owner.snapshot(runA);if(predicate(state))return state;await new Promise(r=>setTimeout(r,50));}throw new Error('Backend state timeout');};
  try{
    assert.equal(owner.start(value,runA,target).ok,true);assert.equal(owner.start(value,runA,target).ok,false);
    const done=await until(state=>state.jobs[0]?.status==='accepted'&&!state.active);assert.equal(done.jobs[0].attempts[1].password,'secret');assert(fs.existsSync(done.jobs[0].reportPath));
    assert.equal(owner.start({...value,delay:5},runA,target).ok,true);await until(state=>state.log.includes('baseline'));
    const other=owner.snapshot(runB);assert.equal(other.jobs.length,0);assert.equal(other.active.runDir,fs.realpathSync(runA));
    await owner.stop();assert.equal(owner.snapshot(runA).jobs[0].status,'cancelled');assert.equal(owner.snapshot(runA).active,null);
    assert.equal(owner.start(value,runA,target).ok,true);await owner.stop();assert.equal(owner.snapshot(runA).jobs[0].status,'cancelled');assert(fs.existsSync(owner.snapshot(runA).jobs[0].reportPath));
  }finally{await owner.dispose();await new Promise(resolve=>server.close(resolve));}
});
