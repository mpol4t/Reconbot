// Packaged backend/IPC lifecycle test with a deterministic external CLI fixture.
// Real SQLmap detection is separately tested by sqlmap-local-smoke.py.
const {_electron}=require('../node_modules/playwright');
const fs=require('fs'),path=require('path'),os=require('os'),assert=require('assert/strict');
(async()=>{
  const root=path.resolve(__dirname,'..');fs.mkdirSync(path.join(root,'test-results'),{recursive:true});
  const scratch=fs.mkdtempSync(path.join(root,'test-results/native-sqlmap-'));
  const bin=path.join(scratch,'bin');fs.mkdirSync(bin);
  const shim=path.join(bin,'sqlmap');fs.writeFileSync(shim,`#!/bin/sh
if [ "$1" = "--version" ]; then echo fixture; exit 0; fi
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output-dir) shift; output="$1" ;;
    -p) shift; parameter="$1" ;;
  esac
  shift
done
echo "native CLI ready: $parameter"
if [ "$parameter" = "slow" ]; then sleep 300 & wait; exit; fi
mkdir -p "$output/localhost"
cat > "$output/localhost/log" <<'PROOF'
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: native fixture evidence
    Payload: id=1 AND 1=1
---
PROOF
echo '[*] ending @ 12:00'
`);fs.chmodSync(shim,0o755);
  const env={...process.env,RECONBOT_E2E_USER_DATA_DIR:path.join(scratch,'user-data'),PATH:bin+path.delimiter+process.env.PATH};
  for(const key of ['RECONBOT_PYTHON','RECONBOT_REPO_ROOT','PYTHONPATH','VIRTUAL_ENV','RECONBOT_E2E'])delete env[key];
  const app=await _electron.launch({executablePath:process.env.RECONBOT_SMOKE_EXECUTABLE||path.join(root,'dist/mac-arm64/ReconBot.app/Contents/MacOS/ReconBot'),args:process.platform==='linux'&&process.getuid()===0?['--no-sandbox']:[],cwd:os.tmpdir(),env});
  try{
    const page=await app.firstWindow();await page.locator('.nav-rail').waitFor();
    const defaults=await page.evaluate(()=>window.reconbot.getConfigDefaults());
    const runA=path.join(defaults.outputDir,'runs','sqlmap-native-a'),runB=path.join(defaults.outputDir,'runs','sqlmap-native-b');
    for(const dir of [runA,runB]){fs.mkdirSync(dir,{recursive:true});fs.writeFileSync(path.join(dir,'run_result.json'),JSON.stringify({run_state:'completed',meta:{target:'http://localhost:8082'},summary:{},stages:{}}));}
    await page.evaluate(dir=>window.reconbot.selectScanHistoryRun(dir),runA);
    const request={runDir:runA,url:'http://localhost:8082/item?id=1',parameter:'id',method:'GET',body:'',cookie:'',level:1,risk:1,timeout:2,duration:10,threads:1,delay:0};
    let result=await page.evaluate(value=>window.reconbot.startSqlmap(value),request);assert(result.ok,result.message);
    const waitState=async predicate=>{ const deadline=Date.now()+15000; while(Date.now()<deadline){ const state=await page.evaluate(()=>window.reconbot.readSqlmap()); if(predicate(state))return state; await new Promise(resolve=>setTimeout(resolve,150)); } throw new Error('Native SQLmap state did not reach expected condition.'); };
    await waitState(state=>state.jobs[0]?.status==='detected');
    const done=await page.evaluate(()=>window.reconbot.readSqlmap());assert.equal(done.jobs[0].evidence.length,1);assert(fs.existsSync(done.jobs[0].reportPath));
    assert(fs.readFileSync(done.jobs[0].reportPath,'utf8').includes('<p class="payload-label">Payload</p><pre aria-label="Payload">id=1 AND 1=1</pre>'));
    await page.locator('.nav-rail [data-view="validation"]').click();
    await page.locator('.sqlmap-evidence pre[aria-label="Payload"]').waitFor();
    assert.equal(await page.locator('.sqlmap-payload-label').textContent(),'Payload');
    assert.equal(await page.locator('.sqlmap-evidence pre[aria-label="Payload"]').textContent(),'id=1 AND 1=1');
    result=await page.evaluate(value=>window.reconbot.startSqlmap({...value,url:'http://localhost:8082/item?slow=1',parameter:'slow'}),request);assert(result.ok,result.message);
    await waitState(state=>state.log.includes('native CLI ready: slow')); 
    await page.evaluate(dir=>window.reconbot.selectScanHistoryRun(dir),runB);
    const other=await page.evaluate(()=>window.reconbot.readSqlmap());assert.equal(other.jobs.length,0);assert.equal(other.active.runDir,runA);
    await page.evaluate(()=>window.reconbot.stopSqlmap());
    await page.evaluate(dir=>window.reconbot.selectScanHistoryRun(dir),runA);
    const cancelled=await page.evaluate(()=>window.reconbot.readSqlmap());assert.equal(cancelled.active,null);assert.equal(cancelled.jobs[0].status,'cancelled');assert(fs.existsSync(cancelled.jobs[0].reportPath));
    assert((await page.evaluate(value=>window.reconbot.startSqlmap(value),request)).ok);
    await page.evaluate(()=>window.reconbot.stopSqlmap());
    const early=await page.evaluate(()=>window.reconbot.readSqlmap());assert.equal(early.jobs[0].status,'cancelled');assert(fs.existsSync(early.jobs[0].reportPath));
    await page.locator('.nav-rail [data-view="validation"]').click();await page.getByRole('button',{name:'Start SQLmap validation',exact:true}).waitFor();
    const output={packagedBackend:'passed',typedIPC:'passed',detectionFixture:'passed',report:'passed',payloadLabels:'passed',cancellation:'passed',immediateCancellation:'passed',runIsolation:'passed'};
    fs.writeFileSync(process.env.RECONBOT_SQLMAP_SMOKE_RESULT||path.join(root,'test-results/native-sqlmap-smoke.json'),JSON.stringify(output,null,2));
    console.log('Packaged SQLmap validation: frozen backend, IPC, evidence/report, cancellation and run isolation passed.');
  }finally{await app.close();}
})().catch(error=>{console.error(error);process.exit(1)});
