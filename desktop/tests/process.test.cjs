const {test, before, after} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const esbuild = require('esbuild');
const root = path.resolve(__dirname, '../..');
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'reconbot-tests-'));
let api;
before(async () => {
  const file = path.join(scratch, 'process.cjs');
  await esbuild.build({stdin: {contents: `export {ReconbotProcess} from './src/main/reconbotProcess'; export {applyAiPlanToConfig} from './src/renderer/lib/aiSettings'; export {validAiSettingChange} from './src/shared/aiSettingsContract'; export {pythonExecutable} from './src/main/pythonRuntime'; export {loadConfigDefaults} from './src/main/configDefaults'; export {configFromDefaults} from './src/renderer/lib/settingsModel'; export {readRunStateSnapshot} from './src/main/artifactWatcher'; export {spawned} from 'node-pty'; export {normalizeStageStatus,summarizeStages} from './src/renderer/lib/stageModel'; export {buildOperatorModel} from './src/renderer/lib/operatorModel'; export {wheelZoomDelta,zoomCameraAt} from './src/renderer/lib/graphViewport'; export {buildEvidenceGraphModel,buildAttackGraphModel,buildScanNetwork,buildFindingNetwork} from './src/renderer/lib/attackGraph';`, resolveDir: path.join(root, 'desktop')}, bundle:true, platform:'node', format:'cjs', outfile:file,
    plugins:[{name:'fake-pty',setup(build){build.onResolve({filter:/^node-pty$/},()=>({path:'mock',namespace:'mock'}));build.onLoad({filter:/.*/,namespace:'mock'},()=>({contents:`export const spawned=[]; export function spawn(executable,args,options){const p={executable,args,options,resizes:[],resize(cols,rows){this.resizes.push({cols,rows})},signals:[],writes:[],exitHandlers:[],exit(event){for(const fn of [...this.exitHandlers])fn(event)},onData(fn){this.data=fn},onExit(fn){this.exitHandlers.push(fn)},write(value){this.writes.push(value)},kill(signal){this.signals.push(signal)}};spawned.push(p);return p;}`}));}}]});
  api = require(file);
});
after(() => fs.rmSync(scratch,{recursive:true,force:true}));
async function fixture(){
  const defaults = api.loadConfigDefaults(root);
  defaults.outputDir = fs.mkdtempSync(path.join(scratch,'output-'));
  const proc = new api.ReconbotProcess(root,defaults);
  proc.runPythonDependencyPreflight = () => ({ok:true});
  const config = api.configFromDefaults(defaults);
  config.target = 'a.example';
  config.wordlist = '/fixture/wordlist';
  const result = await proc.startScan(config);
  assert.equal(result.ok,true);
  const job = api.spawned.at(-1);
  const runDir = path.join(defaults.outputDir,'runs','a');
  fs.mkdirSync(runDir,{recursive:true});
  fs.writeFileSync(path.join(runDir,'run_result.json'),JSON.stringify({meta:{target:'a.example'}}));
  return {proc,job,runDir,defaults,result,config};
}
test('fragmented output binds a complete run path and real exit clears running',async()=>{
  const {proc,job,runDir}=await fixture();
  job.data('[+] Out');job.data('put (run): '+runDir.slice(0,-2));
  assert.equal(proc.getCurrentRunDir(),'');
  job.data(runDir.slice(-2)+'\r\n');
  assert.equal(proc.getCurrentRunDir(),runDir);
  job.data('[reconbot-electron] child return code: 0\n');
  assert.equal(proc.isProcessAttached(),true,'stdout cannot forge completion');
  job.exit({exitCode:0});
  assert.equal(proc.isProcessAttached(),false);
});
test('queued enrichment stays attached to A when history B is selected',async()=>{
  const {proc,job,runDir,defaults}=await fixture();
  const req={originalTarget:'a.example',resolvedIp:'192.0.2.1',scanMode:'quick'};
  assert.equal(proc.startIpEnrichment(req).ok,true);
  req.originalTarget='mutated.example';
  const b=path.join(defaults.outputDir,'runs','b');fs.mkdirSync(b);
  fs.writeFileSync(path.join(b,'run_result.json'),JSON.stringify({meta:{target:'b.example'}}));
  proc.selectRunDir(b);
  job.data('[+] Output (run): '+runDir+'\n');
  assert.equal(proc.getCurrentRunDir(),b);
  job.exit({exitCode:0});
  const request=JSON.parse(fs.readFileSync(path.join(runDir,'ip_enrichment_request.json'),'utf8'));
  assert.equal(request.original_target,'a.example');assert.equal(request.run_dir,runDir);
  assert.equal(request.run_id,'a');assert.equal(fs.existsSync(path.join(b,'ip_enrichment_request.json')),false);
  assert.equal(proc.getCurrentRunDir(),b);
  api.spawned.at(-1).exit({exitCode:0});
});
test('stop clears queued work and signals the actual child',async()=>{
  const {proc,job,runDir}=await fixture();job.data('[+] Output (run): '+runDir+'\n');
  proc.startIpEnrichment({originalTarget:'a.example',resolvedIp:'192.0.2.1'});
  const count=api.spawned.length;
  proc.stopScan();assert.deepEqual(job.signals,['SIGINT']);
  job.exit({exitCode:130});assert.equal(proc.isProcessAttached(),false);
  assert.equal(api.spawned.length,count);
});
test('failed scan never launches queued enrichment',async()=>{
  const {proc,job,runDir}=await fixture();job.data('[+] Output (run): '+runDir+'\n');
  proc.startIpEnrichment({originalTarget:'a.example',resolvedIp:'192.0.2.1'});
  const count=api.spawned.length;job.exit({exitCode:1});
  assert.equal(api.spawned.length,count);assert.equal(proc.isProcessAttached(),false);
});
test('wrong target and missing historical state are rejected before starting a job',async()=>{
  const {proc,job,runDir}=await fixture();job.data('[+] Output (run): '+runDir+'\n');job.exit({exitCode:0});
  const count=api.spawned.length;
  assert.equal(proc.startIpEnrichment({originalTarget:'b.example',resolvedIp:'192.0.2.1'}).ok,false);
  assert.equal(api.spawned.length,count);
});
test('scan uses direct arguments and never sends status logs to a shell',async()=>{
  const {job}=await fixture();
  assert.deepEqual(job.args.slice(0,4),['-u','-m','reconbot','a.example']);
  assert.equal(job.writes.length,0);job.exit({exitCode:0});
});
test('terminal geometry reaches both PTYs and subsequent jobs inherit the latest size',async()=>{
  const {proc,job,config}=await fixture();
  proc.ensureTerminal();const shell=api.spawned.at(-1);
  proc.resize(205,55);
  assert.deepEqual(job.resizes,[{cols:205,rows:55}]);
  assert.deepEqual(shell.resizes,[{cols:205,rows:55}]);
  for(const [cols,rows] of [[0,50],[NaN,50],[1001,50],[50,1.5]])proc.resize(cols,rows);
  assert.equal(job.resizes.length,1);
  job.exit({exitCode:0});
  assert.equal((await proc.startScan(config)).ok,true);
  const nextJob=api.spawned.at(-1);
  assert.equal(nextJob.options.cols,205);assert.equal(nextJob.options.rows,55);
  nextJob.exit({exitCode:0});
});
test('request config retains scanner controls for the canonical backend mapper',async()=>{
  const {job,result,config}=await fixture();
  const saved=JSON.parse(fs.readFileSync(result.configPath,'utf8')).reconbot;
  assert.equal(saved.tool_settings.katana.timeout,config.toolSettings.katana.timeout);
  assert.equal(saved.tool_settings.nuclei.maxTemplates,config.toolSettings.nuclei.maxTemplates);
  assert.equal(saved.tool_settings.ipNmap.topPorts,config.toolSettings.ipNmap.topPorts);
  job.exit({exitCode:0});
});
test('effective settings are read from run evidence, not the current UI selection',async()=>{
  const {job,runDir}=await fixture();
  fs.writeFileSync(path.join(runDir,'effective_config.json'),JSON.stringify({limits:{nmap_top_ports:123,nmap_timeout_sec:19,katana_timeout_sec:7,katana_max_urls:23,nuclei_timeout_sec:8,nuclei_pool_limit:31},traffic:{nmap:{timing:'T2'},katana:{rate_limit:2},nuclei:{rate_limit:3}},tools:{nmap:true,katana:true,nuclei:true}}));
  const snapshot=api.readRunStateSnapshot(runDir,true,false);
  assert.match(snapshot.effectiveSettings[0],/123 port/);
  assert.match(snapshot.effectiveSettings[2],/URL sınırı: 31/);
  job.exit({exitCode:0});
});

test('dispose waits for actual exit and preserves normal exit bookkeeping',async()=>{
  const {proc,job}=await fixture();
  let settled=false;const closing=proc.dispose().then(()=>{settled=true});
  await Promise.resolve();assert.equal(settled,false);assert.deepEqual(job.signals,['SIGINT']);
  job.exit({exitCode:130});await closing;
  assert.equal(settled,true);assert.equal(proc.isProcessAttached(),false);
});
test('OSINT evidence never invents active scanner limits',async()=>{
  const {job,runDir}=await fixture();
  fs.writeFileSync(path.join(runDir,'effective_config.json'),JSON.stringify({run_mode:'osint_only',tools:{},limits:{},traffic:{}}));
  const settings=api.readRunStateSnapshot(runDir,true,false).effectiveSettings.join(' ');
  assert.match(settings,/Yalnız OSINT/);assert.doesNotMatch(settings,/undefined|Nmap:|Katana:|Nuclei:/);
  job.exit({exitCode:0});
});
test('report presence cannot conceal failed stages or attach history to a running job',async()=>{
  const {job,runDir}=await fixture();
  fs.writeFileSync(path.join(runDir,'report.html'),'<html>partial</html>');
  fs.writeFileSync(path.join(runDir,'run_result.json'),JSON.stringify({run_state:'completed',stages:{katana:{status:'partial'},nuclei:{status:'done'}}}));
  const snapshot=api.readRunStateSnapshot(runDir,true,true);
  assert.equal(snapshot.runState,'incomplete');assert.equal(snapshot.processAttached,false);
  assert.equal(snapshot.report.exists,true);job.exit({exitCode:0});
});

function aiPlan(changes){return {type:'settings_recommendation',requires_user_approval:true,risk_score_impact:0,changes};}
test('AI profile uses real preset while preserving collector and IP configuration',async()=>{
  const defaults=api.loadConfigDefaults(root);
  const config=api.configFromDefaults(defaults);
  config.toolSettings.osint.sources.githubCodeSearch.apiKeyEnv='PRIVATE_GITHUB_TOKEN';
  config.toolSettings.ipNmap.topPorts=777;
  config.toolSettings.katana.timeout=45;
  const next=api.applyAiPlanToConfig(config,aiPlan([{path:'scan_profile',proposed:'fast'}]),defaults);
  assert.equal(next.scanProfile,'fast');assert.equal(next.trafficProfile,'fast');
  assert.equal(next.toolSettings.katana.timeout,20);assert.equal(next.toolSettings.katana.maxDepth,2);
  assert.deepEqual(next.toolSettings.osint,config.toolSettings.osint);
  assert.deepEqual(next.toolSettings.ipNmap,config.toolSettings.ipNmap);
  assert.equal(config.toolSettings.katana.timeout,45);
});
test('AI explicit overrides win regardless of row order and synchronize enabled tools',async()=>{
  const defaults=api.loadConfigDefaults(root);const config=api.configFromDefaults(defaults);
  const next=api.applyAiPlanToConfig(config,aiPlan([{path:'tool_settings.katana.maxDepth',proposed:7},{path:'tool_settings.nuclei.enabled',proposed:false},{path:'scan_profile',proposed:'fast'}]),defaults);
  assert.equal(next.scanProfile,'custom');assert.equal(next.trafficProfile,'fast');
  assert.equal(next.toolSettings.katana.maxDepth,7);assert.equal(next.tools.nuclei,false);
});
test('renderer rejects malformed approved plans without mutating configuration',async()=>{
  const defaults=api.loadConfigDefaults(root);const config=api.configFromDefaults(defaults);const before=structuredClone(config);
  for(const value of [{},true,-1,1.5,'3',101]) {
    assert.throws(()=>api.applyAiPlanToConfig(config,aiPlan([{path:'tool_settings.katana.maxDepth',proposed:value}]),defaults));
    assert.deepEqual(config,before);
  }
  assert.throws(()=>api.applyAiPlanToConfig(config,aiPlan([{path:'scan_profile',proposed:'fast'},{path:'scan_profile',proposed:'slow'}]),defaults));
});
test('renderer and Python share every action schema and valid enum boundaries',async()=>{
  const schema=require(path.join(root,'reconbot/ai/settings_contract.json')).actionSettings;
  for(const [key,rule] of Object.entries(schema)) {
    if(rule.type==='integer') {
      assert(api.validAiSettingChange(key,rule.minimum));assert(api.validAiSettingChange(key,rule.maximum));
      assert(!api.validAiSettingChange(key,rule.maximum+1));assert(!api.validAiSettingChange(key,true));
    } else if(rule.type==='enum') {
      for(const value of rule.values)assert(api.validAiSettingChange(key,value));
      assert(!api.validAiSettingChange(key,'invalid'));
    }
  }
});
test('AI and scanner interpreter resolver honors local environment and explicit override',async()=>{
  const old=process.env.RECONBOT_PYTHON;
  try {
    delete process.env.RECONBOT_PYTHON;
    assert.equal(api.pythonExecutable(root),path.join(root,'.venv','bin','python'));
    process.env.RECONBOT_PYTHON=' /fixture/python ';
    assert.equal(api.pythonExecutable(root),'/fixture/python');
  } finally {if(old===undefined)delete process.env.RECONBOT_PYTHON;else process.env.RECONBOT_PYTHON=old;}
});

test('snapshot cache skips parsing unchanged files and invalidates additions, rewrites and deletions',async()=>{
  const runDir=fs.mkdtempSync(path.join(scratch,'cache-'));
  const state=path.join(runDir,'run_result.json');
  fs.writeFileSync(state,JSON.stringify({meta:{target:'a.example'},stages:{nmap:{status:'done'}}}));
  const first=api.readRunStateSnapshot(runDir,true,false);
  const originalRead=fs.readFileSync;let reads=0;
  fs.readFileSync=function(...args){reads++;return originalRead.apply(this,args)};
  try { assert.equal(api.readRunStateSnapshot(runDir,true,false),first);assert.equal(reads,0); }
  finally { fs.readFileSync=originalRead; }
  fs.writeFileSync(state,JSON.stringify({meta:{target:'b.example'},stages:{nmap:{status:'done'}}}));
  const second=api.readRunStateSnapshot(runDir,true,false);
  assert.equal(second.target,'b.example');assert.notEqual(second.updatedAt,first.updatedAt);
  fs.writeFileSync(path.join(runDir,'report.html'),'<html>report</html>');
  assert.equal(api.readRunStateSnapshot(runDir,true,false).report.exists,true);
  fs.unlinkSync(path.join(runDir,'report.html'));
  assert.equal(api.readRunStateSnapshot(runDir,true,false).report.exists,false);
  fs.writeFileSync(path.join(runDir,'stages_live.json'),JSON.stringify({katana:{status:'running'}}));
  const attached=api.readRunStateSnapshot(runDir,false,true);
  assert.equal(attached.currentStage,'Katana');
  const historical=api.readRunStateSnapshot(runDir,true,true);
  assert.equal(historical.currentStage,'');assert.equal(historical.processAttached,false);
  assert.equal(historical.stages.find(row=>row.name==='nmap').status,'done');
});
test('nested Nuclei output changes invalidate cached findings',async()=>{
  const runDir=fs.mkdtempSync(path.join(scratch,'nested-'));
  fs.mkdirSync(path.join(runDir,'nuclei'));const output=path.join(runDir,'nuclei','results.jsonl');
  fs.writeFileSync(path.join(runDir,'run_result.json'),JSON.stringify({nuclei:{output_path:output}}));
  const write=name=>fs.writeFileSync(output,JSON.stringify({'template-id':name,'matched-at':'https://a.example/','info':{name,severity:'critical'}})+'\n');
  write('first');const first=api.readRunStateSnapshot(runDir,true,false);assert.equal(first.findings[0].name,'first');
  write('other');const next=api.readRunStateSnapshot(runDir,true,false);assert.equal(next.findings[0].name,'other');assert.notEqual(first.updatedAt,next.updatedAt);
});
test('stage summary separates skipped, partial and interrupted from successful completion',async()=>{
  const row=status=>({name:status,label:status,status,metric:'',reason:''});
  assert.deepEqual(api.summarizeStages(['done','skipped','skipped','skipped'].map(row)),{done:1,skipped:3,unknown:0,total:1,status:'done'});
  assert.equal(api.summarizeStages(['done','partial'].map(row)).status,'partial');
  assert.equal(api.summarizeStages(['interrupted'].map(row)).status,'interrupted');
  assert.equal(api.summarizeStages(['skipped'].map(row)).status,'skipped');
  assert.equal(api.summarizeStages(['unknown'].map(row)).status,'unknown');
  assert.equal(api.summarizeStages(['done','unknown'].map(row)).total,1);
  assert.equal(api.normalizeStageStatus('timeout'),'error');assert.equal(api.normalizeStageStatus('unexpected'),'unknown');
});
test('graph preserves distinct long endpoints and severity alone cannot prove exploitation',async()=>{
  const snapshot=api.readRunStateSnapshot('',false,false);
  snapshot.target='https://a.example';snapshot.metrics.nucleiFindings=9;snapshot.risk.score=87;
  snapshot.findings=Array.from({length:9},(_,i)=>({templateId:'CVE-template',name:'Template '+i,severity:'critical',matchedAt:'https://a.example/'+ 'long-path/'.repeat(20)+i,timestamp:''}));
  const model=api.buildOperatorModel(snapshot);
  const matches=model.signals.filter(signal=>signal.source==='nuclei');assert.equal(matches.length,9);
  assert.equal(new Set(matches.map(signal=>signal.id)).size,9);
  assert.equal(model.attackChain.some(node=>node.status==='confirmed'),false);
  const workflow=api.buildAttackGraphModel(snapshot,model);assert.equal(workflow.nodes.some(node=>node.status==='confirmed'),false);
  assert.deepEqual(workflow.nodes.find(node=>node.id==='target').signalIds,[]);
  const graph=api.buildEvidenceGraphModel(model);assert.equal(graph.nodes.filter(node=>node.id.startsWith('finding:')).length,8);
  for(const signal of matches.slice(0,8)) {
    const node=graph.nodes.find(node=>node.id==='finding:'+signal.id);assert.deepEqual(node.signalIds,[signal.id]);
    assert.equal(graph.edges.some(edge=>edge.from==='endpoint:'+signal.location && edge.to===node.id && edge.kind==='match'),true);
  }
  assert.equal(api.buildEvidenceGraphModel(model,1).nodes.filter(node=>node.id.startsWith('finding:')).length,1);
  snapshot.findings[0].verificationState='verified';snapshot.findings[0].validationEvidence={validated:true};
  assert.equal(api.buildOperatorModel(snapshot).signals.find(signal=>signal.title==='Template 0').verified,true);
});
test('first cache read never stores a nested dependency that changed during parsing',async()=>{
  const runDir=fs.mkdtempSync(path.join(scratch,'race-'));fs.mkdirSync(path.join(runDir,'nuclei'));
  const output=path.join(runDir,'nuclei','results.jsonl'),row=name=>JSON.stringify({'template-id':name,'matched-at':'https://a.example/',info:{name,severity:'high'}})+'\n';
  fs.writeFileSync(path.join(runDir,'run_result.json'),JSON.stringify({nuclei:{output_path:output}}));fs.writeFileSync(output,row('before'));
  const original=fs.readFileSync;let rewritten=false;
  fs.readFileSync=function(file,...args){const value=original.call(this,file,...args);if(file===output&&!rewritten){rewritten=true;fs.writeFileSync(output,row('after'))}return value};
  let first;try{first=api.readRunStateSnapshot(runDir,true,false)}finally{fs.readFileSync=original}
  assert.equal(first.findings[0].name,'before');assert.equal(api.readRunStateSnapshot(runDir,true,false).findings[0].name,'after');
});

test('preflight does not block navigation, rejects duplicate launches and respects cancellation',async()=>{
  const {proc,job,config}=await fixture(); job.exit({exitCode:0});
  let finish; proc.runPythonDependencyPreflight=()=>new Promise(resolve=>{finish=resolve});
  const count=api.spawned.length, pending=proc.startScan(config);
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal((await proc.startScan(config)).ok,false);
  proc.stopScan(); finish({ok:true});
  assert.equal((await pending).ok,false); assert.equal(api.spawned.length,count);
});
test('scan network uses recorded URLs, merges sources and never creates placeholder nodes',async()=>{
  const state={target:'https://example.test',currentRunDir:'/run',currentRunResult:{katana:{urls:['https://example.test/a','https://example.test/a']},gobuster:{results:{base:[{url:'https://example.test/a'}]}}}};
  const graph=api.buildScanNetwork(state,{signals:[]});
  assert.equal(graph.nodes.filter(n=>n.id.startsWith('endpoint:')).length,1);
  assert.equal(graph.edges.filter(e=>e.to==='endpoint:https://example.test/a').length,2);
  assert.equal(graph.nodes.some(n=>n.id==='source:ffuf'),false);
  assert.deepEqual(api.buildScanNetwork({target:'',currentRunDir:''},{signals:[]}).nodes,[]);
});

function graphFixture(urls,signals=[]){
  return api.buildScanNetwork({target:'https://example.test',currentRunDir:'/run',currentRunResult:{katana:{urls},gobuster:{results:{base:urls.slice(0,3).map(url=>({url}))}}}}, {signals});
}
function graphSignal(id,location){return {id,location,title:id,source:'nuclei',type:'vulnerability',severity:'high',verified:false,actionHint:'Review recorded evidence'};}
test('finding focus groups discovery while retaining exact finding addresses and verification state',()=>{
  const urls=Array.from({length:75},(_,i)=>'https://example.test/'+i);
  const signals=[graphSignal('first',urls[0]),graphSignal('second',urls[0]),graphSignal('third','https://example.test/sensitive?token=raw-value')];
  const full=graphFixture(urls,signals),focused=api.buildFindingNetwork(full);
  assert.equal(focused.nodes.filter(n=>n.id.startsWith('finding:')).length,3);
  assert.equal(focused.nodes.filter(n=>n.id.startsWith('endpoint:')).length,2);
  assert.equal(focused.nodes.find(n=>n.id==='cluster:katana').cluster.count,74);
  assert.equal(focused.nodes.find(n=>n.id==='cluster:gobuster').cluster.count,2);
  assert.equal(focused.grouped,74,'shared URLs count once in grouped total');
  assert.equal(focused.nodes.some(n=>n.id==='endpoint:https://example.test/sensitive?token=raw-value'),true);
  for(const n of focused.nodes.filter(n=>n.id.startsWith('finding:')))assert.equal(n.status,'evidence');
  assert.ok(focused.edges.some(e=>e.from==='source:katana'&&e.to==='endpoint:'+urls[0]),'finding endpoint keeps its discovery association');
  assert.ok(focused.nodes.length<full.nodes.length/3);
});
test('expanded clusters merge shared addresses and collapsing never mutates the full network',()=>{
  const full=graphFixture(['https://example.test/a','https://example.test/a','https://example.test/b']);
  const original=JSON.stringify(full);
  const expanded=api.buildFindingNetwork(full,new Set(['cluster:katana','cluster:gobuster']));
  assert.equal(expanded.nodes.filter(n=>n.id.startsWith('endpoint:')).length,2);
  assert.equal(expanded.edges.filter(e=>e.to==='endpoint:https://example.test/a').length,2);
  assert.equal(expanded.grouped,0);
  assert.equal(api.buildFindingNetwork(full).grouped,2);
  assert.equal(JSON.stringify(full),original);
  assert.ok(expanded.edges.every(e=>expanded.nodes.some(n=>n.id===e.from)&&expanded.nodes.some(n=>n.id===e.to)));
});
test('live discovery promotes a newly matched URL out of its cluster without losing its identity',()=>{
  const urls=['https://example.test/a','https://example.test/b'];
  const initial=api.buildFindingNetwork(graphFixture(urls));assert.equal(initial.grouped,2);
  const update=api.buildFindingNetwork(graphFixture([...urls,'https://example.test/c'],[graphSignal('new',urls[1])]),new Set(['cluster:katana']));
  assert.equal(update.nodes.find(n=>n.id==='cluster:katana').cluster.count,2);
  assert.equal(update.nodes.filter(n=>n.id==='endpoint:'+urls[1]).length,1);
  assert.ok(update.edges.some(e=>e.from==='endpoint:'+urls[1]&&e.to==='finding:new'));
  assert.equal(update.nodes.find(n=>n.id==='cluster:katana').cluster.expanded,true);
});
test('large discovery inventory cannot consume the budget before finding endpoints',()=>{
  const urls=Array.from({length:900},(_,i)=>'https://example.test/discovery/'+i);
  const full=graphFixture(urls,[graphSignal('important','https://example.test/finding')]);
  const focused=api.buildFindingNetwork(full);
  assert.ok(focused.nodes.some(n=>n.id==='endpoint:https://example.test/finding'));
  assert.ok(focused.edges.some(e=>e.from==='endpoint:https://example.test/finding'&&e.to==='finding:important'));
  assert.ok(full.omitted>0);assert.equal(focused.omitted,full.omitted);
  assert.deepEqual(api.buildFindingNetwork({nodes:[],edges:[]}),{nodes:[],edges:[],omitted:undefined,grouped:0});
});
test('large finding sets stay accessible through clusters, expansion and exact selection',()=>{
  const signals=Array.from({length:35},(_,i)=>graphSignal('match-'+i,'https://example.test/finding/'+i));
  signals[34].severity='critical';
  const full=graphFixture([],signals),focused=api.buildFindingNetwork(full);
  assert.equal(focused.nodes.filter(n=>n.id.startsWith('finding:')).length,12);
  assert.ok(focused.nodes.some(n=>n.id==='finding:match-34'),'severity ordering reserves the critical finding');
  const group=focused.nodes.find(n=>n.id==='cluster:findings:nuclei');assert.equal(group.cluster.count,23);
  const represented=new Set(focused.nodes.filter(n=>n.id.startsWith('finding:')||n.cluster?.kind==='findings').flatMap(n=>n.signalIds));
  assert.deepEqual([...represented].sort(),signals.map(s=>s.id).sort());
  const expanded=api.buildFindingNetwork(full,new Set([group.id]));
  assert.equal(expanded.nodes.filter(n=>n.id.startsWith('finding:')).length,35);
  assert.equal(expanded.nodes.filter(n=>n.id.startsWith('endpoint:')).length,35);
  const pinned=api.buildFindingNetwork(full,new Set(),'finding:match-30');
  assert.ok(pinned.nodes.some(n=>n.id==='finding:match-30'));
  assert.ok(pinned.nodes.some(n=>n.id==='endpoint:https://example.test/finding/30'));
  assert.equal(pinned.nodes.find(n=>n.id===group.id).cluster.count,22);
  assert.ok(pinned.edges.every(e=>pinned.nodes.some(n=>n.id===e.from)&&pinned.nodes.some(n=>n.id===e.to)));
});

test('trackpad micro-events preserve gesture magnitude and wheel units are normalized',()=>{
  const delta=api.wheelZoomDelta(20);
  assert.ok(Math.abs(delta)<.02,'20 pixels must not behave like 20 full zoom steps');
  assert.ok(Math.abs(delta-Array.from({length:20},()=>api.wheelZoomDelta(1)).reduce((a,b)=>a+b,0))<1e-12);
  assert.equal(api.wheelZoomDelta(2,1),api.wheelZoomDelta(32,0));
  assert.equal(api.wheelZoomDelta(1,2),api.wheelZoomDelta(600,0));
  assert.ok(api.wheelZoomDelta(100,0,false,.25)<api.wheelZoomDelta(100,0,false,1));
  assert.ok(api.wheelZoomDelta(1,0,true)>api.wheelZoomDelta(1,0,false));
  assert.equal(api.wheelZoomDelta(NaN),0);
});
test('zoom remains anchored to the pointer, reverses small gestures and respects bounds',()=>{
  const camera={x:30,y:-40,zoom:1.1},point={x:230,y:180};
  const next=api.zoomCameraAt(camera,point,api.wheelZoomDelta(-80));
  for(const axis of ['x','y'])assert.ok(Math.abs((point[axis]-camera[axis])/camera.zoom-(point[axis]-next[axis])/next.zoom)<1e-10);
  const restored=api.zoomCameraAt(next,point,api.wheelZoomDelta(80));
  for(const field of ['x','y','zoom'])assert.ok(Math.abs(restored[field]-camera[field])<1e-10);
  const max={x:4,y:6,zoom:5},min={x:4,y:6,zoom:.25};
  assert.equal(api.zoomCameraAt(max,point,-1000),max);assert.equal(api.zoomCameraAt(min,point,1000),min);
  assert.equal(api.zoomCameraAt(camera,point,NaN),camera);
  assert.ok(api.zoomCameraAt({x:0,y:0,zoom:1},point,-1000).zoom<1.13,'a large frame must not jump several zoom levels');
});
