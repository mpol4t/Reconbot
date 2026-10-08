// Actual loopback Basic/form requests through the frozen backend and typed IPC.
const {_electron}=require('../node_modules/playwright');
const fs=require('fs'),path=require('path'),os=require('os'),assert=require('assert/strict'),http=require('http');
(async()=>{
  const root=path.resolve(__dirname,'..'),scratch=fs.mkdtempSync(path.join(root,'test-results/native-authentication-'));
  const userDataDir=path.join(scratch,'user-data'),passwords=path.join(scratch,'passwords.txt');fs.writeFileSync(passwords,'wrong\nsecret\n');
  const server=http.createServer((req,res)=>{
    if(req.method==='GET'){res.setHeader('www-authenticate','Basic realm="native fixture"');res.statusCode=req.headers.authorization==='Basic '+Buffer.from('operator:secret').toString('base64')?200:401;res.end(res.statusCode===200?'Welcome operator':'Invalid credentials');return;}
    let body='';req.on('data',chunk=>body+=chunk);req.on('end',()=>{const values=new URLSearchParams(body);if(req.url==='/unsupported'){res.statusCode=405;res.end('Method not allowed');return;}res.end(req.url==='/same'?'Public page':req.url==='/dynamic'?'Changed '+Math.random():values.get('username')==='operator'&&values.get('password')==='secret'?'Welcome operator':'Invalid credentials');});
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const target='http://127.0.0.1:'+server.address().port;
  const env={...process.env,RECONBOT_E2E_USER_DATA_DIR:userDataDir};for(const key of ['RECONBOT_PYTHON','RECONBOT_REPO_ROOT','PYTHONPATH','VIRTUAL_ENV','RECONBOT_E2E'])delete env[key];
  const launch=()=>_electron.launch({executablePath:process.env.RECONBOT_SMOKE_EXECUTABLE||path.join(root,'dist/mac-arm64/ReconBot.app/Contents/MacOS/ReconBot'),args:process.platform==='linux'&&process.getuid()===0?['--no-sandbox']:[],cwd:os.tmpdir(),env});
  let app;
  try{
    app=await launch();let page=await app.firstWindow();await page.locator('.nav-rail').waitFor();
    await app.evaluate(({BrowserWindow})=>BrowserWindow.getAllWindows()[0].setSize(1280,800));
    const defaults=await page.evaluate(()=>window.reconbot.getConfigDefaults());const runA=path.join(defaults.outputDir,'runs','native-auth-a'),runB=path.join(defaults.outputDir,'runs','native-auth-b');
    for(const dir of [runA,runB]){fs.mkdirSync(dir,{recursive:true});fs.writeFileSync(path.join(dir,'run_result.json'),JSON.stringify({run_state:'completed',meta:{target},summary:{},stages:{}}));}
    await page.evaluate(dir=>window.reconbot.selectScanHistoryRun(dir),runA);
    await page.locator('.nav-rail [data-view="authentication"]').click();let pane=page.locator('.view-pane[data-view="authentication"]');
    await pane.getByLabel('Login URL',{exact:true}).fill(target+'/basic');await pane.getByLabel('Username',{exact:true}).fill('operator');await pane.getByLabel('Password wordlist',{exact:true}).fill(passwords);
    await pane.getByRole('button',{name:'Save and lock',exact:true}).click();await pane.getByRole('button',{name:'Unlock path',exact:true}).waitFor();
    await pane.getByLabel('Request delay (seconds)',{exact:true}).fill('0');
    // Wheel input must reveal the button before Playwright's click can auto-scroll.
    const bounds=await pane.boundingBox();assert(bounds);
    await page.mouse.move(bounds.x+bounds.width-12,bounds.y+bounds.height/2);await page.mouse.wheel(0,-10000);
    await page.waitForFunction(()=>document.querySelector('.view-pane[data-view="authentication"]').scrollTop===0);
    await page.mouse.wheel(0,300);await page.waitForFunction(()=>document.querySelector('.view-pane[data-view="authentication"]').scrollTop>0);
    const start=pane.getByRole('button',{name:'Start authentication test',exact:true});let visible=false;
    for(let step=0;step<15;step++){const button=await start.boundingBox();visible=button&&button.y>=bounds.y&&button.y+button.height<=bounds.y+bounds.height;if(visible)break;await page.mouse.wheel(0,220);await page.waitForTimeout(80);}
    assert(visible,'Wheel scrolling must expose the authentication start button');
    await page.screenshot({path:path.join(root,'test-results/native-authentication-scroll.png')});
    await start.click();
    const waitState=async predicate=>{const end=Date.now()+15000;while(Date.now()<end){const state=await page.evaluate(()=>window.reconbot.readAuthentication());if(predicate(state))return state;await new Promise(resolve=>setTimeout(resolve,150));}throw new Error('Native authentication state timeout');};
    const done=await waitState(state=>state.jobs[0]?.status==='accepted'&&!state.active);assert.equal(done.jobs[0].attempts.length,2);assert.equal(done.jobs[0].attempts[1].password,'secret');assert(fs.existsSync(done.jobs[0].reportPath));
    await pane.locator('.auth-success pre[aria-label="Password"]').waitFor();assert.equal(await pane.locator('.auth-success pre[aria-label="Password"]').textContent(),'secret');assert.equal(await pane.locator('.auth-attempts article').count(),0);
    const report=fs.readFileSync(done.jobs[0].reportPath,'utf8');assert(report.indexOf('Accepted credentials')<report.indexOf('See failed attempts (1)'));assert(report.includes('<details class="failed-attempts"><summary>'));
    await pane.getByRole('button',{name:/See failed attempts/}).click();await pane.locator('.auth-attempts article').waitFor();assert.equal(await pane.locator('.auth-attempts pre[aria-label="Password"]').textContent(),'wrong');await pane.getByRole('button',{name:/Hide failed attempts/}).click();
    const request={runDir:runA,url:target+'/form',mode:'form',usernameSource:'single',username:'operator',usernameWordlist:'',passwordWordlist:passwords,usernameField:'username',passwordField:'password',extraBody:'submit=Login',successMode:'body',successValue:'Welcome operator',failureValue:'Invalid credentials',lockoutValue:'account locked',maxAttempts:10,duration:10,timeout:2,delay:0};
    let result=await page.evaluate(value=>window.reconbot.startAuthentication(value),request);assert(result.ok,result.message);await waitState(state=>state.jobs[0]?.mode==='form'&&state.jobs[0]?.status==='accepted'&&!state.active);
    const autoRequest={...request,successMode:'auto',successValue:'',failureValue:''};
    result=await page.evaluate(value=>window.reconbot.startAuthentication(value),autoRequest);assert(result.ok,result.message);
    const automatic=await waitState(state=>state.jobs[0]?.successMode==='auto'&&state.jobs[0]?.status==='candidate'&&!state.active);
    assert.equal(automatic.jobs[0].baselineRequests,3);assert.equal(automatic.jobs[0].comparisonRequests,2);assert.equal(automatic.jobs[0].attempts.length,2);
    assert.equal(automatic.jobs[0].attempts[1].password,'secret');assert(!automatic.jobs[0].attempts.some(attempt=>attempt.outcome==='accepted'));
    await pane.getByLabel('Authentication history',{exact:true}).selectOption(automatic.jobs[0].jobId);
    await pane.locator('.auth-candidate pre[aria-label="Password"]').waitFor();assert.equal(await pane.locator('.auth-candidate pre[aria-label="Password"]').textContent(),'secret');assert.equal(await pane.locator('.auth-success').count(),0);
    const automaticReport=fs.readFileSync(automatic.jobs[0].reportPath,'utf8');assert(automaticReport.includes('Possible successful login — verification required'));assert(!automaticReport.includes('<h2>Accepted credentials</h2>'));
    await pane.getByRole('button',{name:/See reference-matching attempts/}).click();await pane.locator('.auth-attempts article').waitFor();assert.equal(await pane.locator('.auth-attempts pre[aria-label="Password"]').textContent(),'wrong');
    await page.screenshot({path:path.join(root,'test-results/native-authentication-auto.png'),fullPage:true});
    for(const [route,status] of [['/same','no_candidate'],['/dynamic','inconclusive'],['/unsupported','inconclusive']]){
      result=await page.evaluate(value=>window.reconbot.startAuthentication(value),{...autoRequest,url:target+route});assert(result.ok,result.message);
      const comparison=await waitState(state=>state.jobs[0]?.url===target+route&&state.jobs[0]?.status===status&&!state.active);
      assert(!comparison.jobs[0].attempts.some(attempt=>['candidate','accepted'].includes(attempt.outcome)));
      if(route==='/unsupported'){assert.equal(comparison.jobs[0].attempts.length,0);assert.match(comparison.jobs[0].message,/HTTP 405.*form action URL/);}
    }
    result=await page.evaluate(value=>window.reconbot.startAuthentication({...value,delay:5}),request);assert(result.ok,result.message);await waitState(state=>state.log.includes('baseline'));
    await page.evaluate(dir=>window.reconbot.selectScanHistoryRun(dir),runB);const other=await page.evaluate(()=>window.reconbot.readAuthentication());assert.equal(other.jobs.length,0);assert.equal(other.active.runDir,runA);
    await page.evaluate(()=>window.reconbot.stopAuthentication());await page.evaluate(dir=>window.reconbot.selectScanHistoryRun(dir),runA);assert.equal((await page.evaluate(()=>window.reconbot.readAuthentication())).jobs[0].status,'cancelled');
    assert((await page.evaluate(value=>window.reconbot.startAuthentication(value),request)).ok);await page.evaluate(()=>window.reconbot.stopAuthentication());const early=await page.evaluate(()=>window.reconbot.readAuthentication());assert.equal(early.jobs[0].status,'cancelled');assert(fs.existsSync(early.jobs[0].reportPath));
    await app.close();app=await launch();page=await app.firstWindow();await page.locator('.nav-rail').waitFor();await page.evaluate(dir=>window.reconbot.selectScanHistoryRun(dir),runA);await page.locator('.nav-rail [data-view="authentication"]').click();pane=page.locator('.view-pane[data-view="authentication"]');
    await pane.getByRole('button',{name:'Unlock path',exact:true}).waitFor();assert.equal(await pane.getByLabel('Password wordlist',{exact:true}).inputValue(),passwords);assert.equal(await pane.getByLabel('Password wordlist',{exact:true}).getAttribute('readonly'),'');
    await pane.getByLabel('Authentication history',{exact:true}).selectOption(done.jobs[0].jobId);await pane.locator('.sqlmap-status').filter({hasText:'Credentials accepted'}).waitFor();
    await page.screenshot({path:path.join(root,'test-results/native-authentication.png'),fullPage:true});
    const output={packagedBackend:'passed',wheelScroll:'passed',successFirst:'passed',failedReveal:'passed',realBasic:'passed',realForm:'passed',automaticCandidate:'passed',automaticNegative:'passed',unstableReference:'passed',endpointGuidance:'passed',report:'passed',runIsolation:'passed',cancellation:'passed',immediateCancellation:'passed',wordlistRelaunch:'passed'};
    fs.writeFileSync(process.env.RECONBOT_AUTHENTICATION_SMOKE_RESULT||path.join(root,'test-results/native-authentication-smoke.json'),JSON.stringify(output,null,2));
    console.log('Packaged authentication: actual loopback Basic/form, frozen backend, report, cancellation, run isolation and saved wordlist relaunch passed.');
  }finally{if(app)await app.close();await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{console.error(error);process.exit(1)});
