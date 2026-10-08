import { test, expect } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { launchReconBot, setWindowSize } from './harness';

test('authentication and SQLmap forms scroll with wheel input to their start buttons in small windows', async ({}, testInfo) => {
  const h = await launchReconBot(testInfo, 'historical');
  try {
    for (const size of [[1280, 800], [1440, 900]]) {
      await setWindowSize(h.app, size[0], size[1]);
      for (const mode of ['basic', 'form', 'sqlmap']) {
        const view = mode === 'sqlmap' ? 'validation' : 'authentication';
        await h.page.locator(`.nav-rail [data-view="${view}"]`).click();
        const pane = h.page.locator(`.view-pane[data-view="${view}"]`);
        if (view === 'authentication') await pane.getByLabel('Authentication method', { exact: true }).selectOption(mode);
        else {
          await pane.locator('.sqlmap-fields select').selectOption('POST');
          const settings = pane.locator('.sqlmap-form details');
          if (!(await settings.evaluate(element => (element as HTMLDetailsElement).open))) await settings.locator('summary').click();
        }
        const start = pane.getByRole('button', { name: view === 'authentication' ? 'Start authentication test' : 'Start SQLmap validation', exact: true });
        const box = await pane.boundingBox();
        if (!box) throw new Error('Validation pane has no visible bounds');
        await h.page.mouse.move(box.x + box.width - 12, box.y + box.height / 2);
        await h.page.mouse.wheel(0, -10000);
        await expect.poll(() => pane.evaluate(element => element.scrollTop)).toBe(0);
        await h.page.mouse.wheel(0, 300);
        await expect.poll(() => pane.evaluate(element => element.scrollTop)).toBeGreaterThan(0);
        for (let step = 0; step < 15; step++) {
          const button = await start.boundingBox();
          if (button && button.y >= box.y && button.y + button.height <= box.y + box.height) break;
          await h.page.mouse.wheel(0, 220);
          await h.page.waitForTimeout(80);
        }
        await expect(start).toBeInViewport();
        await expect(start).toBeEnabled();
        await h.page.screenshot({ path: testInfo.outputPath(`${mode}-${size[0]}-scrolled.png`) });
        await h.page.mouse.wheel(0, 10000);
        await expect(pane.locator('.sqlmap-console small')).toBeInViewport();
        await h.page.mouse.wheel(0, -10000);
        await expect.poll(() => pane.evaluate(element => element.scrollTop)).toBe(0);
      }
    }
    expect(h.errors).toEqual([]);
  } finally { await h.close(); }
});

test('successful credentials stay above collapsed failures and every failed page remains available', async ({}, testInfo) => {
  const h = await launchReconBot(testInfo, 'historical');let dir = '';
  try {
    const run = await h.page.evaluate(() => window.reconbot.readRunState());
    dir = path.join(run.currentRunDir, 'validations/authentication', `zz-success-ui-${Date.now()}`);fs.mkdirSync(dir, { recursive: true });
    const attempts = Array.from({ length: 205 }, (_, index) => ({ username: 'operator', password: `wrong-${index}`, statusCode: 401, outcome: 'rejected', detail: 'HTTP 401 challenge.' }));
    attempts.push({ username: 'operator', password: 'correct <&> password', statusCode: 200, outcome: 'accepted', detail: 'Successful HTTP response after a verified Basic challenge.' });
    const job = { jobId: path.basename(dir), jobDir: dir, runDir: run.currentRunDir, reportPath: path.join(dir, 'report.html'), url: run.target, mode: 'basic', status: 'accepted', startedAt: '2026-10-08T03:00:00Z', finishedAt: '2026-10-08T03:00:01Z', attempts, attemptCount: attempts.length, plannedAttempts: attempts.length, baselineRequests: 1 };
    fs.writeFileSync(path.join(dir, 'result.json'), JSON.stringify(job));fs.writeFileSync(path.join(dir, 'summary.json'), JSON.stringify({ ...job, attempts: [] }));
    await h.page.locator('.nav-rail [data-view="authentication"]').click();const pane = h.page.locator('.view-pane[data-view="authentication"]');
    await pane.getByLabel('Authentication history', { exact: true }).selectOption(job.jobId);
    await expect(pane.locator('.auth-success').getByLabel('Password', { exact: true })).toHaveText('correct <&> password');
    await expect(pane.locator('.auth-attempts article')).toHaveCount(0);
    const toggle = pane.getByRole('button', { name: /See failed attempts/ });await expect(toggle).toContainText('205');await expect(toggle).toHaveAttribute('aria-expanded', 'false');
    await toggle.click();await expect(pane.locator('.auth-attempts article')).toHaveCount(50);
    await expect(pane.locator('.auth-attempts article').first().getByLabel('Password', { exact: true })).toHaveText('wrong-0');
    const pages = pane.getByRole('navigation', { name: 'Failed attempts pages', exact: true });
    for (let page = 1; page < 5; page++) { await pages.getByRole('button', { name: 'Next', exact: true }).click();await expect(pages).toContainText(`Page ${page + 1} of 5`); }
    await expect(pane.locator('.auth-attempts article')).toHaveCount(5);await expect(pane.locator('.auth-attempts article').last().getByLabel('Password', { exact: true })).toHaveText('wrong-204');
    await expect(pages.getByRole('button', { name: 'Next', exact: true })).toBeDisabled();await pages.getByRole('button', { name: 'Previous', exact: true }).click();await expect(pages).toContainText('Page 4 of 5');
    await h.page.locator('.language-selector select').selectOption('tr');await pane.getByRole('button', { name: /Başarısız denemeleri gizle/ }).click();await expect(pane.locator('.auth-attempts article')).toHaveCount(0);
    await expect(pane.locator('.auth-success').getByLabel('Şifre', { exact: true })).toHaveText('correct <&> password');
    await pane.getByRole('button', { name: /Başarısız denemeleri göster/ }).click();await expect(pane.getByRole('navigation', { name: 'Başarısız deneme sayfaları', exact: true })).toContainText('Sayfa 4 / 5');
    await pane.getByRole('button', { name: /Başarısız denemeleri gizle/ }).click();await setWindowSize(h.app, 1440, 900);
    const box = await pane.boundingBox();if (!box) throw new Error('Evidence view missing');await h.page.mouse.move(box.x + box.width - 12, box.y + box.height / 2);await h.page.mouse.wheel(0, -10000);await expect.poll(() => pane.evaluate(element => element.scrollTop)).toBe(0);
    await h.page.screenshot({ path: testInfo.outputPath('authentication-success-first-tr.png') });
    expect(h.errors).toEqual([]);
  } finally { await h.close();if (dir) fs.rmSync(dir, { recursive: true, force: true }); }
});

test('wordlist save/lock survives relaunch, unlock allows changes, and missing files are explained', async ({}, testInfo) => {
  const scratch=fs.mkdtempSync(path.resolve(__dirname,'../test-results/wordlist-ui-'));
  const first=path.join(scratch,'first list.txt'),second=path.join(scratch,'second.txt');fs.writeFileSync(first,'admin');fs.writeFileSync(second,'login');
  const userDataDir=path.join(scratch,'user-data');let h=await launchReconBot(testInfo,'idle',{userDataDir});
  try{
    await h.page.locator('.nav-rail [data-view="configure"]').click();let pane=h.page.locator('.view-pane[data-view="configure"]');
    await expect(pane.getByLabel('Wordlist',{exact:true})).toBeEnabled();
    await pane.getByLabel('Wordlist',{exact:true}).fill(first);await pane.getByRole('button',{name:'Save and lock',exact:true}).click();
    await expect(pane.getByRole('button',{name:'Unlock path',exact:true})).toBeVisible();await expect(pane.getByLabel('Wordlist',{exact:true})).toHaveAttribute('readonly','');
    await pane.getByRole('button',{name:/^slow$/i}).click();await expect(pane.getByLabel('Wordlist',{exact:true})).toHaveValue(first);
    await h.close();h=await launchReconBot(testInfo,'idle',{userDataDir});
    await h.page.locator('.nav-rail [data-view="configure"]').click();pane=h.page.locator('.view-pane[data-view="configure"]');
    await expect(pane.getByLabel('Wordlist',{exact:true})).toHaveValue(first);await expect(pane.getByLabel('Wordlist',{exact:true})).toHaveAttribute('readonly','');
    await pane.getByRole('button',{name:'Unlock path',exact:true}).click();await expect(pane.getByLabel('Wordlist',{exact:true})).not.toHaveAttribute('readonly','');
    await pane.getByLabel('Wordlist',{exact:true}).fill(second);await pane.getByRole('button',{name:'Save and lock',exact:true}).click();await expect(pane.getByRole('button',{name:'Unlock path',exact:true})).toBeVisible();
    fs.unlinkSync(second);await h.close();h=await launchReconBot(testInfo,'idle',{userDataDir});
    await h.page.locator('.nav-rail [data-view="configure"]').click();pane=h.page.locator('.view-pane[data-view="configure"]');
    await expect(pane.getByText('The saved wordlist is unavailable. Unlock it to choose another file.',{exact:true})).toBeVisible();
    await pane.getByRole('button',{name:'Unlock path',exact:true}).click();await expect(pane.getByLabel('Wordlist',{exact:true})).not.toHaveAttribute('readonly','');
    expect(h.errors).toEqual([]);
  }finally{await h.close();fs.rmSync(scratch,{recursive:true,force:true});}
});

test('Authentication UI drives actual loopback Basic/form tests, preserves score, cancels and translates',async({},testInfo)=>{
  const scratch=fs.mkdtempSync(path.resolve(__dirname,'../test-results/authentication-ui-'));
  const passwords=path.join(scratch,'passwords.txt');fs.writeFileSync(passwords,'wrong\nsecret\n');
  const server=http.createServer((req,res)=>{
    if(req.method==='GET'){res.setHeader('www-authenticate','Basic realm="fixture"');res.statusCode=req.headers.authorization==='Basic '+Buffer.from('operator:secret').toString('base64')?200:401;res.end(res.statusCode===200?'Welcome operator':'Invalid credentials');return;}
    let body='';req.on('data',chunk=>body+=chunk);req.on('end',()=>{const values=new URLSearchParams(body);res.end(values.get('username')==='operator'&&values.get('password')==='secret'?'Welcome operator':'Invalid credentials');});
  });
  await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));const address=server.address();if(!address||typeof address==='string')throw new Error('Fixture server missing');
  const target=`http://127.0.0.1:${address.port}`;const h=await launchReconBot(testInfo,'historical',{loopbackTarget:target});let jobRoot='',previous:string[]=[];
  try{
    const before=await h.page.evaluate(()=>window.reconbot.readRunState());jobRoot=path.join(before.currentRunDir,'validations/authentication');previous=fs.existsSync(jobRoot)?fs.readdirSync(jobRoot):[];
    await h.page.locator('.nav-rail [data-view="authentication"]').click();const pane=h.page.locator('.view-pane[data-view="authentication"]');
    await pane.getByLabel('Login URL',{exact:true}).fill(target+'/basic');await pane.getByLabel('Username',{exact:true}).fill('operator');
    await pane.getByLabel('Password wordlist',{exact:true}).fill(passwords);await pane.getByRole('button',{name:'Save and lock',exact:true}).click();await expect(pane.getByRole('button',{name:'Unlock path',exact:true})).toBeVisible();
    await pane.getByLabel('Request delay (seconds)',{exact:true}).fill('0');await pane.getByRole('button',{name:'Start authentication test',exact:true}).click();
    await expect(pane.locator('.sqlmap-status')).toHaveText('Credentials accepted');await expect(pane.locator('.auth-attempts article')).toHaveCount(0);
    await expect(pane.locator('.auth-success').getByLabel('Password',{exact:true})).toHaveText('secret');
    await pane.getByRole('button',{name:/See failed attempts/}).click();await expect(pane.locator('.auth-attempts article')).toHaveCount(1);
    await expect(pane.locator('.auth-attempts article').getByLabel('Password',{exact:true})).toHaveText('wrong');
    await pane.getByRole('button',{name:/Hide failed attempts/}).click();await expect(pane.locator('.auth-attempts article')).toHaveCount(0);
    const after=await h.page.evaluate(()=>window.reconbot.readRunState());expect(after.risk).toEqual(before.risk);expect(after.runState).toBe(before.runState);
    await pane.getByRole('button',{name:/See failed attempts/}).click();
    await pane.getByLabel('Authentication method',{exact:true}).selectOption('form');await pane.getByLabel('Login URL',{exact:true}).fill(target+'/form');
    await pane.getByLabel('Success criterion',{exact:true}).selectOption('body');
    await pane.getByLabel('Success value',{exact:true}).fill('xx');await pane.getByLabel('Failed login text',{exact:true}).fill('Invalid credentials');
    await pane.getByRole('button',{name:'Start authentication test',exact:true}).click();await expect(pane.locator('.sqlmap-message')).toContainText('Set explicit success and failure');
    await pane.getByLabel('Success value',{exact:true}).fill('Welcome operator');await pane.getByLabel('Failed login text',{exact:true}).fill('Invalid credentials');
    await pane.getByRole('button',{name:'Start authentication test',exact:true}).click();await expect.poll(async()=>(await h.page.evaluate(()=>window.reconbot.readAuthentication())).jobs.length).toBe(2);await expect(pane.locator('.sqlmap-status')).toHaveText('Credentials accepted');
    await expect(pane.locator('.auth-attempts article')).toHaveCount(0);
    await pane.getByLabel('Request delay (seconds)',{exact:true}).fill('5');await pane.getByRole('button',{name:'Start authentication test',exact:true}).click();await expect(pane.getByRole('button',{name:'Stop authentication test',exact:true})).toBeVisible();
    await pane.getByRole('button',{name:'Stop authentication test',exact:true}).click();await expect(pane.locator('.sqlmap-status')).toHaveText('Cancelled');
    await h.page.locator('.language-selector select').selectOption('tr');await expect(pane.getByRole('button',{name:'Giriş testini başlat',exact:true})).toBeVisible();await expect(pane.getByRole('button',{name:'Kilidi aç',exact:true})).toBeVisible();
    await setWindowSize(h.app,1280,800);await h.page.screenshot({path:testInfo.outputPath('authentication-tr.png'),fullPage:true});expect(h.errors).toEqual([]);
  }finally{await h.close();await new Promise<void>(resolve=>server.close(()=>resolve()));if(jobRoot&&fs.existsSync(jobRoot))for(const name of fs.readdirSync(jobRoot))if(!previous.includes(name))fs.rmSync(path.join(jobRoot,name),{recursive:true,force:true});fs.rmSync(scratch,{recursive:true,force:true});}
});

test('automatic form comparison needs no success text and separates candidates, unchanged and unstable replies', async ({}, testInfo) => {
  const scratch = fs.mkdtempSync(path.resolve(__dirname, '../test-results/auth-auto-ui-'));
  const passwords = path.join(scratch, 'passwords.txt');fs.writeFileSync(passwords, 'wrong-password\nsecret\n');
  let counter = 0;
  const server = http.createServer((req, res) => {
    let body = '';req.on('data', chunk => body += chunk);req.on('end', () => {
      const values = new URLSearchParams(body);counter++;
      res.setHeader('Content-Type', 'text/html');
      if (req.url === '/unsupported') { res.statusCode = 405;res.end('Method not allowed');return; }
      res.end(req.url === '/same' ? 'Public page' : req.url === '/unstable' ? `Invalid credentials ${counter}` : values.get('username') === 'operator' && values.get('password') === 'secret' ? 'Welcome operator' : 'Invalid credentials');
    });
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));const address = server.address();if (!address || typeof address === 'string') throw new Error('Fixture server missing');
  const target = `http://127.0.0.1:${address.port}`, h = await launchReconBot(testInfo, 'historical', { loopbackTarget: target });let jobRoot = '';let previous: string[] = [];
  try {
    const before = await h.page.evaluate(() => window.reconbot.readRunState());jobRoot = path.join(before.currentRunDir, 'validations/authentication');previous = fs.existsSync(jobRoot) ? fs.readdirSync(jobRoot) : [];
    await h.page.locator('.nav-rail [data-view="authentication"]').click();const pane = h.page.locator('.view-pane[data-view="authentication"]');
    await pane.getByLabel('Authentication method', { exact: true }).selectOption('form');
    await expect(pane.getByLabel('Success criterion', { exact: true })).toHaveValue('auto');
    await expect(pane.getByLabel('Success value', { exact: true })).toHaveCount(0);
    await expect(pane.getByLabel('Failed login text')).not.toHaveAttribute('required');
    await pane.getByLabel('Login URL', { exact: true }).fill(target + '/auto');await pane.getByLabel('Username', { exact: true }).fill('operator');await pane.getByLabel('Password wordlist', { exact: true }).fill(passwords);
    await pane.getByLabel('Request delay (seconds)', { exact: true }).fill('0');await pane.getByRole('button', { name: 'Start authentication test', exact: true }).click();
    await expect(pane.locator('.sqlmap-status')).toHaveText('Possible successful login — verification required');await expect(pane.locator('.auth-candidate').getByLabel('Password', { exact: true })).toHaveText('secret');await expect(pane.locator('.auth-success')).toHaveCount(0);
    const done = await h.page.evaluate(() => window.reconbot.readAuthentication());const candidateId = done.jobs[0].jobId;expect(done.jobs[0].baselineRequests).toBe(3);expect(done.jobs[0].comparisonRequests).toBe(2);
    expect(fs.readFileSync(done.jobs[0].reportPath, 'utf8')).not.toContain('<h2>Accepted credentials</h2>');
    await pane.getByRole('button', { name: /See reference-matching attempts/ }).click();await expect(pane.locator('.auth-attempts article')).toHaveCount(1);await expect(pane.locator('.auth-attempts')).toContainText('Matches incorrect-password response');await expect(pane.locator('.auth-attempts')).not.toContainText('baseline_match');await pane.getByRole('button', { name: /Hide reference-matching attempts/ }).click();
    for (const [route, status] of [['/same', 'No candidate identified'], ['/unstable', 'Inconclusive'], ['/unsupported', 'Inconclusive']]) {
      await expect(pane.getByRole('button', { name: 'Start authentication test', exact: true })).toBeEnabled();await pane.getByLabel('Login URL', { exact: true }).fill(target + route);await pane.getByRole('button', { name: 'Start authentication test', exact: true }).click();
      await expect(pane.locator('.sqlmap-url')).toHaveText(target + route);await expect(pane.locator('.sqlmap-status')).toHaveText(status);await expect(pane.locator('.auth-candidate')).toHaveCount(0);await expect(pane.locator('.auth-success')).toHaveCount(0);
      if (route === '/unsupported') {
        await expect(pane).toContainText('HTTP 405: This URL does not accept POST. Check the form action URL.');
        await expect(pane).toContainText('No wordlist pairs were tested.');
        await h.page.locator('.language-selector select').selectOption('tr');await expect(pane).toContainText('HTTP 405: Bu adres POST kabul etmiyor.');
        await h.page.locator('.language-selector select').selectOption('en');
      }
    }
    await pane.getByLabel('Authentication history', { exact: true }).selectOption(candidateId);await expect(pane.locator('.auth-candidate')).toHaveCount(1);
    await pane.getByLabel('Success criterion', { exact: true }).selectOption('body');await expect(pane.getByLabel('Success value', { exact: true })).toHaveAttribute('required', '');await expect(pane.getByLabel('Failed login text', { exact: true })).toHaveAttribute('required', '');
    await pane.getByLabel('Success criterion', { exact: true }).selectOption('auto');await h.page.locator('.language-selector select').selectOption('tr');await expect(pane.locator('.auth-candidate h3')).toHaveText('Olası başarılı giriş — doğrulama gerekli');
    const after = await h.page.evaluate(() => window.reconbot.readRunState());expect(after.risk).toEqual(before.risk);expect(after.runState).toBe(before.runState);
    await setWindowSize(h.app, 1440, 900);await pane.evaluate(element => element.scrollTop = 0);await h.page.screenshot({ path: testInfo.outputPath('authentication-auto-tr.png') });expect(h.errors).toEqual([]);
  } finally {
    await h.close();await new Promise<void>(resolve => server.close(() => resolve()));if (jobRoot && fs.existsSync(jobRoot)) for (const name of fs.readdirSync(jobRoot)) if (!previous.includes(name)) fs.rmSync(path.join(jobRoot, name), { recursive: true, force: true });fs.rmSync(scratch, { recursive: true, force: true });
  }
});
