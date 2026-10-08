import { test, expect } from '@playwright/test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { launchReconBot, setRunScenario } from './harness';

test('SQLmap form, exact parameter, evidence, cancellation and run isolation work in Electron', async ({}, testInfo) => {
  const bin=fs.mkdtempSync(path.join(os.tmpdir(),'reconbot-sqlmap-ui-'));
  const shim=path.join(bin,'sqlmap');
  fs.writeFileSync(shim,`#!/usr/bin/env python3
import pathlib,sys,time
if '--version' in sys.argv: print('fixture'); sys.exit(0)
parameter=sys.argv[sys.argv.index('-p')+1]
print('Fixture SQLmap job: '+parameter,flush=True)
if parameter=='slow': time.sleep(300)
output=pathlib.Path(sys.argv[sys.argv.index('--output-dir')+1])/'localhost'
output.mkdir(parents=True)
(output/'log').write_text('---\\nParameter: id (GET)\\n    Type: boolean-based blind\\n    Title: fixture evidence\\n    Payload: id=1 AND 1=1\\n---\\n')
print('[*] ending @ 12:00',flush=True)
`);fs.chmodSync(shim,0o755);
  const prior=process.env.PATH;process.env.PATH=bin+path.delimiter+prior;
  const h=await launchReconBot(testInfo,'historical');
  let jobRoot=''; let priorJobs: string[] = [];
  try {
    const before=await h.page.evaluate(()=>window.reconbot.readRunState());
    jobRoot=path.join(before.currentRunDir,'validations','sqlmap');
    priorJobs=fs.existsSync(jobRoot)?fs.readdirSync(jobRoot):[];
    await h.page.locator('.nav-rail [data-view="validation"]').click();
    const pane=h.page.locator('.view-pane[data-view="validation"]');
    await expect(pane.getByText('SQLmap available')).toBeVisible();
    await pane.getByLabel('URL to validate',{exact:true}).fill('http://localhost:8082/item?id=1');
    await pane.getByLabel('Parameter',{exact:true}).fill('absent');
    await pane.getByRole('button',{name:'Start SQLmap validation',exact:true}).click();
    await expect(pane.getByRole('status').first()).toContainText('selected parameter must occur');
    await pane.getByLabel('Parameter',{exact:true}).fill('id');
    await pane.getByRole('button',{name:'Start SQLmap validation',exact:true}).click();
    await expect(pane.locator('.sqlmap-status')).toHaveText('Injection detected');
    await expect(pane.locator('.sqlmap-evidence article')).toContainText('id=1 AND 1=1');
    await expect(pane.locator('.sqlmap-payload-label')).toHaveText('Payload');
    await expect(pane.locator('pre[aria-label="Payload"]')).toHaveText('id=1 AND 1=1');
    const after=await h.page.evaluate(()=>window.reconbot.readRunState());
    expect(after.risk).toEqual(before.risk);
    expect(after.runState).toBe(before.runState);
    const saved=await h.page.evaluate(()=>window.reconbot.readSqlmap());
    expect(saved.jobs[0].parameter).toBe('id');expect(fs.existsSync(saved.jobs[0].reportPath)).toBeTruthy();
    await pane.getByLabel('URL to validate',{exact:true}).fill('http://localhost:8082/item?slow=1');
    await pane.getByLabel('Parameter',{exact:true}).fill('slow');
    await pane.getByRole('button',{name:'Start SQLmap validation',exact:true}).click();
    await expect(pane.locator('.sqlmap-console pre')).toContainText('Fixture SQLmap job: slow');
    await setRunScenario(h.app,'incomplete-partial');
    await expect(pane.getByText('This job belongs to another scan.')).toBeVisible();
    await expect(pane.getByText('No SQLmap jobs for this scan yet.')).toBeVisible();
    await pane.getByRole('button',{name:'Stop SQLmap',exact:true}).click();
    await setRunScenario(h.app,'historical');
    await expect(pane.locator('.sqlmap-status')).toHaveText('Cancelled');
    const result=await h.page.evaluate(()=>window.reconbot.readSqlmap());expect(result.active).toBeNull();expect(result.jobs[0].status).toBe('cancelled');
    await h.page.locator('.nav-rail [data-view="report"]').click();
    await h.page.getByRole('button',{name:'SQLmap evidence',exact:true}).click();
    await expect(pane).toBeVisible();
    await h.page.locator('.language-selector select').selectOption('tr');
    await expect(pane.getByRole('button',{name:'SQLmap doğrulamasını başlat',exact:true})).toBeVisible();
    await h.page.screenshot({path:testInfo.outputPath('sqlmap-tr.png'),fullPage:true});
    expect(h.errors).toEqual([]);
  }finally{
    await h.close();process.env.PATH=prior;fs.rmSync(bin,{recursive:true,force:true});
    // This test owns only its newly created validation subdirectory.
    if(jobRoot && fs.existsSync(jobRoot)) for(const name of fs.readdirSync(jobRoot)) if(!priorJobs.includes(name)) fs.rmSync(path.join(jobRoot,name),{recursive:true,force:true});
  }
});
