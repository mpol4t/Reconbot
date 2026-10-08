import { expect, test } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";
import { launchReconBot, setWindowSize, setRunScenario, readFixture } from "./harness";

test("graph selection clears by repeat click, background, Escape and Reset", async ({}, info) => {
  const h = await launchReconBot(info, "historical");
  try {
    const p = h.page;
    await p.locator('.nav-rail [data-view="pipeline"]').click();
    await p.getByRole('button', { name: 'Pause graph motion', exact: true }).click();
    const graph = p.locator('.evidence-graph');
    const target = graph.locator('[data-node-id="target"]');
    const cleared = async () => {
      await expect(graph.locator('[aria-pressed="true"]')).toHaveCount(0);
      await expect(graph.locator('.force-node.faded')).toHaveCount(0);
      await expect(graph.locator('.force-edge.faded')).toHaveCount(0);
    };
    await target.locator('.node-body').click();
    await expect(target).toHaveAttribute('aria-pressed', 'true');
    await target.locator('.node-body').click();
    await cleared(); // Pointer is still over the node: hover must not leave the map dimmed.
    await target.locator('.node-body').click();
    const box = (await graph.boundingBox())!;
    await p.mouse.click(box.x + 20, box.y + 20);
    await cleared();
    await target.locator('.node-body').click();
    await p.mouse.move(box.x + 20, box.y + 20);
    await p.mouse.down(); await p.mouse.move(box.x + 70, box.y + 55, { steps: 5 }); await p.mouse.up();
    await expect(target).toHaveAttribute('aria-pressed', 'true'); // Pan is not a background click.
    await target.focus(); await p.keyboard.press('Escape');
    await cleared();
    await target.focus(); await p.keyboard.press('Enter');
    await p.getByRole('button', { name: 'Recon', exact: true }).click();
    await p.getByRole('button', { name: 'Graph settings', exact: true }).click();
    await p.getByLabel('Search nodes', { exact: true }).fill('target-that-does-not-match');
    await p.getByRole('button', { name: 'Reset graph position', exact: true }).click();
    await cleared();
    await expect(p.getByRole('button', { name: 'All', exact: true })).toHaveAttribute('aria-pressed', 'true');
    await expect(p.locator('.graph-settings')).toHaveCount(0);
    expect(h.errors).toEqual([]);
  } finally { await h.close(); }
});

test("graph supports selection, drag, zoom, motion controls and workflow scope", async ({}, info) => {
  const h = await launchReconBot(info, "historical");
  try {
    const p = h.page;
    await setWindowSize(h.app, 1600, 1000);
    await p.locator('.nav-rail [data-view="pipeline"]').click();
    const graph = p.locator('.evidence-graph');
    await expect(graph).toBeVisible();
    const finding = graph.locator('[data-node-id^="finding:"]').first();
    await p.getByRole('button', { name: 'Pause graph motion', exact: true }).click();
    await finding.focus(); await p.keyboard.press('Enter');
    await expect(finding).toHaveAttribute("aria-pressed", "true");
    await expect(p.locator('.pipeline-evidence-list .finding-card')).toHaveCount(1);
    const original = await finding.getAttribute('style');
    const box = (await finding.locator('.node-body').boundingBox())!;
    await p.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await p.mouse.down(); await p.mouse.move(box.x + 75, box.y + 35, { steps: 5 }); await p.mouse.up();
    expect(await finding.getAttribute('style')).not.toBe(original);
    await p.getByRole('button', { name: 'Zoom in', exact: true }).click();
    await expect(p.locator('.graph-view-controls')).toContainText('110%');
    await p.getByRole('button', { name: 'Reset graph position', exact: true }).click();
    await expect(p.locator('.graph-view-controls')).toContainText('100%');
    expect(await finding.getAttribute('style')).not.toContain('NaN');
    await expect(p.locator('.evidence-graph-shell')).toHaveAttribute('data-motion', 'off');
    await p.getByRole('button', { name: 'Resume graph motion', exact: true }).click();
    await expect(p.locator('.evidence-graph-shell')).toHaveAttribute('data-motion', 'on');
    await p.emulateMedia({ reducedMotion: 'reduce' });
    await expect(p.locator('.evidence-graph-shell')).toHaveAttribute('data-motion', 'off');
    await p.emulateMedia({ reducedMotion: 'no-preference' });
    await p.getByRole('button', { name: 'Source workflow', exact: true }).click();
    await graph.locator('[data-node-id="target"]').focus(); await p.keyboard.press('Enter');
    await expect(p.locator('.pipeline-evidence-list .finding-card')).toHaveCount(0);
    await expect(p.locator('.pipeline-evidence-list')).toContainText('No evidence linked');
    await p.locator('.nav-rail [data-view="dashboard"]').click();
    await expect(p.locator('.evidence-graph-shell')).toHaveAttribute('data-motion', 'off');
    const preview = p.locator('.mini-evidence-graph [role="button"]').first();
    await preview.focus(); await p.keyboard.press('Enter');
    await expect(p.locator('.view-pane.active')).toHaveAttribute('data-view', 'pipeline');
    await expect(graph.locator('[data-node-id^="finding:"][aria-pressed="true"]')).toHaveCount(1);
    expect(h.errors).toEqual([]);
  } finally { await h.close(); }
});

test("graph shows all recorded endpoints without dropping distinct findings", async ({}, info) => {
  const output = path.resolve(__dirname, 'fixtures/runs/complete-report-run/nuclei_output.jsonl');
  const previous = fs.existsSync(output) ? fs.readFileSync(output) : null;
  fs.writeFileSync(output, Array.from({length: 9}, (_,i) => JSON.stringify({'template-id':'same-template',info:{name:'Recorded finding '+i,severity:'critical'},'matched-at':'https://complete-a.example/'+ 'long-path/'.repeat(20)+i})).join('\n'));
  const h = await launchReconBot(info, 'complete-report');
  try {
    const p = h.page;
    await p.locator('.nav-rail [data-view="pipeline"]').click();
    await expect(p.locator('[data-node-id^="finding:nuclei-"]')).toHaveCount(9);
    await expect(p.locator('[data-node-id^="endpoint:"]')).toHaveCount(9);
    await expect(p.locator('.graph-pagination')).toHaveCount(0);
    await p.getByRole('button', { name: 'Graph settings', exact: true }).click();
    await p.getByLabel('Search nodes', { exact: true }).fill('Recorded finding 8');
    await expect(p.locator('[data-node-id^="finding:"]:not(.faded)')).toHaveCount(1);
    expect(h.errors).toEqual([]);
  } finally { await h.close(); if(previous) fs.writeFileSync(output, previous); else fs.unlinkSync(output); }
});

test("interrupted stage and partial report stay factual in both languages", async ({}, info) => {
  const h = await launchReconBot(info, 'historical');
  try {
    const p = h.page;
    const interrupted = p.locator('.stage-phase.status-interrupted');
    await expect(interrupted).toHaveCount(1);
    await interrupted.locator('summary').click();
    await expect(interrupted.locator('.stage-tool-details')).toBeVisible();
    expect(await interrupted.locator('.stage-tool-details').evaluate(el => { const r=el.getBoundingClientRect(); return el.contains(document.elementFromPoint(r.x+20,r.y+20)); })).toBe(true);
    await expect(interrupted.locator('.stage-tool-details')).toContainText(/Interrupted|interrupted/);
    await expect(p.locator('.stage-phase').last()).toContainText('Partial report');
    await p.locator('.language-selector select').selectOption('tr');
    await expect(interrupted.locator('.stage-tool-details')).toContainText(/Kesildi|kesildi/);
    await expect(p.locator('.stage-phase').last()).toContainText('Kısmi rapor');
    const name = await h.app.evaluate(({app}) => app.getName()); expect(name).toBe('ReconBot');
    expect(h.errors).toEqual([]);
  } finally { await h.close(); }
});

test("disabled tools have factual metric labels instead of waiting", async ({}, info) => {
  const h = await launchReconBot(info, "incomplete-partial");
  try {
    await expect(h.page.locator('.metric-card').filter({hasText:'FFUF Hits'})).toContainText('Not run');
    await expect(h.page.locator('.metric-card').filter({hasText:'Screenshots'})).toContainText('Not run');
    await expect(h.page.getByText("Outside this scan's selected scope",{exact:false})).toBeVisible();
    expect(h.errors).toEqual([]);
  } finally { await h.close(); }
});


test("finding focus folds discovery, expands by keyboard and retains live selection", async ({}, info) => {
  const findingPath=path.resolve(__dirname,'fixtures/runs/complete-report-run/nuclei_output.jsonl');
  const previousFinding=fs.existsSync(findingPath)?fs.readFileSync(findingPath):null;
  fs.writeFileSync(findingPath,JSON.stringify({'template-id':'focus-test',info:{name:'Recorded focus finding',severity:'high'},'matched-at':'https://complete-a.example/finding'})+'\n');
  const resultPath=path.resolve(__dirname,'fixtures/runs/complete-report-run/run_result.json');
  const previous=fs.readFileSync(resultPath);
  const result=JSON.parse(previous.toString());
  const urls=Array.from({length:75},(_,i)=>`https://complete-a.example/discovery/${i}`);
  result.katana={urls};fs.writeFileSync(resultPath,JSON.stringify(result));
  const h=await launchReconBot(info,'complete-report');
  try {
    const p=h.page;
    await setWindowSize(h.app,1280,800);
    await p.locator('.nav-rail [data-view="pipeline"]').click();
    await expect(p.getByRole('button',{name:'Finding focus',exact:true})).toHaveAttribute('aria-pressed','true');
    const graph=p.locator('.evidence-graph');
    const cluster=graph.locator('[data-node-id="cluster:katana"]');
    const compactCount=await graph.locator('[data-node-id]').count();
    await expect(cluster).toHaveAttribute('aria-expanded','false');
    await expect(cluster).toContainText('75 discovery URLs');
    await expect(graph.locator('[data-node-id^="endpoint:"]')).toHaveCount(1);
    await p.getByRole('button',{name:'Pause graph motion',exact:true}).click();
    await cluster.focus();await p.keyboard.press('Enter');
    await expect(cluster).toHaveAttribute('aria-expanded','true');
    await expect(graph.locator('[data-node-id^="endpoint:"]')).toHaveCount(76);
    await p.getByRole('button',{name:'Collapse URLs',exact:true}).click();
    await expect(cluster).toHaveAttribute('aria-expanded','false');
    await expect(graph.locator('[data-node-id]')).toHaveCount(compactCount);
    await p.getByRole('button',{name:'All discovery data',exact:true}).click();
    await expect(graph.locator('[data-node-id^="endpoint:"]')).toHaveCount(76);
    await expect(graph.locator('[data-node-id^="cluster:"]')).toHaveCount(0);
    await p.getByRole('button',{name:'Finding focus',exact:true}).click();
    const finding=graph.locator('[data-node-id^="finding:"]').first();
    await finding.focus();await p.keyboard.press('Enter');
    const selectedId=await finding.getAttribute('data-node-id');
    await expect(graph.locator('[data-node-id="target"]')).not.toHaveClass(/faded/);
    await expect(graph.locator('[data-node-id="source:nuclei"]')).not.toHaveClass(/faded/);
    await expect(cluster).toHaveClass(/faded/);
    result.katana.urls.push('https://complete-a.example/discovery/new');
    fs.writeFileSync(resultPath,JSON.stringify(result));
    await expect(cluster).toContainText('76 discovery URLs');
    await expect(graph.locator(`[data-node-id="${selectedId}"]`)).toHaveAttribute('aria-pressed','true');
    await expect(p.locator('.pipeline-evidence-list .finding-card')).toHaveCount(1);
    await p.locator('.language-selector select').selectOption('tr');
    await expect(p.getByRole('button',{name:'Bulgu odaklı',exact:true})).toHaveAttribute('aria-pressed','true');
    await expect(cluster).toContainText('76 keşif adresi');
    await cluster.focus();await p.keyboard.press('Enter');
    await expect(p.getByRole('button',{name:'Adresleri kapat',exact:true})).toBeVisible();
    expect(await p.evaluate(()=>document.documentElement.scrollWidth>innerWidth)).toBe(false);
    await setRunScenario(h.app,'incomplete-partial');
    await expect(graph.locator('[data-node-id^="cluster:"][aria-expanded="true"]')).toHaveCount(0);
    await expect(graph.locator('[aria-pressed="true"]')).toHaveCount(0);
    expect(h.errors).toEqual([]);
  } finally { await h.close();fs.writeFileSync(resultPath,previous);if(previousFinding)fs.writeFileSync(findingPath,previousFinding);else fs.unlinkSync(findingPath); }
});

test("large finding groups open individually from the inspector without losing evidence", async ({}, info) => {
  const output=path.resolve(__dirname,'fixtures/runs/complete-report-run/nuclei_output.jsonl');
  const previous=fs.existsSync(output)?fs.readFileSync(output):null;
  fs.writeFileSync(output,Array.from({length:35},(_,i)=>JSON.stringify({'template-id':'group-'+i,info:{name:'Grouped finding '+i,severity:'high'},'matched-at':'https://complete-a.example/finding/'+i})).join('\n'));
  const h=await launchReconBot(info,'complete-report');
  try {
    const p=h.page;await p.locator('.nav-rail [data-view="pipeline"]').click();
    const graph=p.locator('.evidence-graph'),group=graph.locator('[data-node-id="cluster:findings:nuclei"]');
    await expect(graph.locator('[data-node-id^="finding:"]')).toHaveCount(12);
    await expect(p.locator('.pipeline-evidence-list .finding-card').filter({hasText:'Grouped finding'})).toHaveCount(35);
    await expect(group).toContainText('23 more findings');
    await group.focus();await p.keyboard.press('Enter');
    await expect(graph.locator('[data-node-id^="finding:nuclei-"]')).toHaveCount(35);
    await expect(p.locator('.pipeline-evidence-list .finding-card')).toHaveCount(23);
    await p.getByRole('button',{name:'Collapse findings',exact:true}).click();
    await expect(graph.locator('[data-node-id^="finding:"]')).toHaveCount(12);
    await p.locator('.pipeline-evidence-list .finding-card').filter({hasText:'Grouped finding 34'}).click();
    await expect(graph.locator('[data-node-id^="finding:"][aria-pressed="true"]')).toContainText('Grouped finding 34');
    await expect(graph.locator('[data-node-id^="finding:"]')).toHaveCount(13);
    await expect(p.locator('.pipeline-evidence-list .finding-card')).toHaveCount(1);
    await p.getByRole('button',{name:'Show all findings',exact:true}).click();
    await expect(p.locator('.pipeline-evidence-list .finding-card').filter({hasText:'Grouped finding'})).toHaveCount(35);
    await expect(graph.locator('[data-node-id^="finding:"]')).toHaveCount(12);
    await p.getByRole('button',{name:'All discovery data',exact:true}).click();
    await expect(graph.locator('[data-node-id^="finding:nuclei-"]')).toHaveCount(35);
    await expect(graph.locator('[data-node-id^="endpoint:"]')).toHaveCount(35);
    expect(h.errors).toEqual([]);
  }finally{await h.close();if(previous)fs.writeFileSync(output,previous);else fs.unlinkSync(output);}
});

test("mouse clicks open URL clusters and their exact addresses are readable in the inspector", async ({}, info) => {
  const resultPath=path.resolve(__dirname,'fixtures/runs/complete-report-run/run_result.json');
  const previous=fs.readFileSync(resultPath), result=JSON.parse(previous.toString());
  const urls=['https://complete-a.example/discovery/a?token=raw-value','https://complete-a.example/discovery/b','https://complete-a.example/discovery/c'];
  result.katana={urls};fs.writeFileSync(resultPath,JSON.stringify(result));
  const h=await launchReconBot(info,'complete-report');
  try {
    const p=h.page;await setWindowSize(h.app,1280,800);
    await p.locator('.nav-rail [data-view="pipeline"]').click();
    await p.getByRole('button',{name:'Pause graph motion',exact:true}).click();
    const graph=p.locator('.evidence-graph'),cluster=graph.locator('[data-node-id="cluster:katana"]');
    await expect(cluster).toHaveAttribute('aria-expanded','false');
    await cluster.locator('.node-body').click();
    await expect(cluster).toHaveAttribute('aria-expanded','true');
    await expect(cluster).toHaveAttribute('aria-pressed','true');
    await expect(p.locator('.discovery-url-row')).toHaveCount(3);
    await expect(graph.locator('[data-node-id^="endpoint:"] .force-label')).toHaveCount(0);
    await expect(p.locator('.discovery-url-row code').first()).toHaveText(urls[0]);
    await p.locator('.discovery-url-row').first().getByRole('button',{name:'Copy URL',exact:true}).click();
    await expect(p.locator('.discovery-url-row').first()).toContainText('Copied');
    expect((await readFixture(h.app)).calls.some(call=>call.channel==='clipboard:copy'&&call.payload===urls[0])).toBe(true);
    await p.locator('.discovery-url-row').first().getByRole('button',{name:'Show on graph',exact:true}).click();
    await expect(graph.locator(`[data-node-id="endpoint:${urls[0]}"]`)).toHaveAttribute('aria-pressed','true');
    await expect(p.locator('.graph-address-detail code')).toHaveText(urls[0]);
    await expect(p.locator('.graph-address-sources')).toContainText('katana');
    await cluster.locator('.force-label').click();
    await expect(cluster).toHaveAttribute('aria-expanded','false');
    await expect(p.locator('.discovery-url-row')).toHaveCount(3);
    const box=(await cluster.locator('.node-body').boundingBox())!;
    await p.mouse.move(box.x+box.width/2,box.y+box.height/2);await p.mouse.down();
    await p.mouse.move(box.x+70,box.y+30,{steps:5});await p.mouse.up();
    await expect(cluster).toHaveAttribute('aria-expanded','false');
    await cluster.focus();await p.keyboard.press('Enter');
    await expect(cluster).toHaveAttribute('aria-expanded','true');
    await p.getByRole('button',{name:'Resume graph motion',exact:true}).click();
    await cluster.locator('.node-body').click();
    await expect(cluster).toHaveAttribute('aria-expanded','false');
    await p.locator('.language-selector select').selectOption('tr');
    await expect(p.locator('.discovery-url-row').first().getByRole('button',{name:'Grafikte göster',exact:true})).toBeVisible();
    expect(await p.evaluate(()=>document.documentElement.scrollWidth>innerWidth)).toBe(false);
    expect(h.errors).toEqual([]);
  }finally{await h.close();fs.writeFileSync(resultPath,previous);}
});

test("trackpad-sized wheel events zoom gently at the pointer and sensitivity is adjustable", async ({}, info) => {
  const h=await launchReconBot(info,'historical');
  try {
    const p=h.page;await setWindowSize(h.app,1280,800);
    await p.locator('.nav-rail [data-view="pipeline"]').click();
    await p.getByRole('button',{name:'Pause graph motion',exact:true}).click();
    const graph=p.locator('.evidence-graph'),camera=graph.locator('.graph-camera');
    const scale=async()=>Number((await camera.getAttribute('transform'))!.match(/scale\(([^)]+)\)/)![1]);
    const box=(await graph.boundingBox())!,anchor={x:Math.floor(box.x+box.width*.45),y:Math.floor(box.y+box.height*.5)};
    const world=()=>graph.evaluate((el,point)=>{const svg=el as SVGSVGElement,p=svg.createSVGPoint();p.x=point.x;p.y=point.y;const result=p.matrixTransform((svg.querySelector('.graph-camera') as SVGGElement).getScreenCTM()!.inverse());return{x:result.x,y:result.y};},anchor);
    await p.mouse.move(anchor.x,anchor.y);const before=await scale(),fixed=await world();
    for(let i=0;i<20;i++)await p.mouse.wheel(0,1);
    await expect.poll(scale).toBeLessThan(before*.99);
    expect(await scale()).toBeGreaterThan(before*.97);
    const after=await world();expect(Math.abs(after.x-fixed.x)).toBeLessThan(.001);expect(Math.abs(after.y-fixed.y)).toBeLessThan(.001);
    await p.mouse.wheel(0,-20);await expect.poll(async()=>Math.abs(await scale()-before)).toBeLessThan(1e-7);
    await p.getByRole('button',{name:'Zoom in',exact:true}).click();await expect(p.locator('.graph-view-controls')).toContainText('110%');
    await p.getByRole('button',{name:'Graph settings',exact:true}).click();
    const settingsBox=(await p.locator('.graph-settings').boundingBox())!,canvasBox=(await p.locator('.evidence-graph-shell').boundingBox())!;
    expect(settingsBox.y+settingsBox.height).toBeLessThanOrEqual(canvasBox.y+canvasBox.height);
    const sensitivity=p.getByLabel(/Zoom sensitivity/);
    const sliderBox=(await sensitivity.boundingBox())!;expect(sliderBox.y+sliderBox.height).toBeLessThanOrEqual(canvasBox.y+canvasBox.height);
    await sensitivity.focus();await p.keyboard.press('Home');await expect(sensitivity).toHaveValue('25');
    await p.mouse.move(anchor.x,anchor.y);const slowBefore=await scale();await p.mouse.wheel(0,-100);
    await expect.poll(scale).toBeGreaterThan(slowBefore);expect(await scale()).toBeLessThan(slowBefore*1.03);
    await p.mouse.wheel(0,100);await expect.poll(async()=>Math.abs(await scale()-slowBefore)).toBeLessThan(1e-7);
    const pinchBefore=await scale();await graph.dispatchEvent('wheel',{deltaY:-2,deltaMode:0,ctrlKey:true,clientX:anchor.x,clientY:anchor.y});
    await expect.poll(scale).toBeGreaterThan(pinchBefore);expect(await scale()).toBeLessThan(pinchBefore*1.02);
    const burstBefore=await scale();await p.mouse.wheel(0,-10000);
    await expect.poll(scale).toBeGreaterThan(burstBefore);expect(await scale()).toBeLessThan(burstBefore*1.13);
    await p.locator('.language-selector select').selectOption('tr');await expect(p.getByLabel(/Yakınlaştırma hassasiyeti/)).toHaveValue('25');
    expect(h.errors).toEqual([]);
  }finally{await h.close();}
});
