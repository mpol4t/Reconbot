// Native bundle smoke test. No development interpreter or repository environment.
const { _electron } = require('../node_modules/playwright');
const fs = require('fs'), path = require('path'), os = require('os'), assert = require('assert/strict');
(async () => {
  const root = path.resolve(__dirname, '..');
  fs.mkdirSync(path.join(root, 'test-results'), {recursive:true});
  const data = fs.mkdtempSync(path.join(root, 'test-results/native-smoke-'));
  const env = { ...process.env, RECONBOT_E2E_USER_DATA_DIR: data };
  for (const name of ['RECONBOT_REPO_ROOT', 'RECONBOT_PYTHON', 'RECONBOT_E2E', 'PYTHONPATH', 'VIRTUAL_ENV']) delete env[name];
  const executablePath = process.env.RECONBOT_SMOKE_EXECUTABLE || path.join(root, 'dist/mac-arm64/ReconBot.app/Contents/MacOS/ReconBot');
  const app = await _electron.launch({ executablePath, args: process.platform === 'linux' && process.getuid() === 0 ? ['--no-sandbox'] : [], cwd: os.tmpdir(), env });
  try {
    const p = await app.firstWindow(), errors = [];
    p.on('pageerror', e => errors.push(e.message));
    await p.locator('.nav-rail').waitFor();
    const info = await app.evaluate(async ({ app, ipcMain }) => {
      const defaults = await ipcMain._invokeHandlers.get('config:get-defaults')({});
      return { name: app.getName(), packaged: app.isPackaged, defaults, path: process.resourcesPath, userData: app.getPath('userData') };
    });
    assert.equal(info.name, 'ReconBot'); assert.equal(info.packaged, true);
    assert.equal(info.defaults.outputDir, path.join(data, 'workspace', 'output'));
    assert.equal(info.defaults.wordlist, '');
    const {execFileSync} = require('child_process');
    const backend = path.join(info.path, 'backend', 'reconbot-backend');
    const preflight = execFileSync(backend, ['-m', 'reconbot', '--check-runtime'], {cwd: os.tmpdir(), env, encoding:'utf8'});
    assert.match(preflight, /requests.*OK/); assert.doesNotMatch(preflight, /PySide6/);
    const context = JSON.parse(execFileSync(backend, ['-m', 'reconbot.ai.assistant'], {cwd:os.tmpdir(), env, input:JSON.stringify({action:'context'}), encoding:'utf8'}));
    assert.equal(typeof context, 'object');
    const runDir = path.join(info.defaults.outputDir, 'runs', 'native-report-smoke');
    fs.mkdirSync(runDir, {recursive:true});
    fs.writeFileSync(path.join(runDir, 'run_result.json'), JSON.stringify({run_state:'completed',meta:{target:'http://localhost:8082'},summary:{},stages:{},auto_refresh_enabled:false}));
    execFileSync(backend, ['-m','reconbot','generate-report','--run-dir',runDir,'--report-depth','balanced'], {cwd:os.tmpdir(),env,encoding:'utf8'});
    assert(fs.existsSync(path.join(runDir,'cytoscape.min.js')));
    await app.evaluate(async ({ipcMain},dir)=>ipcMain._invokeHandlers.get('history:select-run')({},dir),runDir);
    for (const view of ['configure','terminal','report','artifacts','findings','validation','authentication','pipeline','settings','dashboard']) {
      await p.locator(`.nav-rail [data-view="${view}"]`).click();
      assert.equal(await p.locator('.view-pane.active').getAttribute('data-view'), view);
      if (view === 'report') {
        await p.frameLocator('.report-frame').locator('#overview').waitFor();
        const frame = p.frames().find(item=>item.url().startsWith('reconbot-report:'));
        await frame.waitForFunction(()=>typeof cytoscape==='function');
      }
      if (view === 'settings') {
        await app.evaluate(({BrowserWindow}) => BrowserWindow.getAllWindows()[0].setSize(1100, 780));
        const toggle = p.locator('.setting-toggle').first();
        await toggle.evaluate(node => node.scrollIntoView({block:'center', inline:'nearest'}));
        const before = await toggle.boundingBox();
        await toggle.click();
        await p.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
        assert(Math.abs((await toggle.boundingBox()).y - before.y) < 64);
        assert(Math.abs(await p.evaluate(() => window.scrollY)) < 1);
        await toggle.click();
      }
    }
    assert.deepEqual(errors, []);
    fs.writeFileSync(path.join(root,'test-results/native-smoke.json'), JSON.stringify({name:info.name,packaged:info.packaged,output:info.defaults.outputDir,backendPreflight:'passed',AIContext:'passed',offlineReport:'passed',navigation:'passed',settingsViewport:'passed',errors},null,2));
    console.log('Native application: identity, writable output, bundled backend, AI context, offline report and navigation passed.');
  } finally { await app.close(); }
})().catch(e=>{console.error(e);process.exit(1)});
