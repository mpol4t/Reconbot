// Build-time notices only; no scanner or application runtime changes.
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const desktop = path.resolve(__dirname, '..');
const root = path.resolve(process.env.RECONBOT_LICENSE_ROOT || path.join(desktop, '..'));
const output = path.resolve(process.env.RECONBOT_LICENSE_OUTPUT || path.join(desktop, 'build', 'licenses'));
const pkg = JSON.parse(fs.readFileSync(path.join(desktop, 'package.json'), 'utf8'));
if (pkg.license !== 'GPL-3.0-only') throw new Error('Unexpected ReconBot license');
fs.mkdirSync(output, { recursive: true });
for (const file of ['LICENSE', 'COPYRIGHT', 'THIRD_PARTY_NOTICES.md']) {
  fs.copyFileSync(path.join(root, file), path.join(output, file));
}
const lock = JSON.parse(fs.readFileSync(path.join(desktop, 'package-lock.json'), 'utf8'));
const components = [];
let text = 'ReconBot third-party license notices\n\nThese components retain their original terms; ReconBot does not relicense them.\n\n';
for (const [location, entry] of Object.entries(lock.packages)) {
  if (!location || (entry.dev && location !== 'node_modules/electron')) continue;
  const directory = path.join(desktop, location);
  const metadata = JSON.parse(fs.readFileSync(path.join(directory, 'package.json'), 'utf8'));
  const notices = fs.readdirSync(directory).filter(name => /^(licen[cs]e|copying|notice)([._-].*)?$/i.test(name) && fs.statSync(path.join(directory, name)).isFile());
  if (!notices.length) throw new Error(`Missing license notice: ${location}`);
  const component = { ecosystem: 'npm', name: metadata.name, version: metadata.version, license: entry.license || metadata.license, source: `https://www.npmjs.com/package/${metadata.name}/v/${metadata.version}` };
  components.push(component);
  text += `\n${'='.repeat(72)}\n${component.name} ${component.version} (${component.license})\nSource: ${component.source}\n`;
  for (const name of notices) text += `\n${name}\n${fs.readFileSync(path.join(directory, name), 'utf8')}\n`;
}
const python = process.env.RECONBOT_PYTHON || path.join(root, '.venv', 'bin', 'python');
const code = String.raw`
import json, sys, sysconfig
from importlib import metadata
from pathlib import Path
names=['dnspython','requests','urllib3','PyYAML','tldextract','certifi','charset-normalizer','idna','requests-file','filelock']
records=[]
for name in names:
 d=metadata.distribution(name);m=d.metadata;notices=[]
 for f in d.files or []:
  if f.name.lower().startswith(('license','copying','notice')):
   p=d.locate_file(f)
   if p.is_file():notices.append({'name':f.name,'text':p.read_text(errors='replace')})
 if not notices:raise RuntimeError('Missing Python license: '+name)
 records.append({'ecosystem':'python','name':name,'version':d.version,'license':m.get('License-Expression') or m.get('License','See notices'),'source':'https://pypi.org/project/'+name+'/'+d.version+'/', 'notices':notices})
minor=str(sys.version_info.major)+'.'+str(sys.version_info.minor)
paths=[Path(sysconfig.get_path('stdlib'))/'LICENSE.txt',Path('/usr/share/doc/libpython'+minor+'-stdlib/copyright'),Path('/usr/share/doc/python'+minor+'/copyright')]
for p in paths:
 if p.is_file():
  records.append({'ecosystem':'runtime','name':'CPython','version':sys.version.split()[0],'license':'PSF and included third-party notices','source':'https://www.python.org/downloads/source/','notices':[{'name':'CPython LICENSE','text':p.read_text(errors='replace')}]});break
else:raise RuntimeError('CPython license file not found')
print(json.dumps(records))
`;
const records = JSON.parse(execFileSync(python, ['-c', code], { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 }));
for (const { notices, ...component } of records) {
  components.push(component);
  text += `\n${'='.repeat(72)}\n${component.name} ${component.version} (${component.license})\nSource: ${component.source}\n`;
  for (const item of notices) text += `\n${item.name}\n${item.text}\n`;
}
text += '\nElectron/Chromium include further notices in the runtime distribution. External scanners and local models are not bundled.\n';
fs.writeFileSync(path.join(output, 'DEPENDENCY-LICENSES.txt'), text);
fs.writeFileSync(path.join(output, 'components.json'), JSON.stringify(components, null, 2) + '\n');
console.log(`Prepared GPL and notices for ${components.length} bundled components.`);
