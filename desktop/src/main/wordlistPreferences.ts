import fs from 'node:fs';
import path from 'node:path';
import type { WordlistSlot, WordlistPreference, WordlistPreferences, WordlistSaveResult } from '../shared/wordlists';

const slots: WordlistSlot[] = ['discovery', 'authUsers', 'authPasswords'];
export class WordlistPreferenceStore {
  constructor(private readonly file: string, private readonly repoRoot: string) {}
  private load(): Partial<Record<WordlistSlot, { path: string; locked: boolean }>> {
    if (!fs.existsSync(this.file)) return {};
    const value = JSON.parse(fs.readFileSync(this.file, 'utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Could not read saved wordlist preferences.');
    const result: Partial<Record<WordlistSlot, { path: string; locked: boolean }>> = {};
    for (const slot of slots) {
      const item = value[slot];
      if (item && typeof item.path === 'string' && typeof item.locked === 'boolean') result[slot] = item;
    }
    return result;
  }
  private available(file: string): boolean {
    try { fs.accessSync(file, fs.constants.R_OK); return fs.statSync(file).isFile(); } catch { return false; }
  }
  read(): WordlistPreferences {
    const saved = this.load();
    return Object.fromEntries(slots.map(slot => {
      const item = saved[slot] || { path: '', locked: false };
      return [slot, { ...item, available: Boolean(item.path) && this.available(item.path) }];
    })) as WordlistPreferences;
  }
  save(slot: WordlistSlot, input: { path: string; locked: boolean }): WordlistSaveResult {
    try {
      if (!slots.includes(slot) || !input || typeof input.path !== 'string' || typeof input.locked !== 'boolean') throw new Error('Invalid wordlist preference.');
      if (!input.path.trim() || input.path.length > 4096 || /[\0\r\n]/.test(input.path)) throw new Error('Enter a readable wordlist file path.');
      const file = path.resolve(this.repoRoot, input.path.trim());
      const saved = this.load(), previous = saved[slot];
      if (previous?.locked && file !== previous.path) throw new Error('Unlock the saved wordlist before changing its path.');
      // Unlock must still work after a saved file has been moved or deleted.
      const unlocking = previous?.locked && !input.locked && file === previous.path;
      if (!unlocking && !this.available(file)) throw new Error('The wordlist file does not exist or cannot be read.');
      saved[slot] = { path: file, locked: input.locked };
      fs.mkdirSync(path.dirname(this.file), { recursive: true });
      const temporary = this.file + '.tmp';
      fs.writeFileSync(temporary, JSON.stringify(saved, null, 2), { mode: 0o600 });
      fs.renameSync(temporary, this.file);
      const preference: WordlistPreference = { ...saved[slot]!, available: this.available(file) };
      return { ok: true, preference };
    } catch (error) { return { ok: false, message: error instanceof Error ? error.message : String(error) }; }
  }
}
