import { useEffect, useId, useRef, useState } from 'react';
import { FolderOpen, LockKeyhole, UnlockKeyhole } from 'lucide-react';
import type { WordlistSlot } from '../../shared/wordlists';
import { t } from '../lib/i18n';

interface Props { slot: WordlistSlot; label: string; value: string; placeholder?: string; onChange: (value: string) => void; disabled?: boolean; }
export default function WordlistField({ slot, label, value, placeholder, onChange, disabled }: Props): JSX.Element {
  const id = useId(), changeRef = useRef(onChange);
  changeRef.current = onChange;
  const [locked, setLocked] = useState(false), [ready, setReady] = useState(false), [pending, setPending] = useState(false), [message, setMessage] = useState('');
  useEffect(() => {
    let alive = true;
    void window.reconbot.readWordlistPreferences().then(saved => {
      if (!alive) return;
      const item = saved[slot];
      if (item.path) changeRef.current(item.path);
      setLocked(item.locked);
      if (item.path && !item.available) setMessage('The saved wordlist is unavailable. Unlock it to choose another file.');
      setReady(true);
    }).catch(error => { if (alive) { setMessage(String(error)); setReady(true); } });
    return () => { alive = false; };
  }, [slot]);
  const save = async (): Promise<void> => {
    setPending(true);
    try {
      const result = await window.reconbot.saveWordlistPreference(slot, { path: value, locked: !locked });
      if (!result.ok || !result.preference) { setMessage(result.message || 'Could not save wordlist preference.'); return; }
      changeRef.current(result.preference.path); setLocked(result.preference.locked);
      setMessage(result.preference.locked ? 'Saved for future sessions.' : 'Unlocked. Choose a file, then save and lock it.');
    } catch (error) { setMessage(String(error)); } finally { setPending(false); }
  };
  const browse = async (): Promise<void> => {
    try { const file = await window.reconbot.chooseWordlistFile(); if (file) { changeRef.current(file); setMessage(''); } }
    catch (error) { setMessage(String(error)); }
  };
  return <div className="field wordlist-field">
    <label htmlFor={id}>{t(label)}</label>
    <input id={id} value={value} placeholder={placeholder} readOnly={locked} disabled={disabled || !ready} onChange={event => { onChange(event.target.value); setMessage(''); }} />
    <div className="wordlist-controls">
      <button type="button" disabled={disabled || !ready || pending || locked} onClick={() => { void browse(); }}><FolderOpen size={14} />{t('Browse')}</button>
      <button type="button" aria-pressed={locked} disabled={disabled || !ready || pending || !value.trim()} onClick={() => { void save(); }}>{locked ? <UnlockKeyhole size={14} /> : <LockKeyhole size={14} />}{t(locked ? 'Unlock path' : 'Save and lock')}</button>
    </div>
    <small role="status">{t(message || (locked ? 'Saved path · locked' : 'Saved paths are reused when ReconBot restarts.'))}</small>
  </div>;
}
