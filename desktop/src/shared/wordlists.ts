export type WordlistSlot = 'discovery' | 'authUsers' | 'authPasswords';
export interface WordlistPreference { path: string; locked: boolean; available: boolean; }
export type WordlistPreferences = Record<WordlistSlot, WordlistPreference>;
export interface WordlistSaveResult { ok: boolean; preference?: WordlistPreference; message?: string; }
