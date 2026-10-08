import { useSyncExternalStore } from "react";
import messages from "./messages.json";

export type Language = "en" | "tr";
const STORAGE_KEY = "reconbot.ui.language";
const listeners = new Set<() => void>();
const catalog = new Map<string, readonly [string, string]>();
for (const entry of messages as Array<[string, string, ...string[]]>) {
  for (const alias of entry) catalog.set(alias.replace(/\s+/g, " ").trim(), [entry[0], entry[1]]);
}

function readLanguage(): Language {
  try { return localStorage.getItem(STORAGE_KEY) === "tr" ? "tr" : "en"; }
  catch { return "en"; }
}
let language: Language = readLanguage();
if (typeof document !== "undefined") document.documentElement.lang = language;

export function getLanguage(): Language { return language; }
export function setLanguage(next: Language): void {
  if (next !== "en" && next !== "tr") return;
  language = next;
  if (typeof document !== "undefined") document.documentElement.lang = next;
  try { localStorage.setItem(STORAGE_KEY, next); } catch { /* Keep the session preference if storage is unavailable. */ }
  for (const listener of listeners) listener();
}
function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}
export function useLanguage(): Language {
  return useSyncExternalStore(subscribe, getLanguage, () => "en");
}

/** Translate application-owned copy only. Never pass model answers, logs or artifact values. */
export function t(source: string, values?: Record<string, string | number>): string {
  const normalized = source.replace(/\s+/g, " ").trim();
  const entry = catalog.get(normalized);
  const text = entry ? entry[language === "tr" ? 1 : 0] : source;
  return values ? text.replace(/\{(\w+)\}/g, (match, key) => String(values[key] ?? match)) : text;
}
