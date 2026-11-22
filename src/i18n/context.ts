import { createContext } from 'react';
import type { Lang } from './text';

export type LangContextValue = {
  lang: Lang;
  setLang: (lang: Lang) => void;
};

export const LangContext = createContext<LangContextValue | null>(null);

/**
 * Same key the previous, static version of the site wrote, so a visitor who
 * picked French there still gets French here.
 */
export const STORAGE_KEY = 'lang';
