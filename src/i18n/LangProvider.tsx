import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import { ui } from '@/data/content';
import { LangContext, STORAGE_KEY } from './context';
import { isLang, tx, type Lang } from './text';

/**
 * First visit: the browser's preferred language if it is French, otherwise
 * English. After that, whatever the visitor last picked.
 *
 * Storage is read in a try/catch because it throws outright in some private
 * modes and when site data is blocked — the toggle then simply forgets.
 */
function initialLang(): Lang {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (isLang(saved)) return saved;
  } catch {
    // storage unavailable — fall through to the browser's languages
  }
  const preferred = navigator.languages?.length ? navigator.languages : [navigator.language];
  return preferred.some(l => l?.toLowerCase().startsWith('fr')) ? 'fr' : 'en';
}

export default function LangProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(initialLang);

  const setLang = useCallback((next: Lang) => {
    setLangState(next);
    try {
      localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // not persisted, but the switch itself still happens
    }
  }, []);

  // <html lang> drives hyphenation, screen-reader pronunciation and the
  // browser's translate prompt, so it follows the toggle; so does the tab title.
  useEffect(() => {
    document.documentElement.lang = lang;
    document.title = tx(ui.meta.title, lang);
  }, [lang]);

  const value = useMemo(() => ({ lang, setLang }), [lang, setLang]);
  return <LangContext.Provider value={value}>{children}</LangContext.Provider>;
}
