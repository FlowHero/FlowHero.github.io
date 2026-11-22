import { useCallback, useContext } from 'react';
import { LangContext } from './context';
import { tx, type Localized, type Text } from './text';

/**
 * The active language, a setter, and `t()` to resolve any copy from
 * content.ts in it:
 *
 *   const { t } = useLang();
 *   t(ui.hero.ctaWork)   // 'View my work' | 'Voir mes projets'
 *   t(profile.roles)     // the role list for the active language
 */
export default function useLang() {
  const ctx = useContext(LangContext);
  if (!ctx) throw new Error('useLang must be used inside <LangProvider>');
  const { lang, setLang } = ctx;

  // Typed as an overload pair: a `Text` resolves to a string, any other
  // localized value (a role list, a paragraph array) to its own type.
  const t = useCallback(
    (text: Text | Localized<unknown>) => tx(text as Localized<unknown>, lang),
    [lang]
  ) as {
    (text: Text): string;
    <T>(text: Localized<T>): T;
  };

  return { lang, setLang, t };
}
