/**
 * Language primitives, kept free of React so the build-time SEO fallback
 * (vite/seo-fallback.ts) can resolve the same copy the components render.
 */

export const languages = ['en', 'fr'] as const;
export type Lang = (typeof languages)[number];

/** One value per site language. */
export type Localized<T> = { en: T; fr: T };

/**
 * A piece of copy. A plain string is shown as-is in both languages — names,
 * tools and acronyms read the same in French — while `{ en, fr }` is
 * translated.
 */
export type Text = string | Localized<string>;

/** Resolves a `Text` (or any localized value) for one language. */
export function tx(text: Text, lang: Lang): string;
export function tx<T>(text: Localized<T>, lang: Lang): T;
export function tx<T>(text: string | Localized<T>, lang: Lang): string | T {
  return typeof text === 'string' ? text : text[lang];
}

export function isLang(value: unknown): value is Lang {
  return typeof value === 'string' && (languages as readonly string[]).includes(value);
}
