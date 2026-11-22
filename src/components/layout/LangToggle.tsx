import { languages } from '@/i18n/text';
import useLang from '@/i18n/useLang';
import { ui } from '@/data/content';

/**
 * EN / FR switch, fixed to the viewport.
 *
 * Top-right from lg up. Below lg the StaggeredMenu header owns both top
 * corners (logo left, toggle right), so the switch moves to the top centre,
 * between them — it stays above the open panel too, where the header area is
 * empty because the panel's list starts 6em down.
 */
export default function LangToggle() {
  const { lang, setLang, t } = useLang();

  return (
    <div
      role="group"
      aria-label={t(ui.langToggle)}
      className="fixed top-5 left-1/2 z-[60] flex -translate-x-1/2 items-center rounded-full border border-white/10 bg-ink-900/70 p-1 font-mono text-[11px] tracking-[0.14em] backdrop-blur-md lg:top-6 lg:right-6 lg:left-auto lg:translate-x-0"
    >
      {languages.map(l => {
        const active = l === lang;
        return (
          <button
            key={l}
            type="button"
            lang={l}
            aria-pressed={active}
            onClick={() => setLang(l)}
            // 44px tall target from a 30px-looking pill: the padding is the
            // hit area, the visible chip is the inner span.
            className="group -my-2 inline-flex h-11 min-w-11 items-center justify-center px-1 uppercase"
          >
            <span
              className={`rounded-full px-2.5 py-1 transition-colors duration-200 ${
                active
                  ? 'bg-signal-glow/15 text-signal-glow'
                  : 'text-mist-500 group-hover:text-mist-100 group-focus-visible:text-mist-100'
              }`}
            >
              {l}
            </span>
          </button>
        );
      })}
    </div>
  );
}
