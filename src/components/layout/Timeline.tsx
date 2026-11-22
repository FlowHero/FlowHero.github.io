import AnimatedContent from '@/components/AnimatedContent';
import GlareHover from '@/components/GlareHover';
import GradientHeading from '@/components/layout/GradientHeading';
import { timeline, type TimelineEntry } from '@/data/content';
import useLang from '@/i18n/useLang';
import { asset } from '@/lib/asset';

type Props = {
  /** Which entries to list — experience and education are separate blocks. */
  kind: TimelineEntry['kind'];
  /**
   * Anchor for the block. The previous site had `#experience` and
   * `#education` sections, so links to those still land here.
   */
  id: string;
  title: string;
  eyebrow: string;
};

/**
 * One chronology — work experience or education. Lives inside the About
 * section rather than owning a top-level section, so every scroll position
 * still maps to one rail item.
 *
 * Each entry is a glass card with a diagonal glare sweep on hover (React Bits
 * GlareHover). The spine and nodes are what make it read as a chronology
 * rather than a pile of cards; roles get a lit node, education a dim one.
 */
export default function Timeline({ kind, id, title, eyebrow }: Props) {
  const { t } = useLang();
  const entries = timeline.filter(e => e.kind === kind);
  const job = kind === 'experience';

  return (
    // scroll-mt so a deep link to #experience / #education doesn't park the
    // heading against the very top edge.
    <div id={id} className="mt-20 scroll-mt-16 sm:mt-28">
      <GradientHeading as="h3" size="sub" eyebrow={eyebrow}>
        {title}
      </GradientHeading>

      <ol className="relative">
        {/* Spine — only worth drawing when there is a sequence to join. */}
        {entries.length > 1 && (
          <span
            aria-hidden
            className="absolute top-2 bottom-2 left-[7px] w-px bg-gradient-to-b from-signal-glow/60 via-white/10 to-transparent sm:left-[calc(9rem+7px)]"
          />
        )}

        {/* The spacing sits on the <li>, not on the inner div: that div is the
            only child of its AnimatedContent wrapper, so `last:pb-0` there
            matched every entry and flattened the gap between all of them. */}
        {entries.map((entry, i) => (
          <li key={`${entry.org}-${i}`} className="pb-10 last:pb-0">
            <AnimatedContent distance={45} duration={0.85} delay={i * 0.08} threshold={0.15}>
              <div className="relative flex flex-col gap-2 pl-9 sm:flex-row sm:gap-8 sm:pl-0">
                <span className="shrink-0 pt-4 font-mono text-[11px] tracking-[0.1em] text-mist-500 uppercase sm:w-36 sm:pr-8 sm:text-right">
                  {t(entry.period)}
                </span>

                {/* Node */}
                <span
                  aria-hidden
                  className={`absolute top-5 left-0 grid h-[15px] w-[15px] place-items-center rounded-full ring-4 ring-ink-950 sm:left-36 ${
                    job ? 'bg-signal-glow shadow-[0_0_14px_rgba(0,245,155,0.55)]' : 'bg-cyan-glow/70'
                  }`}
                >
                  <span className="h-1 w-1 rounded-full bg-ink-950/70" />
                </span>

                <div className="min-w-0 flex-1 sm:pl-8">
                  <GlareHover
                    width="100%"
                    height="auto"
                    borderRadius="16px"
                    background={job ? 'rgba(0, 245, 155, 0.045)' : 'rgba(34, 211, 238, 0.04)'}
                    borderColor={job ? 'rgba(0, 245, 155, 0.22)' : 'rgba(34, 211, 238, 0.2)'}
                    glareColor="#22d3ee"
                    glareOpacity={0.16}
                    glareSize={220}
                    transitionDuration={750}
                    // These go through `style` rather than className because
                    // the component's own classes set `grid place-items-center`
                    // and `cursor-pointer`: inline wins, and a text card needs
                    // to flow left-aligned and not pretend to be clickable.
                    //
                    // `justifyItems` is the non-obvious one. Chrome applies box
                    // alignment to block layout, not just grid, so the
                    // `place-items-center` class kept centring every child as
                    // a shrink-to-fit box even with `display: block`.
                    // `stretch` is the block default.
                    style={{ display: 'block', justifyItems: 'stretch', cursor: 'default' }}
                    className="p-5 backdrop-blur-sm transition-colors duration-500 hover:border-white/25 sm:p-6"
                  >
                    <div className="flex items-start gap-4">
                      {entry.logo && (
                        <span className="grid h-14 w-14 shrink-0 place-items-center rounded-xl border border-white/10 bg-white/[0.04] p-2">
                          <img src={asset(entry.logo)} alt="" className="h-full w-full object-contain" loading="lazy" />
                        </span>
                      )}
                      <div className="min-w-0">
                        <h4 className="font-display text-lg leading-snug font-semibold tracking-tight text-mist-100 sm:text-xl">
                          {t(entry.title)}
                        </h4>
                        <p className="mt-1.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-sm">
                          <span className={`font-medium ${job ? 'text-signal-glow' : 'text-cyan-glow'}`}>{entry.org}</span>
                          {entry.badge && (
                            <span className="rounded-full border border-cyan-glow/30 bg-cyan-glow/10 px-2 py-px font-mono text-[10px] tracking-[0.06em] text-cyan-glow/90 uppercase">
                              {t(entry.badge)}
                            </span>
                          )}
                        </p>
                        <p className="mt-1 font-mono text-[11px] tracking-[0.06em] text-mist-500">{t(entry.location)}</p>
                      </div>
                    </div>

                    {entry.description && (
                      <p className="mt-3 text-[14.5px] leading-relaxed text-mist-300/80">{t(entry.description)}</p>
                    )}

                    {entry.highlights && (
                      <ul className="mt-3 space-y-1.5">
                        {t(entry.highlights).map(point => (
                          <li
                            key={point}
                            className="relative pl-4 text-[14.5px] leading-relaxed text-mist-300/80 before:absolute before:top-0 before:left-0 before:font-mono before:text-[12px] before:text-signal-glow/70 before:content-['›']"
                          >
                            {point}
                          </li>
                        ))}
                      </ul>
                    )}

                    {entry.tags && (
                      <ul className="mt-4 flex flex-wrap gap-1.5">
                        {entry.tags.map(tag => (
                          <li
                            key={t(tag)}
                            className={`rounded-full border px-2.5 py-0.5 font-mono text-[10.5px] tracking-[0.08em] uppercase ${
                              job
                                ? 'border-signal-glow/25 bg-signal-glow/10 text-signal-glow/90'
                                : 'border-cyan-glow/25 bg-cyan-glow/10 text-cyan-glow/90'
                            }`}
                          >
                            {t(tag)}
                          </li>
                        ))}
                      </ul>
                    )}
                  </GlareHover>
                </div>
              </div>
            </AnimatedContent>
          </li>
        ))}
      </ol>
    </div>
  );
}
