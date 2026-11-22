import { useEffect, useMemo, useRef, useState } from 'react';
import AnimatedContent from '@/components/AnimatedContent';
import SkillRadar from '@/components/layout/SkillRadar';
import { skillDomains, ui, type SkillDomain } from '@/data/content';
import useLang from '@/i18n/useLang';

/** Stroke icons from the previous site's skill cards, on a 24px grid. */
const ICONS: Record<SkillDomain['icon'], React.ReactNode> = {
  target: (
    <>
      <circle cx="12" cy="12" r="10" />
      <circle cx="12" cy="12" r="6" />
      <circle cx="12" cy="12" r="2" />
    </>
  ),
  shield: (
    <>
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <polyline points="9 12 11 14 15 10" />
    </>
  ),
  layers: (
    <>
      <polygon points="12 2 2 7 12 12 22 7 12 2" />
      <polyline points="2 17 12 22 22 17" />
      <polyline points="2 12 12 17 22 12" />
    </>
  ),
  terminal: (
    <>
      <polyline points="4 17 10 11 4 5" />
      <line x1="12" y1="19" x2="20" y2="19" />
    </>
  ),
  wrench: (
    <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" />
  ),
  check: (
    <>
      <path d="M9 11l3 3L22 4" />
      <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11" />
    </>
  ),
};

/**
 * Six security domains: the radar on the left, one card per domain on the
 * right. Pointing at a card (or a legend entry) traces that domain's axis on
 * the radar, which is the link between the two halves.
 */
export default function SkillDomains() {
  const { t } = useLang();
  const [active, setActive] = useState<number | null>(null);

  // Stable per language (`t` is memoised on it), so the radar only redraws
  // its labels when they actually change.
  const axes = useMemo(
    () => skillDomains.map(d => ({ label: t(d.short), value: d.level, color: d.color })),
    [t]
  );

  return (
    <div className="mx-auto mt-24 grid max-w-6xl items-start gap-10 sm:mt-28 lg:grid-cols-[minmax(0,22rem)_1fr] xl:grid-cols-[minmax(0,25rem)_1fr]">
      <AnimatedContent distance={50} duration={0.9} threshold={0.15}>
        <div className="mx-auto w-full max-w-[26rem] lg:sticky lg:top-24">
          <div className="rounded-3xl border border-white/[0.08] bg-ink-950/60 p-4 backdrop-blur-md sm:p-6">
            <SkillRadar axes={axes} active={active} />
            <p className="mt-2 text-center font-mono text-[10.5px] tracking-[0.1em] text-mist-500 uppercase">
              {t(ui.skills.radarHint)}
            </p>
          </div>
          <ul className="mt-4 grid grid-cols-2 gap-x-4 gap-y-1 px-2 sm:grid-cols-3 lg:grid-cols-2">
            {skillDomains.map((d, i) => (
              <li
                key={d.color}
                onPointerEnter={() => setActive(i)}
                onPointerLeave={() => setActive(null)}
                className={`flex cursor-default items-center gap-2 rounded-md px-2 py-1.5 font-mono text-[11px] tracking-[0.04em] transition-colors duration-200 select-none ${
                  active === i ? 'bg-white/[0.06] text-white' : 'text-mist-300'
                }`}
              >
                <i
                  aria-hidden
                  className={`h-2 w-2 shrink-0 rounded-full transition-transform duration-200 ${active === i ? 'scale-150' : ''}`}
                  style={{ background: d.color, boxShadow: `0 0 6px ${d.color}99` }}
                />
                {t(d.short)}
              </li>
            ))}
          </ul>
        </div>
      </AnimatedContent>

      <ul className="grid gap-4 sm:grid-cols-2">
        {skillDomains.map((d, i) => (
          <DomainCard
            key={d.color}
            domain={d}
            index={i}
            active={active === i}
            onActive={setActive}
            title={t(d.title)}
            levelLabel={`${d.level}% ${t(ui.skills.proficiency)}`}
          />
        ))}
      </ul>
    </div>
  );
}

function DomainCard({
  domain,
  index,
  active,
  onActive,
  title,
  levelLabel,
}: {
  domain: SkillDomain;
  index: number;
  active: boolean;
  onActive: (i: number | null) => void;
  title: string;
  levelLabel: string;
}) {
  const ref = useRef<HTMLLIElement>(null);
  const [filled, setFilled] = useState(false);

  // The bar fills once, the first time the card is properly on screen.
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const io = new IntersectionObserver(
      ([entry]) => {
        if (!entry.isIntersecting) return;
        setFilled(true);
        io.disconnect();
      },
      { threshold: 0.35 }
    );
    io.observe(el);
    return () => io.disconnect();
  }, []);

  return (
    <li
      ref={ref}
      onPointerEnter={() => onActive(index)}
      onPointerLeave={() => onActive(null)}
      // Pointer-tracked spotlight, written straight to the element so moving
      // the mouse doesn't re-render the grid.
      onPointerMove={e => {
        const r = e.currentTarget.getBoundingClientRect();
        e.currentTarget.style.setProperty('--mx', `${e.clientX - r.left}px`);
        e.currentTarget.style.setProperty('--my', `${e.clientY - r.top}px`);
      }}
      className={`group relative overflow-hidden rounded-2xl border bg-ink-900/70 p-5 backdrop-blur-sm transition-[border-color,transform,box-shadow] duration-300 ${
        active ? '-translate-y-1' : ''
      }`}
      style={
        {
          '--c': domain.color,
          borderColor: active ? `${domain.color}88` : 'rgba(255,255,255,0.08)',
          boxShadow: active ? `0 0 24px ${domain.color}22, 0 8px 24px rgba(0,0,0,0.3)` : undefined,
        } as React.CSSProperties
      }
    >
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-0 transition-opacity duration-300 group-hover:opacity-100"
        style={{
          background: `radial-gradient(260px circle at var(--mx, 50%) var(--my, 50%), ${domain.color}1f, transparent 70%)`,
        }}
      />
      <div className="relative">
        <div className="flex items-center gap-3.5">
          <span
            className="grid h-11 w-11 shrink-0 place-items-center rounded-xl border transition-shadow duration-300"
            style={{
              color: domain.color,
              borderColor: `${domain.color}40`,
              background: `${domain.color}14`,
              boxShadow: active ? `0 0 16px ${domain.color}66` : undefined,
            }}
          >
            <svg
              aria-hidden
              viewBox="0 0 24 24"
              className="h-[22px] w-[22px]"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              {ICONS[domain.icon]}
            </svg>
          </span>
          <div className="min-w-0">
            <h4 className="font-display text-[1.05rem] leading-snug font-semibold text-white">{title}</h4>
            <p className="font-mono text-[11px] tracking-[0.06em] text-mist-500">{levelLabel}</p>
          </div>
        </div>

        <div
          className="mt-4 h-1 overflow-hidden rounded-full bg-white/[0.06]"
          role="meter"
          aria-label={title}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={domain.level}
        >
          <div
            className="h-full rounded-full transition-[width] duration-[1.4s] ease-[cubic-bezier(0.22,1,0.36,1)]"
            style={{
              width: filled ? `${domain.level}%` : '0%',
              background: `linear-gradient(90deg, ${domain.color}88, ${domain.color})`,
              boxShadow: `0 0 10px ${domain.color}88`,
            }}
          />
        </div>

        <ul className="mt-4 flex flex-wrap gap-1.5">
          {domain.tags.map(tag => (
            <li
              key={tag}
              className="rounded-md border border-white/[0.07] bg-white/[0.03] px-2 py-0.5 font-mono text-[10.5px] text-mist-300"
            >
              {tag}
            </li>
          ))}
        </ul>
      </div>
    </li>
  );
}
