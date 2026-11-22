import type { IconType } from 'react-icons';
import { SiHackthebox, SiTryhackme } from 'react-icons/si';
import { TbBrandAws, TbBrandAzure } from 'react-icons/tb';
import AnimatedContent from '@/components/AnimatedContent';
import GradientHeading from '@/components/layout/GradientHeading';
import { certifications, ui, type Certification } from '@/data/content';
import useLang from '@/i18n/useLang';

function Trophy({ className, style }: { className?: string; style?: React.CSSProperties }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" className={className} style={style}>
      <path d="M6 9H4.5a2.5 2.5 0 0 1 0-5H6" />
      <path d="M18 9h1.5a2.5 2.5 0 0 0 0-5H18" />
      <path d="M4 22h16" />
      <path d="M10 14.66V17c0 .55-.47.98-.97 1.21C7.85 18.75 7 20.24 7 22" />
      <path d="M14 14.66V17c0 .55.47.98.97 1.21C16.15 18.75 17 20.24 17 22" />
      <path d="M18 2H6v7a6 6 0 0 0 12 0V2z" />
    </svg>
  );
}

const ICONS: Record<Certification['icon'], IconType | typeof Trophy> = {
  htb: SiHackthebox,
  thm: SiTryhackme,
  azure: TbBrandAzure,
  aws: TbBrandAws,
  trophy: Trophy,
};

/**
 * Certifications & achievements — not a section the reference design has,
 * but the first thing a security hiring manager looks for.
 *
 * The backdrop is static CSS on purpose (a dot lattice, see `.cyber-grid`):
 * the Skills aurora above and the Contact plasma below already run shaders,
 * and a quiet section between them keeps the page's rhythm.
 */
export default function Certifications() {
  const { t } = useLang();

  return (
    <section
      id="certifications"
      className="relative isolate overflow-hidden px-6 py-24 sm:py-32 lg:pl-52 xl:pl-72"
    >
      <div aria-hidden className="cyber-grid pointer-events-none absolute inset-0 -z-10" />

      <div className="mx-auto max-w-6xl">
        <GradientHeading eyebrow="ls ~/certs" lede={t(ui.certs.lede)}>
          {t(ui.certs.title)}
        </GradientHeading>

        <ul className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
          {certifications.map((cert, i) => (
            <li key={`${t(cert.title)}-${i}`} className="h-full">
              <AnimatedContent distance={40} duration={0.8} delay={(i % 3) * 0.08} threshold={0.1} className="h-full">
                <CertCard cert={cert} />
              </AnimatedContent>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}

function CertCard({ cert }: { cert: Certification }) {
  const { t } = useLang();
  const Icon = ICONS[cert.icon];
  const title = t(cert.title);

  const body = (
    <>
      {/* Pointer spotlight, tinted with the issuer's colour. */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 rounded-[inherit] opacity-0 transition-opacity duration-300 group-hover:opacity-100"
        style={{
          background: `radial-gradient(300px circle at var(--mx, 50%) var(--my, 0%), ${cert.color}1a, transparent 70%)`,
        }}
      />

      <div className="relative flex items-start justify-between gap-3">
        <span
          className="grid h-12 w-12 shrink-0 place-items-center rounded-xl border"
          style={{ borderColor: `${cert.color}38`, background: `${cert.color}12` }}
        >
          <Icon aria-hidden className="h-6 w-6" style={{ color: cert.color }} />
        </span>
        {cert.badge && (
          <span
            className="rounded-full border px-2.5 py-1 font-mono text-[10px] tracking-[0.12em] uppercase"
            style={{ borderColor: `${cert.color}55`, background: `${cert.color}14`, color: cert.color }}
          >
            {t(cert.badge)}
          </span>
        )}
      </div>

      <div className="relative mt-5 flex flex-1 flex-col">
        <h3 className="font-display text-lg leading-snug font-semibold text-white">{title}</h3>
        <p className="mt-1 font-mono text-[11px] tracking-[0.08em] text-signal-glow/85 uppercase">{t(cert.issuer)}</p>
        <p className="mt-3 text-sm leading-relaxed text-mist-300/80">{t(cert.detail)}</p>

        {cert.progress !== undefined && (
          <div className="mt-auto pt-5">
            <div className="mb-1.5 flex items-center justify-between font-mono text-[11px] tracking-[0.06em]">
              <span className="text-mist-500 uppercase">{t(ui.certs.inProgress)}</span>
              <span className="text-signal-glow tabular-nums">{cert.progress}%</span>
            </div>
            <div
              className="h-1.5 overflow-hidden rounded-full bg-white/[0.07]"
              role="progressbar"
              aria-label={title}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={cert.progress}
            >
              <div
                className="h-full rounded-full bg-gradient-to-r from-signal-glow to-cyan-glow shadow-[0_0_12px_rgba(0,245,155,0.5)]"
                style={{ width: `${cert.progress}%` }}
              />
            </div>
          </div>
        )}

        {cert.url && (
          <span className="mt-auto inline-flex items-center gap-1.5 pt-5 font-mono text-[11px] font-medium tracking-[0.12em] text-mist-300 uppercase transition-colors duration-300 group-hover:text-signal-glow">
            {t(ui.certs.verify)}
            <svg aria-hidden viewBox="0 0 24 24" className="h-3.5 w-3.5 transition-transform duration-300 group-hover:translate-x-0.5 group-hover:-translate-y-0.5" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M7 17 17 7M9 7h8v8" />
            </svg>
          </span>
        )}
      </div>
    </>
  );

  const className = `group relative flex h-full flex-col rounded-2xl border p-6 backdrop-blur-sm transition-[border-color,transform,background-color] duration-300 hover:-translate-y-1 ${
    cert.featured
      ? 'cert-featured border-signal-glow/20 bg-signal-glow/[0.04] hover:bg-signal-glow/[0.06]'
      : 'border-white/[0.08] bg-ink-900/70 hover:border-white/20'
  }`;

  // Written straight to the element so moving the pointer doesn't re-render.
  const track = (e: React.PointerEvent<HTMLElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    e.currentTarget.style.setProperty('--mx', `${e.clientX - r.left}px`);
    e.currentTarget.style.setProperty('--my', `${e.clientY - r.top}px`);
  };

  // With proof to link to, the whole card is the link: a bigger target than
  // the "Verify" label alone, and one tab stop rather than two.
  return cert.url ? (
    <a href={cert.url} target="_blank" rel="noopener noreferrer" onPointerMove={track} className={className}>
      {body}
    </a>
  ) : (
    <div onPointerMove={track} className={className}>
      {body}
    </div>
  );
}
