import { lazy, Suspense, useEffect, useState } from 'react';
import GlitchText from '@/components/GlitchText';
import AnimatedContent from '@/components/AnimatedContent';
import DecryptedText from '@/components/DecryptedText';
import SpecularButton from '@/components/SpecularButton';
import CanvasBoundary from '@/components/layout/CanvasBoundary';
import NearViewport from '@/components/layout/NearViewport';
import SocialIcon from '@/components/layout/SocialIcon';
import useAppLoaded from '@/hooks/useAppLoaded';
import { profile, socials, ui } from '@/data/content';
import useLang from '@/i18n/useLang';
import { asset } from '@/lib/asset';

// ogl is ~70 kB of WebGL runtime and purely decorative — keep it off the
// critical path so the headline paints first.
const DarkVeil = lazy(() => import('@/components/DarkVeil'));

const COMMAND = 'whoami';

/**
 * Types `whoami` at the prompt once the boot overlay has cleared — the name
 * below is its output. Reduced motion gets the finished line straight away.
 */
function useTyped(text: string, start: boolean) {
  const reduce =
    typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
  const [count, setCount] = useState(reduce ? text.length : 0);

  useEffect(() => {
    if (!start || count >= text.length) return;
    // A beat before the first key, then a human-ish uneven cadence.
    const delay = count === 0 ? 380 : 70 + ((count * 37) % 60);
    const id = window.setTimeout(() => setCount(c => c + 1), delay);
    return () => window.clearTimeout(id);
  }, [start, count, text.length]);

  return text.slice(0, count);
}

export default function Hero() {
  const { t, lang } = useLang();
  // The decrypt and the typed command are long enough to be wasted behind the
  // boot overlay, so they wait for the handoff instead of starting at mount.
  const loaded = useAppLoaded();
  const typed = useTyped(COMMAND, loaded);
  const tagline = t(profile.tagline);

  return (
    <section
      id="home"
      className="grain relative isolate flex min-h-[100svh] flex-col justify-center overflow-hidden px-6 lg:pl-52 xl:pl-72"
    >
      {/* DarkVeil (WebGL), hue-shifted from violet to signal green and run
          with faint CRT scanlines. Wrapped in a boundary because a failed GL
          context throws during init and would otherwise blank the page. */}
      <div aria-hidden className="pointer-events-none absolute inset-0 -z-10">
        <NearViewport className="absolute inset-0" fallback={<Backdrop />}>
          <CanvasBoundary fallback={<Backdrop />}>
            <Suspense fallback={<Backdrop />}>
              <DarkVeil
                speed={0.4}
                hueShift={60}
                warpAmount={0.6}
                noiseIntensity={0.025}
                scanlineIntensity={0.12}
                scanlineFrequency={2.2}
                resolutionScale={1}
              />
            </Suspense>
          </CanvasBoundary>
        </NearViewport>
      </div>

      {/* Fade the veil into the page so the section seam disappears */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-x-0 bottom-0 -z-10 h-64 bg-gradient-to-b from-transparent to-ink-950"
      />

      <div className="mx-auto w-full max-w-6xl pt-28 pb-20">
        {/* GlitchText renders a <div>, which cannot live inside an <h1>, so the
            heading is carried by a visually-hidden one for semantics and SEO. */}
        <h1 className="sr-only">
          {profile.fullName} — {t(profile.role)}
        </h1>

        <AnimatedContent distance={24} duration={0.8}>
          <p className="mb-6 inline-flex items-center gap-2.5 rounded-full border border-signal-glow/25 bg-signal-glow/[0.07] px-3.5 py-1.5 font-mono text-[11px] tracking-[0.08em] text-signal-glow/90 backdrop-blur-sm">
            <span aria-hidden className="h-2 w-2 animate-pulse-dot rounded-full bg-signal-glow" />
            {t(profile.status)}
          </p>
        </AnimatedContent>

        <AnimatedContent distance={30} duration={0.8}>
          {/* The prompt is decoration around the name, which is its "output"
              — screen readers get the name from the <h1> above. */}
          <p aria-hidden className="mb-3 font-mono text-[clamp(0.85rem,1.6vw,1.05rem)] text-mist-300">
            <span className="text-signal-glow">
              {profile.name.toLowerCase()}@{profile.handle.toLowerCase()}
            </span>
            <span className="text-mist-500">:</span>
            <span className="text-cyan-glow">~</span>
            <span className="text-mist-500">$ </span>
            <span className="text-mist-100">{typed}</span>
            <span className="ml-0.5 inline-block h-[1.1em] w-[0.55em] translate-y-[0.18em] animate-caret bg-signal-glow/90" />
          </p>
        </AnimatedContent>

        <GlitchText
          speed={1}
          enableShadows
          className="glitch text-signal-gradient font-display text-[clamp(2.75rem,9vw,6.5rem)] leading-[0.95] font-bold tracking-[-0.035em]"
        >
          {profile.fullName}
        </GlitchText>

        <div className="mt-7 max-w-2xl">
          <div className="flex flex-col items-start gap-2 font-display text-[1.25rem] font-semibold text-mist-100 sm:text-[1.45rem] md:flex-row md:items-center md:gap-3 md:text-[1.7rem]">
            <span>{t(ui.hero.iAmA)}</span>
            {/* One fixed role, so a plain highlighted tag rather than the
                reference design's RotatingText. */}
            <span className="inline-block rounded-lg bg-signal-glow px-2.5 py-0.5 text-ink-950 shadow-[0_0_28px_rgba(0,245,155,0.32)]">
              {t(profile.role)}
            </span>
          </div>
        </div>

        {/* Scrambles through random glyphs and resolves into the real copy.

            The unrevealed half reads as a hash: hex digits, salted with a few
            symbols. The hex is listed twice so the draw lands on it about three
            times in four — an even mix with the symbols looks like keyboard
            mash rather than a digest.

            The hidden copy underneath reserves the box. Scramble glyphs run
            wider than the real ones, so without it the text wrapped to an
            extra line and rocked everything below it for the whole animation.

            Keyed on the language, so switching re-runs the decrypt into the
            other language instead of swapping the text flat. */}
        <div className="relative mt-6 max-w-xl text-[clamp(1rem,2.2vw,1.35rem)] leading-relaxed">
          <p aria-hidden className="invisible">
            {tagline}
          </p>
          <p className="absolute inset-0 text-mist-300/85">
            {loaded && (
              <DecryptedText
                key={lang}
                text={tagline}
                animateOn="view"
                sequential
                revealDirection="start"
                characters="0123456789abcdef0123456789abcdef#$%&*+/<>^"
                // ~100 chars revealed one per tick, so this is
                // ms-per-character: ~2.8s end to end.
                speed={28}
                maxIterations={10}
                // Monospace sells the digest; every glyph in JetBrains Mono is
                // 0.6em wide, and at 0.82em that lands under Inter's average,
                // which keeps the scramble inside the reserved box.
                encryptedClassName="font-mono text-[0.82em] tracking-tight text-signal-glow/60"
              />
            )}
          </p>
        </div>

        <div className="mt-10 flex flex-wrap items-center gap-4">
          {/* Both carry an href, so they render as anchors rather than the
              component's default <button> — see the note on SpecularButton. */}
          <SpecularButton
            href="#projects"
            lineColor="#00f59b"
            baseColor="#0b4a35"
            intensity={1.15}
            className="min-h-11 font-mono text-[12px] tracking-wide uppercase"
          >
            {t(ui.hero.ctaWork)}
          </SpecularButton>

          <SpecularButton
            href={asset(profile.cv)}
            download
            lineColor="#22d3ee"
            baseColor="#3f3f46"
            intensity={0.85}
            textColor="#c9d4de"
            className="min-h-11 font-mono text-[12px] tracking-wide uppercase"
          >
            <span className="inline-flex items-center gap-2">
              <svg aria-hidden viewBox="0 0 24 24" className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                <polyline points="7 10 12 15 17 10" />
                <line x1="12" y1="15" x2="12" y2="3" />
              </svg>
              {t(ui.hero.ctaCv)}
            </span>
          </SpecularButton>
        </div>

        {/* Icon-only, so each link carries its name for screen readers. The
            44px box is the pointer target — the mark itself is smaller. */}
        <ul className="mt-12 -ml-3 flex flex-wrap items-center gap-1">
          {socials.map(s => (
            <li key={s.label}>
              <a
                href={s.href}
                target={s.href.startsWith('http') ? '_blank' : undefined}
                rel={s.href.startsWith('http') ? 'noreferrer' : undefined}
                aria-label={s.label}
                className="inline-flex h-11 w-11 items-center justify-center rounded-full text-mist-500 transition-all duration-300 hover:bg-white/5 hover:text-signal-glow focus-visible:bg-white/5 focus-visible:text-signal-glow"
              >
                <SocialIcon name={s.icon} className="h-5 w-5" />
              </a>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}

/**
 * Static stand-in for DarkVeil: layered radial glows in the site palette,
 * shown while `ogl` loads and kept permanently if WebGL is unavailable.
 */
function Backdrop() {
  return (
    <div aria-hidden className="absolute inset-0 overflow-hidden">
      <div className="absolute -top-1/3 left-1/2 h-[75vh] w-[125vw] -translate-x-1/2 rounded-[50%] bg-[radial-gradient(ellipse_at_center,#00a86b_0%,transparent_62%)] opacity-45 blur-3xl" />
      <div className="absolute -top-1/4 left-[24%] h-[58vh] w-[72vw] -translate-x-1/2 rounded-[50%] bg-[radial-gradient(ellipse_at_center,#22d3ee_0%,transparent_66%)] opacity-30 blur-3xl" />
      <div className="absolute top-[8%] right-[-10%] h-[45vh] w-[55vw] rounded-[50%] bg-[radial-gradient(ellipse_at_center,#0f766e_0%,transparent_70%)] opacity-35 blur-3xl" />
    </div>
  );
}
