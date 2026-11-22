import { lazy, Suspense } from 'react';
import { SiGmail } from 'react-icons/si';
import AnimatedContent from '@/components/AnimatedContent';
import CanvasBoundary from '@/components/layout/CanvasBoundary';
import GradientHeading from '@/components/layout/GradientHeading';
import SocialIcon from '@/components/layout/SocialIcon';
import { contact, profile, socials, ui } from '@/data/content';
import useLang from '@/i18n/useLang';
import { asset } from '@/lib/asset';

// WebGL and purely decorative, like the other section backdrops.
const Plasma = lazy(() => import('@/components/Plasma'));

export default function Contact() {
  const { t } = useLang();

  return (
    <section
      id="contact"
      className="relative isolate overflow-hidden px-6 py-24 sm:py-32 lg:pl-52 xl:pl-72"
    >
      {/* Not pointer-events-none, unlike the page's other backdrops: Plasma
          listens for mousemove on its own container. It sits at -z-10 with no
          click handlers, so it only takes events that would have hit the page
          background anyway. Boundary-wrapped because ogl throws outright
          without a GL context. */}
      <div aria-hidden className="absolute inset-0 -z-10">
        <CanvasBoundary fallback={null}>
          <Suspense fallback={null}>
            <Plasma
              color="#0fb487"
              speed={1}
              direction="forward"
              scale={1}
              opacity={0.9}
              mouseInteractive
              iterations={60}
              renderScale={0.55}
              targetFps={60}
              maxDpr={1.5}
            />
          </Suspense>
        </CanvasBoundary>
      </div>
      {/* Blend the plasma into the section above instead of starting on a
          hard edge. */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-x-0 top-0 -z-10 h-48 bg-gradient-to-b from-ink-950 to-transparent"
      />

      <div className="mx-auto max-w-4xl">
        <GradientHeading eyebrow="./contact --init" lede={t(ui.contact.lede)}>
          {t(ui.contact.title)}
        </GradientHeading>

        <AnimatedContent distance={50} duration={0.9} threshold={0.15}>
          <div className="rounded-3xl border border-white/10 bg-ink-900/80 p-8 backdrop-blur-xl">
            <h3 className="mb-6 text-center font-display text-2xl font-bold text-white">
              {t(ui.contact.connect)}
            </h3>
            <p className="mx-auto mb-8 max-w-2xl text-center leading-relaxed text-mist-300">
              {t(contact.intro)}
            </p>

            <div className="mb-8 flex flex-col items-center gap-4 sm:flex-row sm:justify-center sm:gap-6">
              {/* The whole row is the link, not just the address: on its own
                  the address was a 20px-tall target, half what a finger
                  needs. The negative margin absorbs the padding. */}
              <a
                href={`mailto:${profile.email}`}
                className="group -mx-3 flex items-center gap-3 rounded-2xl px-3 py-2 transition-colors hover:bg-white/5 focus-visible:bg-white/5"
              >
                <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl">
                  <SiGmail aria-hidden className="h-6 w-6 text-[#EA4335]" />
                </span>
                <span className="min-w-0">
                  <span className="block text-sm font-medium text-white">{t(ui.contact.emailLabel)}</span>
                  <span className="block text-sm break-all text-mist-500 transition-colors group-hover:text-signal-glow group-focus-visible:text-signal-glow">
                    {profile.email}
                  </span>
                </span>
              </a>

              <a
                href={asset(profile.cv)}
                download
                className="group -mx-3 flex items-center gap-3 rounded-2xl px-3 py-2 transition-colors hover:bg-white/5 focus-visible:bg-white/5"
              >
                <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-signal-glow/30 bg-signal-glow/10 text-signal-glow">
                  <svg aria-hidden viewBox="0 0 24 24" className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                    <polyline points="7 10 12 15 17 10" />
                    <line x1="12" y1="15" x2="12" y2="3" />
                  </svg>
                </span>
                <span className="min-w-0">
                  <span className="block text-sm font-medium text-white">CV</span>
                  <span className="block text-sm text-mist-500 transition-colors group-hover:text-signal-glow group-focus-visible:text-signal-glow">
                    {t(ui.contact.cv)}
                  </span>
                </span>
              </a>
            </div>

            <div className="text-center">
              <p className="mb-4 font-medium text-white">{t(ui.contact.follow)}</p>
              <ul className="flex justify-center gap-4">
                {/* Email is already the row above; only the profiles here. */}
                {socials
                  .filter(s => s.icon !== 'email')
                  .map(s => (
                    <li key={s.label}>
                      <a
                        href={s.href}
                        target="_blank"
                        rel="noopener noreferrer"
                        aria-label={s.label}
                        title={s.label}
                        className="flex h-11 w-11 items-center justify-center rounded-lg border border-white/10 text-mist-300 transition-all duration-300 hover:scale-110 hover:border-signal-glow/40 hover:bg-white/5 hover:text-signal-glow"
                      >
                        <SocialIcon name={s.icon} className="h-5 w-5" />
                      </a>
                    </li>
                  ))}
              </ul>
            </div>
          </div>
        </AnimatedContent>

        <footer className="mt-10 flex flex-col items-center gap-1.5 text-center font-mono text-[11px] tracking-wide text-mist-500">
          <p>
            © {new Date().getFullYear()} {profile.fullName} · {t(ui.contact.role)}
          </p>
          <p className="text-mist-500/80">{t(ui.contact.credit)}</p>
        </footer>
      </div>
    </section>
  );
}
