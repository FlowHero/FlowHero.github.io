import { lazy, Suspense } from 'react';
import AnimatedContent from '@/components/AnimatedContent';
import ProfileCard from '@/components/ProfileCard';
import CanvasBoundary from '@/components/layout/CanvasBoundary';
import AboutCard from '@/components/layout/AboutCard';
import GradientHeading from '@/components/layout/GradientHeading';
import Timeline from '@/components/layout/Timeline';
import { profile, ui } from '@/data/content';
import useLang from '@/i18n/useLang';
import { asset } from '@/lib/asset';

// WebGL, and purely decorative — same treatment as the hero's DarkVeil.
const LightRays = lazy(() => import('@/components/LightRays'));

export default function About() {
  const { t } = useLang();

  return (
    <section id="about" className="relative isolate overflow-hidden px-6 py-24 sm:py-32 lg:pl-52 xl:pl-72">
      {/* Rays rake down across the section, tinted a pale mint so they read
          as the same light as the hero. Boundary-wrapped because ogl throws
          outright when a GL context is unavailable, which would take the
          whole page with it. */}
      <div aria-hidden className="pointer-events-none absolute inset-0 -z-10">
        <CanvasBoundary fallback={null}>
          <Suspense fallback={null}>
            <LightRays raysColor="#b5ffe1" />
          </Suspense>
        </CanvasBoundary>
      </div>
      {/* Keep the rays from colliding with the section seams above and below. */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-x-0 top-0 -z-10 h-40 bg-gradient-to-b from-ink-950 to-transparent"
      />
      <div
        aria-hidden
        className="pointer-events-none absolute inset-x-0 bottom-0 -z-10 h-40 bg-gradient-to-t from-ink-950 to-transparent"
      />

      <div className="mx-auto max-w-6xl">
        <GradientHeading eyebrow="cat ~/about.md" lede={t(ui.about.lede)}>
          {t(ui.about.title)}
        </GradientHeading>

        {/* Side by side from xl, as one row: the grid stretches both cells to
            the taller one, and the profile card fills its cell (index.css,
            `.pc-fit` under xl), so the card and the text start and end on the
            same lines. Below xl they stack — next to a 24rem card the text
            column would be too narrow to read. */}
        <div className="grid gap-12 xl:grid-cols-[minmax(0,24rem)_1fr] xl:items-stretch xl:gap-14">
          {/* `pc-fit` (index.css) makes the card size from this column's width
              (or, from xl, its height) rather than from the viewport. */}
          <div className="mx-auto w-full max-w-[24rem] xl:mx-0">
            <ProfileCard
              className="pc-fit"
              // Luminance mask for the holographic shine: padlocks, shields,
              // keys and prompts glint through it as the card tilts.
              iconUrl={asset('/card-icons.svg')}
              // The photo from the previous site, cut out of its white
              // backdrop and faded out below the chin (see README).
              avatarUrl={asset('/subject.webp')}
              miniAvatarUrl={asset('/subject.webp')}
              innerGradient="linear-gradient(145deg, #0b3b2c8c 0%, #22d3ee33 100%)"
              behindGlowColor="rgba(0, 245, 155, 0.55)"
              name={profile.fullName}
              title={t(profile.role)}
              handle={profile.handle}
              status={t(ui.about.cardStatus)}
              contactText={t(ui.about.cardContact)}
              onContactClick={() => {
                window.location.href = `mailto:${profile.email}`;
              }}
            />
          </div>

          <AnimatedContent direction="horizontal" distance={60} duration={0.9} threshold={0.15} className="xl:h-full">
            <AboutCard />
          </AnimatedContent>
        </div>

        <Timeline kind="experience" id="experience" title={t(ui.about.experience)} eyebrow="cat ~/experience.log" />
        <Timeline kind="education" id="education" title={t(ui.about.education)} eyebrow="cat ~/education.txt" />
      </div>
    </section>
  );
}
