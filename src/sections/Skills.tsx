import { lazy, Suspense, useEffect, useRef, useState } from 'react';
import LogoLoop from '@/components/LogoLoop';
import AnimatedContent from '@/components/AnimatedContent';
import GradientHeading from '@/components/layout/GradientHeading';
import CanvasBoundary from '@/components/layout/CanvasBoundary';
import NearViewport from '@/components/layout/NearViewport';
import MatrixRain from '@/components/layout/MatrixRain';
import SkillDomains from '@/components/layout/SkillDomains';
import ToolTile from '@/components/layout/ToolTile';
import { arsenal, learning, ui } from '@/data/content';
import useLang from '@/i18n/useLang';

// WebGL and purely decorative, like the hero's DarkVeil and About's LightRays.
const SoftAurora = lazy(() => import('@/components/SoftAurora'));
// gsap-driven and pointer-only, so it is no use until the page is interactive.
const TargetCursor = lazy(() => import('@/components/TargetCursor'));

const toolLogos = arsenal.map(name => ({
  node: <ToolTile name={name} />,
  title: name,
  ariaLabel: name,
}));

export default function Skills() {
  const { t } = useLang();
  const [cursorOnLoop, setCursorOnLoop] = useState(false);
  const loopRef = useRef<HTMLDivElement>(null);

  // LogoLoop repeats the row to fill the track, so each logo link appears
  // several times: aria-hidden hides the copies from screen readers, but they
  // stay in the tab order. Take them out of it by hand — `inert` would do it
  // in one attribute, but it also makes the copies ignore the pointer, which
  // left the target cursor dead on every logo outside the first copy. The
  // observer re-applies it because the copies are rebuilt on resize.
  useEffect(() => {
    const root = loopRef.current;
    if (!root) return;
    const apply = () =>
      root
        .querySelectorAll<HTMLElement>('ul[aria-hidden="true"] a')
        .forEach(a => a.setAttribute('tabindex', '-1'));
    apply();
    const observer = new MutationObserver(apply);
    observer.observe(root, { childList: true, subtree: true });
    return () => observer.disconnect();
  }, []);

  return (
    <section
      id="skills"
      className="relative isolate overflow-hidden px-6 py-24 sm:py-32 lg:pl-52 xl:pl-72"
    >
      <div className="mx-auto max-w-6xl">
        <GradientHeading eyebrow="cat ~/skills.json" lede={t(ui.skills.lede)}>
          {t(ui.skills.title)}
        </GradientHeading>
      </div>

      <div className="relative">
        {/* The aurora glows under the tiles and bleeds behind the cards.
            Much wider than this column so it runs the full width of the
            window, sidebar included — the section's overflow-hidden trims it.
            Its ribbon draws across the middle of the canvas, so the canvas is
            pulled up until that line sits just below the tiles, and a mask
            fades the top and bottom so no edge of the canvas ever shows.

            Not pointer-events-none, unlike the page's other backdrops:
            SoftAurora listens for mousemove on its own canvas. It sits at
            -z-10 with no click handlers, so the only events it takes are ones
            that would have hit the page background anyway. */}
        <div
          aria-hidden
          className="absolute top-[-13rem] left-1/2 -z-10 h-[44rem] w-[160vw] -translate-x-1/2 [mask-image:linear-gradient(to_bottom,transparent,black_30%,black_70%,transparent)]"
        >
          <NearViewport className="h-full w-full">
            <CanvasBoundary fallback={null}>
              <Suspense fallback={null}>
                {/* Stock React Bits settings re-tinted from magenta to the
                    site's green; bandSpread halved so the glow spreads
                    wider, with brightness buying back the lower peak. */}
                <SoftAurora
                  speed={0.6}
                  scale={1.5}
                  brightness={1.35}
                  color1="#e9fff6"
                  color2="#00f59b"
                  noiseFrequency={2.5}
                  noiseAmplitude={1}
                  bandHeight={0.5}
                  bandSpread={0.5}
                  octaveDecay={0.1}
                  layerOffset={0}
                  colorSpeed={1}
                  enableMouseInteraction
                  mouseInfluence={0.25}
                />
              </Suspense>
            </CanvasBoundary>
          </NearViewport>
        </div>

        {/* TargetCursor — a crosshair that locks onto each tool — hides the
            window's cursor for as long as it is mounted, which would be the
            whole page. So it is mounted only while the pointer is over the
            marquee, and its cleanup puts the cursor back on the way out. */}
        <div
          id="tool-loop"
          ref={loopRef}
          className="py-4"
          onPointerEnter={e => e.pointerType === 'mouse' && setCursorOnLoop(true)}
          onPointerLeave={() => setCursorOnLoop(false)}
        >
          {cursorOnLoop && (
            <Suspense fallback={null}>
              <TargetCursor targetSelector="#tool-loop .cursor-target" spinDuration={2.4} cursorColor="#00f59b" />
            </Suspense>
          )}
          {/* No fadeOut: its edge gradients are solid page colour, which would
              paint dark blocks over the aurora glowing behind.
              LogoLoop clips on the x axis, which clips y as well, so the
              tooltips above the tiles need room inside it: the padding makes
              that room and the negative margin gives the space back. */}
          <LogoLoop
            logos={toolLogos}
            speed={38}
            direction="left"
            logoHeight={64}
            gap={18}
            pauseOnHover
            className="-my-12 py-12"
            ariaLabel={t(ui.skills.marquee)}
          />
        </div>

        <SkillDomains />

        <AnimatedContent distance={50} duration={0.9} threshold={0.15}>
          {/* `isolate` keeps the rain's negative z-index inside the card:
              above its glass, below its copy. overflow-hidden clips the
              canvas to the rounded corners. */}
          <div className="relative isolate mx-auto mt-20 max-w-4xl overflow-hidden rounded-3xl border border-white/10 bg-ink-950/60 px-6 py-10 text-center shadow-[0_24px_80px_rgba(0,0,0,0.45)] backdrop-blur-md sm:mt-24 sm:px-12 sm:py-12">
            <MatrixRain className="pointer-events-none absolute inset-0 -z-10 h-full w-full opacity-60" />
            {/* Scrim: darkest behind the copy and clear toward the rim, so the
                rain frames the text instead of running through it. */}
            <div
              aria-hidden
              className="pointer-events-none absolute inset-0 -z-10"
              style={{
                background:
                  'radial-gradient(ellipse 62% 58% at 50% 50%, rgba(4,7,10,0.88) 0%, rgba(4,7,10,0.62) 55%, rgba(4,7,10,0) 100%)',
              }}
            />
            <h3 className="m-0 font-display text-2xl font-bold text-white sm:text-3xl">
              {t(learning.title)}
            </h3>
            <p className="mx-auto mt-5 max-w-3xl leading-relaxed text-mist-300 sm:text-lg">
              {t(learning.text)}
            </p>
            <ul className="mt-8 flex flex-wrap justify-center gap-3">
              {t(learning.topics).map(topic => (
                <li
                  key={topic}
                  className="rounded-full border border-cyan-glow/25 bg-cyan-glow/10 px-4 py-2 text-sm text-cyan-glow/90"
                >
                  {topic}
                </li>
              ))}
            </ul>
          </div>
        </AnimatedContent>
      </div>
    </section>
  );
}
