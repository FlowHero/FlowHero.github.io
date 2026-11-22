import { useMemo, useState } from 'react';
import ChromaGrid, { type ChromaItem } from '@/components/ChromaGrid';
import AnimatedContent from '@/components/AnimatedContent';
import GradientHeading from '@/components/layout/GradientHeading';
import ProjectDialog from '@/components/layout/ProjectDialog';
import { projects, ui } from '@/data/content';
import useLang from '@/i18n/useLang';
import { projectCover } from '@/lib/cover';
import { asset } from '@/lib/asset';

export default function Work() {
  const { t } = useLang();
  // Index rather than the project itself: the grid reports the card position,
  // and null is simply "nothing open".
  const [selected, setSelected] = useState<number | null>(null);

  // The generated covers are a few KB of SVG each — build them once, not on
  // every render. They don't depend on the language (the seed is the English
  // title), so switching language never changes the art.
  const images = useMemo(
    () =>
      projects.map(p =>
        p.image ? asset(p.image) : projectCover({ accent: p.accent, title: typeof p.title === 'string' ? p.title : p.title.en, motif: p.motif })
      ),
    []
  );

  const items: ChromaItem[] = projects.map((p, i) => ({
    image: images[i],
    title: t(p.title),
    subtitle: t(p.blurb),
    tech: [...p.tech],
    borderColor: p.accent,
    gradient: `linear-gradient(145deg, ${p.accent}, transparent)`,
    badge: p.domain,
    url: p.url,
  }));

  return (
    <section id="projects" className="relative px-6 py-24 sm:py-32 lg:pl-52 xl:pl-72">
      <div className="mx-auto max-w-6xl">
        <GradientHeading eyebrow="ls ~/projects" lede={t(ui.projects.lede)}>
          {t(ui.projects.title)}
        </GradientHeading>

        <AnimatedContent distance={60} duration={0.9} threshold={0.1}>
          {/* The card opens the write-up instead of the link — the link lives
              inside the dialog, where there is room to label it. Two columns
              from sm: four projects fill two even rows, where three columns
              left one stranded. `!` because the component's own
              `xl:grid-cols-3` would otherwise win or lose on sheet order. */}
          <ChromaGrid
            items={items}
            desaturate={false}
            onCardSelect={setSelected}
            readMoreLabel={t(ui.projects.readMore)}
            className="xl:grid-cols-2!"
          />
        </AnimatedContent>
      </div>

      {/* Mounted only while open, so <dialog> opens on mount and closing is an
          unmount — no stale element left in the top layer. */}
      {selected !== null && (
        <ProjectDialog project={projects[selected]} image={images[selected]} onClose={() => setSelected(null)} />
      )}
    </section>
  );
}
