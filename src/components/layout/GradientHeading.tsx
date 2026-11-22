import AnimatedContent from '@/components/AnimatedContent';

type Props = {
  children: React.ReactNode;
  lede?: string;
  /**
   * Mono label above the title, styled as a path at a shell prompt —
   * `~/about.md`. Carried over from the previous site's section labels.
   */
  eyebrow?: string;
  /** `section` is a top-level section title; `sub` is a heading within one. */
  size?: 'section' | 'sub';
  as?: 'h2' | 'h3';
  /** Extra classes for the heading element alone, not the divider or lede. */
  titleClassName?: string;
};

/**
 * The green-to-cyan gradient heading used across the page.
 *
 * `inline-block` is load-bearing: as a full-width block the gradient box spans
 * the container and the glyphs only sample its middle, which renders flat.
 * Hugging the text shows the whole ramp.
 */
export default function GradientHeading({
  children,
  lede,
  eyebrow,
  size = 'section',
  as: Tag = 'h2',
  titleClassName = '',
}: Props) {
  return (
    <AnimatedContent distance={40} duration={0.9} threshold={0.15}>
      <div className={size === 'section' ? 'mb-14 text-center sm:mb-20' : 'mb-8 text-center'}>
        {eyebrow && (
          <p className="mb-3 font-mono text-[11px] tracking-[0.18em] text-mist-500 uppercase">
            <span aria-hidden className="text-signal-glow/80">
              ${' '}
            </span>
            {eyebrow}
          </p>
        )}
        <Tag
          // opacity-80 on every section title: the headings sit over the
          // shader backdrops, and holding them back a little keeps them from
          // shouting over the content. Large bold type, so it stays well
          // clear of the 3:1 contrast floor.
          className={`text-signal-gradient mb-4 inline-block font-display font-bold tracking-tight opacity-80 ${
            size === 'section' ? 'text-4xl md:text-5xl' : 'text-2xl md:text-3xl'
          } ${titleClassName}`}
        >
          {children}
        </Tag>
        <span
          aria-hidden
          className="mx-auto mt-1 block h-px w-20 bg-gradient-to-r from-transparent via-signal-glow to-transparent"
        />
        {lede && (
          <p className="mx-auto mt-5 max-w-2xl text-lg leading-relaxed text-mist-300/80">{lede}</p>
        )}
      </div>
    </AnimatedContent>
  );
}
