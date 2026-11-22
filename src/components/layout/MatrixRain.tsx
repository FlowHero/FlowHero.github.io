import { useEffect, useRef } from 'react';

type Props = {
  className?: string;
  style?: React.CSSProperties;
  /** Trail colour. */
  color?: string;
  /** The leading glyph of each stream, drawn brighter like cmatrix's bold head. */
  headColor?: string;
  /** Glyph size in CSS px; also the column pitch. */
  fontSize?: number;
  /** Ticks per second. cmatrix's default delay reads at roughly 20–25. */
  fps?: number;
  /** Share of the canvas faded out per tick: lower means longer trails. */
  fade?: number;
  /** Glyphs to rain. Defaults to cmatrix's own: printable ASCII. */
  chars?: string;
};

const ASCII = Array.from({ length: 94 }, (_, i) => String.fromCharCode(33 + i)).join('');

/**
 * cmatrix-style digital rain on a 2D canvas: columns of glyphs falling at
 * their own speeds, each stream led by a bright head with a green trail
 * behind it, and the odd glyph in a trail flickering to a new one.
 *
 * Trails fade with `destination-out` rather than the usual translucent black
 * wash, so the canvas stays transparent between streams and whatever sits
 * behind it — here the card's glass — shows through instead of turning into
 * an opaque black panel.
 *
 * It only animates while on screen, starts already mid-fall (the first
 * seconds are simulated up front rather than shown as an empty box), and
 * under prefers-reduced-motion draws one still frame and stops.
 */
export default function MatrixRain({
  className = '',
  style,
  color = '#00f59b',
  headColor = '#e8fff6',
  fontSize = 14,
  fps = 22,
  fade = 0.11,
  chars = ASCII,
}: Props) {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    const ctx = canvas?.getContext('2d');
    if (!canvas || !ctx) return;

    const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;
    const glyph = () => chars[(Math.random() * chars.length) | 0];

    let w = 0;
    let h = 0;
    let rows = 0;
    // Per column: head position in rows (negative = waiting above the top),
    // rows advanced per tick, the last row drawn, and the glyph drawn there.
    let pos = new Float32Array(0);
    let speed = new Float32Array(0);
    let drawnRow = new Int32Array(0);
    let drawnGlyph: string[] = [];

    // "Nothing drawn yet". It has to fit an Int32Array: MIN_SAFE_INTEGER
    // would wrap to 1 there and read as a real row.
    const NONE = -1_000_000;

    const respawn = (i: number, anywhere: boolean) => {
      pos[i] = anywhere ? Math.random() * rows * 1.6 - rows * 0.6 : -Math.random() * rows * 0.9;
      speed[i] = 0.35 + Math.random() * 0.65;
      drawnRow[i] = NONE;
    };

    const tick = () => {
      // Fade everything already drawn toward transparent.
      ctx.globalCompositeOperation = 'destination-out';
      ctx.fillStyle = `rgba(0,0,0,${fade})`;
      ctx.fillRect(0, 0, w, h);
      ctx.globalCompositeOperation = 'source-over';

      for (let i = 0; i < pos.length; i++) {
        pos[i] += speed[i];
        const row = Math.floor(pos[i]);
        if (row !== drawnRow[i]) {
          const x = i * fontSize;
          // The old head becomes trail: repaint it in the trail colour.
          if (drawnRow[i] >= 0 && drawnRow[i] < rows) {
            ctx.fillStyle = color;
            ctx.fillText(drawnGlyph[i], x, drawnRow[i] * fontSize);
          }
          if (row >= 0 && row < rows) {
            const g = glyph();
            ctx.fillStyle = headColor;
            ctx.fillText(g, x, row * fontSize);
            drawnGlyph[i] = g;
          }
          drawnRow[i] = row;
        }
        // Past the bottom and its trail gone: start a new stream, after a gap.
        if (row > rows + 12 && Math.random() > 0.96) respawn(i, false);
      }

      // cmatrix's flicker: a couple of trail glyphs change in place.
      ctx.fillStyle = color;
      for (let k = 0; k < 2; k++) {
        const i = (Math.random() * pos.length) | 0;
        const row = drawnRow[i] - 1 - ((Math.random() * 10) | 0);
        if (row >= 0 && row < rows) {
          const x = i * fontSize;
          ctx.clearRect(x, row * fontSize, fontSize, fontSize);
          ctx.fillText(glyph(), x, row * fontSize);
        }
      }
    };

    const setup = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = canvas.clientWidth;
      h = canvas.clientHeight;
      if (!w || !h) return false;
      // Resizing a canvas resets its whole context, font included.
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.font = `${fontSize}px 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace`;
      ctx.textBaseline = 'top';

      const cols = Math.ceil(w / fontSize);
      rows = Math.ceil(h / fontSize);
      pos = new Float32Array(cols);
      speed = new Float32Array(cols);
      drawnRow = new Int32Array(cols);
      drawnGlyph = new Array(cols).fill('');
      for (let i = 0; i < cols; i++) respawn(i, true);
      // Pre-roll, so the rain is already falling when it comes into view.
      for (let k = 0; k < rows * 1.5; k++) tick();
      return true;
    };

    let raf = 0;
    let last = 0;
    let running = false;
    const frame = (t: number) => {
      raf = requestAnimationFrame(frame);
      if (t - last < 1000 / fps) return;
      last = t;
      tick();
    };
    const start = () => {
      if (running || reduce) return;
      running = true;
      raf = requestAnimationFrame(frame);
    };
    const stop = () => {
      running = false;
      cancelAnimationFrame(raf);
    };

    let ready = setup();
    let visible = false;

    // Canvas has no :visible; a rain nobody can see shouldn't cost a frame.
    const io = new IntersectionObserver(
      ([entry]) => {
        visible = entry.isIntersecting;
        if (visible && ready) start();
        else stop();
      },
      { rootMargin: '120px 0px' }
    );
    io.observe(canvas);

    // The card changes height with the copy (a language switch) and width
    // with the viewport; re-grid on either.
    const ro = new ResizeObserver(() => {
      if (canvas.clientWidth === w && canvas.clientHeight === h) return;
      ready = setup();
      if (ready && visible) start();
    });
    ro.observe(canvas);

    // The pre-roll may have drawn in the fallback face; once JetBrains Mono
    // is in, redraw from a fresh grid. Guarded: in dev StrictMode this effect
    // runs twice, and the first run's callback must not touch the canvas.
    let alive = true;
    document.fonts?.ready.then(() => {
      if (alive) ready = setup();
    });

    return () => {
      alive = false;
      stop();
      io.disconnect();
      ro.disconnect();
    };
  }, [chars, color, headColor, fontSize, fps, fade]);

  return <canvas ref={ref} aria-hidden className={className} style={style} />;
}
