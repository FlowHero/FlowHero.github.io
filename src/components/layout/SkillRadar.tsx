import { useEffect, useLayoutEffect, useRef } from 'react';

export type RadarAxis = { label: string; value: number; color: string };

type Props = {
  axes: RadarAxis[];
  /** Index of the axis to trace, or null for the resting chart. */
  active: number | null;
  className?: string;
};

const reduceMotion = () =>
  typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

/** `#rrggbb` + alpha → `rgba()`. Canvas has no color-mix. */
function alpha(hex: string, a: number) {
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${a})`;
}

/**
 * The skills radar, carried over from the previous version of the site and
 * redrawn in the new palette. Canvas rather than SVG because the traced axis
 * pulses every frame while highlighted.
 *
 * It grows in once when it first scrolls into view; a highlighted axis gets a
 * dashed arm, a pulsing ring and its value. Decorative: the same numbers are
 * in the domain cards as text, so the canvas is hidden from assistive tech.
 */
export default function SkillRadar({ axes, active, className = '' }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  // Mutable draw state lives in refs: the pulse loop reads it every frame and
  // must not restart (or close over stale values) on each render.
  const state = useRef({ progress: 0, size: 0, pulse: 0, started: false });
  const axesRef = useRef(axes);
  const activeRef = useRef(active);
  const drawRef = useRef<() => void>(() => {});

  // Layout effects run before the passive ones below, so the redraw effect
  // always sees this render's values.
  useLayoutEffect(() => {
    axesRef.current = axes;
    activeRef.current = active;
  });

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    const s = state.current;

    const setup = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      s.size = canvas.clientWidth;
      if (!s.size) return;
      canvas.width = s.size * dpr;
      canvas.height = s.size * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };

    const point = (i: number, r: number, n: number) => {
      const a = (i / n) * Math.PI * 2 - Math.PI / 2;
      const c = s.size / 2;
      const R = s.size * 0.3;
      return { x: c + r * R * Math.cos(a), y: c + r * R * Math.sin(a), a };
    };

    const draw = () => {
      const sz = s.size;
      if (!sz) return;
      const data = axesRef.current;
      const hi = activeRef.current;
      const n = data.length;
      const c = sz / 2;
      const R = sz * 0.3;
      const prog = s.progress;
      ctx.clearRect(0, 0, sz, sz);

      // Grid rings
      [0.2, 0.4, 0.6, 0.8, 1].forEach((t, idx) => {
        ctx.beginPath();
        for (let i = 0; i < n; i++) {
          const p = point(i, t, n);
          if (i === 0) ctx.moveTo(p.x, p.y);
          else ctx.lineTo(p.x, p.y);
        }
        ctx.closePath();
        ctx.strokeStyle = idx === 4 ? 'rgba(255,255,255,0.12)' : 'rgba(255,255,255,0.05)';
        ctx.lineWidth = 0.8;
        ctx.stroke();
      });

      // Axes
      for (let i = 0; i < n; i++) {
        const p = point(i, 1, n);
        ctx.beginPath();
        ctx.moveTo(c, c);
        ctx.lineTo(p.x, p.y);
        ctx.strokeStyle = i === hi ? alpha(data[i].color, 0.45) : 'rgba(255,255,255,0.07)';
        ctx.lineWidth = i === hi ? 1.5 : 0.8;
        ctx.stroke();
      }

      // Filled shape — dimmed while one axis is traced
      ctx.beginPath();
      for (let i = 0; i < n; i++) {
        const p = point(i, (data[i].value / 100) * prog, n);
        if (i === 0) ctx.moveTo(p.x, p.y);
        else ctx.lineTo(p.x, p.y);
      }
      ctx.closePath();
      const fillA = hi !== null ? 0.12 : 0.26;
      const g = ctx.createRadialGradient(c, c, 0, c, c, R);
      g.addColorStop(0, `rgba(0,245,155,${fillA})`);
      g.addColorStop(0.65, `rgba(34,211,238,${fillA * 0.55})`);
      g.addColorStop(1, 'rgba(34,211,238,0.03)');
      ctx.fillStyle = g;
      ctx.fill();
      ctx.strokeStyle = hi !== null ? 'rgba(0,245,155,0.35)' : 'rgba(0,245,155,0.85)';
      ctx.lineWidth = 1.5;
      ctx.shadowColor = '#00f59b';
      ctx.shadowBlur = hi !== null ? 4 : 10;
      ctx.stroke();
      ctx.shadowBlur = 0;

      // Vertices
      for (let i = 0; i < n; i++) {
        const p = point(i, (data[i].value / 100) * prog, n);
        const on = i === hi;
        ctx.beginPath();
        ctx.arc(p.x, p.y, on ? sz * 0.022 : sz * 0.013, 0, Math.PI * 2);
        ctx.fillStyle = hi !== null && !on ? alpha(data[i].color, 0.35) : data[i].color;
        ctx.shadowColor = data[i].color;
        ctx.shadowBlur = on ? 16 : hi !== null ? 3 : 9;
        ctx.fill();
        ctx.shadowBlur = 0;
      }

      // Traced axis: dashed arm, pulse ring, value
      if (hi !== null && data[hi]) {
        const d = data[hi];
        const hp = point(hi, (d.value / 100) * prog, n);
        ctx.beginPath();
        ctx.moveTo(c, c);
        ctx.lineTo(hp.x, hp.y);
        ctx.strokeStyle = d.color;
        ctx.lineWidth = 1.5;
        ctx.shadowColor = d.color;
        ctx.shadowBlur = 12;
        ctx.setLineDash([4, 3]);
        ctx.stroke();
        ctx.setLineDash([]);
        ctx.shadowBlur = 0;

        const pulse = 0.5 + 0.5 * Math.sin(s.pulse * 3);
        ctx.beginPath();
        ctx.arc(hp.x, hp.y, sz * 0.03 + pulse * sz * 0.018, 0, Math.PI * 2);
        ctx.strokeStyle = d.color;
        ctx.globalAlpha = 0.32 * (1 - pulse * 0.6);
        ctx.lineWidth = 1.5;
        ctx.stroke();
        ctx.globalAlpha = 1;

        const a = hp.a;
        ctx.font = `700 ${sz * 0.042}px 'JetBrains Mono', monospace`;
        ctx.fillStyle = '#fff';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.shadowColor = d.color;
        ctx.shadowBlur = 8;
        ctx.fillText(`${d.value}%`, hp.x + Math.cos(a) * sz * 0.075, hp.y + Math.sin(a) * sz * 0.075);
        ctx.shadowBlur = 0;
      }

      // Labels
      for (let i = 0; i < n; i++) {
        const a = (i / n) * Math.PI * 2 - Math.PI / 2;
        const lx = c + R * 1.24 * Math.cos(a);
        const ly = c + R * 1.24 * Math.sin(a);
        const on = i === hi;
        ctx.textAlign = Math.abs(Math.cos(a)) < 0.15 ? 'center' : Math.cos(a) > 0 ? 'left' : 'right';
        ctx.textBaseline = Math.sin(a) < -0.6 ? 'bottom' : Math.sin(a) > 0.6 ? 'top' : 'middle';
        ctx.font = `${on ? 700 : 500} ${on ? sz * 0.034 : sz * 0.03}px 'JetBrains Mono', monospace`;
        ctx.fillStyle = on ? '#fff' : hi !== null ? alpha(data[i].color, 0.4) : data[i].color;
        if (on) {
          ctx.shadowColor = data[i].color;
          ctx.shadowBlur = 10;
        }
        ctx.fillText(data[i].label, lx, ly);
        ctx.shadowBlur = 0;
      }
    };
    drawRef.current = draw;

    let raf = 0;
    const grow = () => {
      s.progress = Math.min(s.progress + 0.022, 1);
      draw();
      if (s.progress < 1) raf = requestAnimationFrame(grow);
    };

    const io = new IntersectionObserver(
      ([entry]) => {
        if (!entry.isIntersecting || s.started) return;
        s.started = true;
        setup();
        if (reduceMotion()) {
          s.progress = 1;
          draw();
        } else {
          grow();
        }
        io.disconnect();
      },
      { threshold: 0.3 }
    );
    io.observe(canvas);

    // The canvas is sized by its column, which changes with the breakpoint
    // as well as with the window.
    const ro = new ResizeObserver(() => {
      if (!s.started) return;
      setup();
      draw();
    });
    ro.observe(canvas);

    // Labels are drawn in JetBrains Mono; if it lands after the first frame,
    // redraw so they don't stay in the fallback face.
    document.fonts?.ready.then(() => s.started && draw());

    return () => {
      io.disconnect();
      ro.disconnect();
      cancelAnimationFrame(raf);
    };
  }, []);

  // Redraw on a label change (language switch) or a new highlight; while an
  // axis is traced, run the pulse loop.
  useEffect(() => {
    const s = state.current;
    if (!s.started) return;
    if (active === null || reduceMotion()) {
      drawRef.current();
      return;
    }
    let raf = 0;
    const loop = () => {
      s.pulse += 0.03;
      drawRef.current();
      raf = requestAnimationFrame(loop);
    };
    loop();
    return () => cancelAnimationFrame(raf);
  }, [active, axes]);

  return <canvas ref={canvasRef} aria-hidden className={`block aspect-square w-full ${className}`} />;
}
