import Rich from '@/components/layout/Rich';
import { interests, profile, stats, ui } from '@/data/content';
import useLang from '@/i18n/useLang';

/**
 * Static counterpart to the ProfileCard — no tilt, no WebGL. Glass, the bio,
 * the two headline numbers, and what drives the work.
 */
export default function AboutCard() {
  const { t } = useLang();

  return (
    // h-full from xl, where it shares a row with the profile card: if the card
    // is the taller of the two, this stretches to match and the chips ride
    // down to the bottom edge (mt-auto) rather than leaving a gap under them.
    <div className="group flex flex-col rounded-2xl border border-white/10 bg-white/[0.04] p-7 shadow-[0_8px_32px_rgba(0,0,0,0.37)] backdrop-blur-lg transition-all duration-500 hover:border-signal-glow/25 hover:bg-white/[0.06] sm:p-8 xl:h-full">
      <div className="flex flex-1 flex-col gap-6">
        <h3 className="font-display text-2xl font-bold text-white">
          {t(ui.about.hello)}{' '}
          <span className="transition-colors duration-300 group-hover:text-signal-glow">{profile.name}</span>
          <span aria-hidden className="ml-1 inline-block animate-caret text-signal-glow">
            _
          </span>
        </h3>

        <div className="space-y-4">
          {t(profile.bio).map(paragraph => (
            <p key={paragraph} className="leading-relaxed text-mist-300">
              <Rich text={paragraph} />
            </p>
          ))}
        </div>

        {/* The headline number and the spoken languages share one row. Each
            group is dt-then-dd as the spec requires; flex-col-reverse puts
            the value visually on top. */}
        <dl className="grid gap-5 border-y border-white/[0.06] py-6 sm:grid-cols-[auto_1fr] sm:items-center sm:gap-0">
          {stats.map(s => (
            <div key={s.value} className="flex flex-col-reverse text-center sm:pr-8 sm:text-left">
              <dt className="text-sm text-mist-500">{t(s.label)}</dt>
              <dd className="mb-1 font-display text-3xl font-bold text-signal-glow tabular-nums">{s.value}</dd>
            </div>
          ))}
          <div className="text-center sm:border-l sm:border-white/[0.08] sm:pl-8 sm:text-left">
            <dt className="mb-1.5 font-mono text-[11px] tracking-[0.12em] text-cyan-glow/80 uppercase">
              {t(ui.about.languages)}
            </dt>
            <dd className="text-sm leading-relaxed text-mist-300">{t(profile.spokenLanguages)}</dd>
          </div>
        </dl>

        <div className="mt-auto">
          <h4 className="mb-3 font-display text-lg font-semibold text-white">{t(ui.about.drives)}</h4>
          <ul className="flex flex-wrap gap-2">
            {t(interests).map(tag => (
              <li
                key={tag}
                className="rounded-full border border-signal-glow/25 bg-signal-glow/[0.08] px-3 py-1 text-sm text-signal-glow/90 transition-colors duration-300 hover:bg-signal-glow/15"
              >
                {tag}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}
