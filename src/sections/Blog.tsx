import AnimatedContent from '@/components/AnimatedContent';
import GradientHeading from '@/components/layout/GradientHeading';
import posts from 'virtual:blog-posts';
import type { PostMeta } from '@/data/blog';
import { blogUrl, ui } from '@/data/content';
import useLang from '@/i18n/useLang';
import { asset } from '@/lib/asset';

/** Five fill the grid exactly; anything older is one click away on /blog/. */
const SHOWN = 5;

/**
 * The latest write-ups. The posts are Markdown in content/posts/, built into
 * static pages under /blog/ (vite/blog/) — this is just the shop window.
 *
 * Five posts in three columns would strand two on the last row, so the newest
 * spans two columns from lg and lies on its side: 2 + 1, then 3.
 */
export default function Blog() {
  const { t } = useLang();

  return (
    <section id="blog" className="relative px-6 py-24 sm:py-32 lg:pl-52 xl:pl-72">
      <div className="mx-auto max-w-6xl">
        <GradientHeading eyebrow="cat ~/blog/*.md" lede={t(ui.blog.lede)}>
          {t(ui.blog.title)}
        </GradientHeading>

        <ul className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
          {posts.slice(0, SHOWN).map((post, i) => (
            <li key={post.url} className={`h-full ${i === 0 ? 'sm:col-span-2' : ''}`}>
              <AnimatedContent distance={40} duration={0.8} delay={(i % 3) * 0.08} threshold={0.1} className="h-full">
                <PostCard post={post} featured={i === 0} />
              </AnimatedContent>
            </li>
          ))}
        </ul>

        <div className="mt-10 flex justify-center">
          <a
            href={asset(blogUrl)}
            className="group inline-flex items-center gap-2 rounded-full border border-white/[0.12] px-5 py-2.5 font-mono text-xs tracking-[0.12em] text-mist-300 uppercase transition-colors duration-300 hover:border-signal-glow/50 hover:text-signal-glow"
          >
            {t(ui.blog.all)}
            <Arrow />
          </a>
        </div>
      </div>
    </section>
  );
}

function PostCard({ post, featured }: { post: PostMeta; featured: boolean }) {
  const { t, lang } = useLang();
  const title = lang === 'fr' && post.titleFr ? post.titleFr : post.title;
  const summary = lang === 'fr' && post.summaryFr ? post.summaryFr : post.summary;
  const date = new Intl.DateTimeFormat(lang === 'fr' ? 'fr-FR' : 'en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    timeZone: 'UTC',
  }).format(new Date(post.date));

  return (
    <a
      href={asset(post.url)}
      className={`group relative flex h-full flex-col overflow-hidden rounded-2xl border border-white/[0.08] bg-ink-900/70 backdrop-blur-sm transition-[border-color,transform] duration-300 hover:-translate-y-1 hover:border-signal-glow/35 ${
        featured ? 'sm:flex-row' : ''
      }`}
    >
      <div
        className={`relative aspect-[1.9] shrink-0 overflow-hidden bg-ink-800 ${
          featured ? 'sm:aspect-auto sm:w-1/2 sm:min-h-64' : ''
        }`}
      >
        <img
          src={post.image ? asset(post.image) : undefined}
          alt=""
          loading="lazy"
          decoding="async"
          className="absolute inset-0 h-full w-full object-cover transition-transform duration-500 group-hover:scale-[1.04]"
        />
        {/* Sinks the thumbnail's lower edge into the card. */}
        <div aria-hidden className="absolute inset-0 bg-gradient-to-t from-ink-900/70 via-transparent to-transparent" />
      </div>

      <div className="flex flex-1 flex-col p-6">
        <time dateTime={post.date} className="font-mono text-[11px] tracking-[0.08em] text-signal-glow/85 uppercase">
          {date}
        </time>
        <h3
          className={`mt-2 font-display leading-snug font-semibold text-white transition-colors duration-300 group-hover:text-signal-glow ${
            featured ? 'text-xl sm:text-2xl' : 'text-lg'
          }`}
        >
          {title}
        </h3>
        <p className="mt-3 text-sm leading-relaxed text-mist-300/80">{summary}</p>

        <ul className="mt-4 flex flex-wrap gap-1.5" aria-label="Tags">
          {post.tags.map(tag => (
            <li
              key={tag}
              className="rounded-full border border-white/[0.08] bg-white/[0.03] px-2.5 py-0.5 font-mono text-[10px] tracking-[0.06em] text-mist-500"
            >
              {tag}
            </li>
          ))}
        </ul>

        <span className="mt-auto inline-flex items-center gap-1.5 pt-5 font-mono text-[11px] font-medium tracking-[0.12em] text-mist-300 uppercase transition-colors duration-300 group-hover:text-signal-glow">
          {t(ui.blog.read)}
          <Arrow />
        </span>
      </div>
    </a>
  );
}

function Arrow() {
  return (
    <svg
      aria-hidden
      viewBox="0 0 24 24"
      className="h-3.5 w-3.5 transition-transform duration-300 group-hover:translate-x-0.5 group-hover:-translate-y-0.5"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M7 17 17 7M9 7h8v8" />
    </svg>
  );
}
