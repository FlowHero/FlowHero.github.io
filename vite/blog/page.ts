/**
 * HTML for the blog's static pages. They link the portfolio's own stylesheet
 * (Tailwind classes here are picked up through the `@source` in index.css),
 * so a post looks like the rest of the site without shipping any React.
 */
import { SITE_URL, type PostMeta, type RenderedPost } from './posts.ts';

const esc = (s: string) =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

/** JSON inside <script>: keep a `</script>` in the data from closing the tag. */
const jsonLd = (data: unknown) => JSON.stringify(data).replace(/</g, '\\u003c');

/** `day` is YYYY-MM-DD; read as UTC midnight so no timezone can shift it. */
const formatDate = (day: string) =>
  new Intl.DateTimeFormat('en-US', { year: 'numeric', month: 'short', day: 'numeric', timeZone: 'UTC' }).format(new Date(day));

const abs = (p: string) => (p.startsWith('http') ? p : SITE_URL + p);

type Shell = {
  title: string;
  description: string;
  canonical: string;
  image?: string;
  cssHref: string;
  ogType: 'article' | 'website';
  head?: string;
  body: string;
};

function shell({ title, description, canonical, image, cssHref, ogType, head = '', body }: Shell) {
  const ogImage = abs(image ?? '/og-image.png');
  return `<!doctype html>
<html lang="en" class="dark">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="color-scheme" content="dark" />
    <meta name="theme-color" content="#04070a" />
    <title>${esc(title)}</title>
    <meta name="description" content="${esc(description)}" />
    <meta name="author" content="ABAD Ayoub" />
    <link rel="canonical" href="${esc(canonical)}" />
    <meta property="og:type" content="${ogType}" />
    <meta property="og:url" content="${esc(canonical)}" />
    <meta property="og:site_name" content="ABAD Ayoub" />
    <meta property="og:title" content="${esc(title)}" />
    <meta property="og:description" content="${esc(description)}" />
    <meta property="og:image" content="${esc(ogImage)}" />
    <meta name="twitter:card" content="summary_large_image" />
    <meta name="twitter:image" content="${esc(ogImage)}" />
    <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32.png" />
    <link rel="apple-touch-icon" href="/apple-touch-icon.png" />
    <link rel="alternate" type="application/rss+xml" title="ABAD Ayoub — Blog" href="/blog/index.xml" />
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link
      href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;700&family=Space+Grotesk:wght@500;600;700&display=swap"
      rel="stylesheet"
    />
    <link rel="stylesheet" href="${esc(cssHref)}" />${head}
  </head>
  <body class="min-h-screen">
    <header class="sticky top-0 z-40 border-b border-white/[0.06] bg-ink-950/80 px-5 backdrop-blur-md sm:px-8">
      <nav class="mx-auto flex max-w-6xl items-center justify-between gap-4 py-3.5" aria-label="Site">
        <div class="flex items-center gap-2.5 font-mono text-[13px]">
          <a href="/" class="flex items-center gap-2.5 text-signal-glow transition-colors hover:text-white">
            <img src="/mark.svg" alt="" width="22" height="22" class="h-[22px] w-[22px]" />
            ayoub@flowhero</a
          ><span class="-ml-2.5 text-mist-500">:~/</span
          ><a href="/blog/" class="text-mist-300 transition-colors hover:text-signal-glow">blog</a>
        </div>
        <div class="flex items-center gap-5 font-mono text-[11px] tracking-[0.14em] uppercase">
          <a href="/blog/" class="text-mist-300 transition-colors hover:text-signal-glow">All posts</a>
          <a href="/" class="text-mist-300 transition-colors hover:text-signal-glow">Portfolio</a>
        </div>
      </nav>
    </header>
${body}
    <footer class="border-t border-white/[0.06] px-5 py-10 text-center font-mono text-[11px] tracking-[0.12em] text-mist-500 uppercase sm:px-8">
      <a href="/" class="transition-colors hover:text-signal-glow">ABAD Ayoub</a> · Cybersecurity Engineer ·
      <a href="/blog/index.xml" class="transition-colors hover:text-signal-glow">RSS</a>
    </footer>
  </body>
</html>
`;
}

function tagList(tags: string[]) {
  if (!tags.length) return '';
  return `<ul class="flex flex-wrap gap-1.5" aria-label="Tags">${tags
    .map(
      t =>
        `<li class="rounded-full border border-white/[0.08] bg-white/[0.03] px-2.5 py-0.5 font-mono text-[10px] tracking-[0.06em] text-mist-500">${esc(t)}</li>`
    )
    .join('')}</ul>`;
}

/** Copy buttons on code blocks. Tiny and inline: the page has no other JS. */
const COPY_SCRIPT = `<script>
document.addEventListener('click', function (e) {
  var btn = e.target.closest && e.target.closest('[data-copy]');
  if (!btn) return;
  var code = btn.closest('figure').querySelector('pre');
  if (!code || !navigator.clipboard) return;
  navigator.clipboard.writeText(code.innerText).then(function () {
    btn.textContent = 'Copied';
    btn.classList.add('is-done');
    setTimeout(function () { btn.textContent = 'Copy'; btn.classList.remove('is-done'); }, 1400);
  });
});
</script>`;

export function postPage(post: RenderedPost, prev: PostMeta | undefined, next: PostMeta | undefined, cssHref: string) {
  const canonical = SITE_URL + post.url;

  const toc = post.toc.length
    ? `<nav class="post-toc" aria-label="On this page">
          <p class="mb-3 font-mono text-[10px] tracking-[0.16em] text-mist-500 uppercase">On this page</p>
          <ol>${post.toc
            .map(h => `<li class="${h.level === 3 ? 'is-sub' : ''}"><a href="#${h.id}">${esc(h.text)}</a></li>`)
            .join('')}</ol>
        </nav>`
    : '';

  const neighbour = (p: PostMeta | undefined, label: string, align: string) =>
    p
      ? `<a href="${p.url}" class="group flex flex-col gap-1.5 rounded-2xl border border-white/[0.08] bg-ink-900/70 p-5 transition-colors hover:border-signal-glow/35 ${align}">
          <span class="font-mono text-[10px] tracking-[0.16em] text-mist-500 uppercase">${label}</span>
          <span class="font-display text-base font-semibold text-white transition-colors group-hover:text-signal-glow">${esc(p.title)}</span>
        </a>`
      : '<span></span>';

  const structured = {
    '@context': 'https://schema.org',
    '@type': 'BlogPosting',
    headline: post.title,
    description: post.description,
    datePublished: post.datetime,
    url: canonical,
    mainEntityOfPage: canonical,
    image: post.image ? abs(post.image) : undefined,
    keywords: post.tags.join(', '),
    author: { '@type': 'Person', name: 'Ayoub Abad', url: SITE_URL + '/' },
  };

  const body = `
    <main class="px-5 pt-12 pb-20 sm:px-8 sm:pt-16">
      <div class="mx-auto max-w-6xl">
        <a href="/blog/" class="inline-flex items-center gap-2 font-mono text-[11px] tracking-[0.14em] text-mist-500 uppercase transition-colors hover:text-signal-glow">
          <span aria-hidden="true">←</span> All posts
        </a>

        <header class="mt-8 max-w-3xl">
          <p class="font-mono text-[11px] tracking-[0.08em] text-signal-glow/85 uppercase">
            <time datetime="${post.datetime}">${formatDate(post.date)}</time>
            <span class="text-mist-500"> · ${post.readingMinutes} min read</span>
          </p>
          <h1 class="mt-3 font-display text-3xl leading-tight font-bold text-white sm:text-5xl">${esc(post.title)}</h1>
          ${post.description ? `<p class="mt-4 text-lg leading-relaxed text-mist-300">${esc(post.description)}</p>` : ''}
          <div class="mt-5">${tagList(post.tags)}</div>
        </header>

        ${
          post.image
            ? `<div class="mt-10 aspect-[1.9] max-w-3xl overflow-hidden rounded-2xl border border-white/[0.08] bg-ink-800">
          <img src="${esc(post.image)}" alt="" class="h-full w-full object-cover" />
        </div>`
            : ''
        }

        <div class="mt-12 grid gap-12 xl:grid-cols-[minmax(0,48rem)_14rem] xl:justify-between">
          <article class="post-body min-w-0">
${post.html}
          </article>
          <aside class="hidden xl:block">
            <div class="sticky top-24 max-h-[calc(100vh-8rem)] overflow-y-auto pr-1">${toc}</div>
          </aside>
        </div>

        <nav class="mt-16 grid max-w-3xl gap-4 sm:grid-cols-2" aria-label="More posts">
          ${neighbour(next, '← Newer', '')}
          ${neighbour(prev, 'Older →', 'sm:text-right')}
        </nav>
      </div>
    </main>`;

  return shell({
    title: `${post.title} — ABAD Ayoub`,
    description: post.description || post.summary,
    canonical,
    image: post.image,
    cssHref,
    ogType: 'article',
    head: `\n    <script type="application/ld+json">${jsonLd(structured)}</script>\n    ${COPY_SCRIPT}`,
    body,
  });
}

export function indexPage(posts: PostMeta[], cssHref: string) {
  const cards = posts
    .map(
      p => `<li>
          <a href="${p.url}" class="group flex h-full flex-col overflow-hidden rounded-2xl border border-white/[0.08] bg-ink-900/70 transition-[border-color,transform] duration-300 hover:-translate-y-1 hover:border-signal-glow/35 sm:flex-row">
            ${
              p.image
                ? `<div class="relative aspect-[1.9] shrink-0 overflow-hidden bg-ink-800 sm:aspect-auto sm:w-72"><img src="${esc(p.image)}" alt="" loading="lazy" decoding="async" class="absolute inset-0 h-full w-full object-cover transition-transform duration-500 group-hover:scale-[1.04]" /></div>`
                : ''
            }
            <div class="flex flex-1 flex-col p-6">
              <p class="font-mono text-[11px] tracking-[0.08em] text-signal-glow/85 uppercase"><time datetime="${p.datetime}">${formatDate(p.date)}</time><span class="text-mist-500"> · ${p.readingMinutes} min read</span></p>
              <h2 class="mt-2 font-display text-xl leading-snug font-semibold text-white transition-colors group-hover:text-signal-glow">${esc(p.title)}</h2>
              <p class="mt-3 text-sm leading-relaxed text-mist-300/80">${esc(p.summary)}</p>
              <div class="mt-4">${tagList(p.tags)}</div>
            </div>
          </a>
        </li>`
    )
    .join('\n        ');

  const body = `
    <main class="px-5 pt-14 pb-20 sm:px-8 sm:pt-20">
      <div class="mx-auto max-w-4xl">
        <p class="font-mono text-[11px] tracking-[0.2em] text-signal-glow uppercase">$ ls ~/blog</p>
        <h1 class="mt-3 font-display text-4xl font-bold text-signal-gradient sm:text-5xl">Blog</h1>
        <p class="mt-4 max-w-2xl text-lg leading-relaxed text-mist-300">Write-ups and cheat sheets from my notes: web and API attacks, evasion, and cloud security.</p>
        <ul class="mt-12 grid gap-5">
        ${cards}
        </ul>
      </div>
    </main>`;

  return shell({
    title: 'Blog — ABAD Ayoub',
    description: 'Security write-ups and cheat sheets by ABAD Ayoub: web and API attacks, WAF evasion, JWTs, GraphQL and Kubernetes security.',
    canonical: `${SITE_URL}/blog/`,
    cssHref,
    ogType: 'website',
    body,
  });
}

export function rssFeed(posts: PostMeta[]) {
  const items = posts
    .map(
      p => `    <item>
      <title>${esc(p.title)}</title>
      <link>${SITE_URL}${p.url}</link>
      <guid>${SITE_URL}${p.url}</guid>
      <pubDate>${new Date(p.datetime).toUTCString()}</pubDate>
      <description>${esc(p.description || p.summary)}</description>
    </item>`
    )
    .join('\n');
  return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>ABAD Ayoub — Blog</title>
    <link>${SITE_URL}/blog/</link>
    <description>Security write-ups and cheat sheets.</description>
    <language>en</language>
${items}
  </channel>
</rss>
`;
}

export function sitemap(posts: PostMeta[]) {
  const urls = [
    { loc: `${SITE_URL}/` },
    { loc: `${SITE_URL}/blog/`, lastmod: posts[0]?.date },
    ...posts.map(p => ({ loc: SITE_URL + p.url, lastmod: p.date })),
  ];
  return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.map(u => `  <url>\n    <loc>${u.loc}</loc>${u.lastmod ? `\n    <lastmod>${u.lastmod}</lastmod>` : ''}\n  </url>`).join('\n')}
</urlset>
`;
}
