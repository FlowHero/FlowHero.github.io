/**
 * The blog: Markdown files in content/posts/, rendered to static HTML at
 * build time. No Markdown or highlighter ships to the browser — a post page
 * is plain HTML plus the site's stylesheet.
 *
 * Each file is `<slug>.md` with TOML front matter (the format the posts had
 * on Hugo, so they moved over unchanged):
 *
 *   +++
 *   title = "Fuzzing APIs"
 *   date = 2023-08-22T00:40:26+01:00
 *   description = "Meta description / search snippet."
 *   image = "/assets/images/apifuzzing.png"   # card + social preview
 *   tags = ["API", "Fuzzing"]
 *   summary = "Card text (optional, falls back to description)."
 *   title_fr = "…"     # optional French card copy
 *   summary_fr = "…"
 *   draft = false      # true keeps it out of the build
 *   +++
 */
import fs from 'node:fs';
import path from 'node:path';
import MarkdownIt from 'markdown-it';
import { parse as parseToml } from 'smol-toml';
import { createHighlighter, type Highlighter } from 'shiki';
import type { PostMeta } from '../../src/data/blog.ts';

export const POSTS_DIR = 'content/posts';
export const SITE_URL = 'https://flowhero.github.io';

export type { PostMeta };

export type Post = PostMeta & { body: string };

export type Heading = { level: 2 | 3; id: string; text: string };
export type RenderedPost = PostMeta & { html: string; toc: Heading[] };

const FRONT_MATTER = /^\+\+\+\r?\n([\s\S]*?)\r?\n\+\+\+\r?\n?/;

const str = (v: unknown) => (typeof v === 'string' ? v : undefined);

/** Reads every non-draft post, newest first. Cheap: no Markdown rendering. */
export function loadPosts(root: string): Post[] {
  const dir = path.join(root, POSTS_DIR);
  if (!fs.existsSync(dir)) return [];

  const posts = fs
    .readdirSync(dir)
    .filter(f => f.endsWith('.md'))
    .map((file): Post | null => {
      const raw = fs.readFileSync(path.join(dir, file), 'utf8');
      const m = raw.match(FRONT_MATTER);
      if (!m) throw new Error(`${POSTS_DIR}/${file}: missing +++ TOML front matter +++`);
      const fm = parseToml(m[1]) as Record<string, unknown>;
      if (fm.draft === true) return null;

      const slug = file.replace(/\.md$/, '');
      const title = str(fm.title);
      if (!title) throw new Error(`${POSTS_DIR}/${file}: front matter needs a title`);
      if (!(fm.date instanceof Date)) throw new Error(`${POSTS_DIR}/${file}: front matter needs a date`);

      const body = raw.slice(m[0].length);
      const description = str(fm.description) ?? '';
      const words = body.replace(/```[\s\S]*?```/g, ' ').split(/\s+/).filter(Boolean).length;

      return {
        slug,
        title,
        titleFr: str(fm.title_fr),
        description,
        summary: str(fm.summary) ?? description,
        summaryFr: str(fm.summary_fr),
        // The calendar date as written, in the author's own timezone —
        // converting to UTC first would move a post published just after
        // midnight (+01:00) back a day.
        date: m[1].match(/^date\s*=\s*(\d{4}-\d{2}-\d{2})/m)?.[1] ?? fm.date.toISOString().slice(0, 10),
        datetime: fm.date.toISOString(),
        image: str(fm.image),
        tags: Array.isArray(fm.tags) ? fm.tags.filter((t): t is string => typeof t === 'string') : [],
        url: `/blog/${slug}/`,
        readingMinutes: Math.max(1, Math.round(words / 220)),
        body,
      };
    })
    .filter((p): p is Post => p !== null);

  return posts.sort((a, b) => b.datetime.localeCompare(a.datetime));
}

export const toMeta = ({ body: _body, ...meta }: Post): PostMeta => meta;

/* ------------------------------------------------------------------ */
/*  Rendering                                                          */
/* ------------------------------------------------------------------ */

/** Fence info strings as the posts write them → a Shiki grammar. */
const LANG_ALIASES: Record<string, string> = {
  sh: 'shellscript',
  shell: 'shellscript',
  bash: 'shellscript',
  zsh: 'shellscript',
  js: 'javascript',
  ts: 'typescript',
  yml: 'yaml',
  py: 'python',
  html: 'html',
};
const LANGS = ['shellscript', 'javascript', 'typescript', 'json', 'yaml', 'python', 'xml', 'html', 'java', 'graphql', 'http', 'sql', 'powershell', 'dockerfile', 'go'];

/** Obsidian admonitions (```ad-note) → one of four callout tones. */
const CALLOUT_TONES: Record<string, 'info' | 'success' | 'warning' | 'danger'> = {
  note: 'info', info: 'info', abstract: 'info', summary: 'info', tldr: 'info', todo: 'info', example: 'info', quote: 'info', cite: 'info',
  tip: 'success', hint: 'success', important: 'success', success: 'success', check: 'success', done: 'success',
  question: 'warning', help: 'warning', faq: 'warning', warning: 'warning', caution: 'warning', attention: 'warning',
  failure: 'danger', fail: 'danger', missing: 'danger', danger: 'danger', error: 'danger', bug: 'danger',
};

let highlighter: Promise<Highlighter> | undefined;
const getHighlighter = () =>
  (highlighter ??= createHighlighter({ themes: ['vitesse-dark'], langs: LANGS }));

const escapeHtml = (s: string) =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

export function slugify(text: string): string {
  return (
    text
      .toLowerCase()
      .normalize('NFKD')
      .replace(/[̀-ͯ]/g, '')
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '') || 'section'
  );
}

async function createRenderer() {
  const hl = await getHighlighter();
  const loaded = new Set(hl.getLoadedLanguages());

  // `html: false` on purpose: these are security write-ups, full of XSS and
  // CSRF payloads. Every one of them must show as text, never run.
  const md = new MarkdownIt({ html: false, linkify: true, typographer: false });

  // Headings get stable ids (for the table of contents and deep links); the
  // TOC is collected into the render env as a side effect.
  md.core.ruler.push('heading_ids', state => {
    const env = state.env as { toc?: Heading[]; seen?: Record<string, number> };
    const toc = (env.toc ??= []);
    const seen = (env.seen ??= {});
    state.tokens.forEach((tok, i) => {
      if (tok.type !== 'heading_open') return;
      const text = state.tokens[i + 1].children?.map(c => c.content).join('').trim() ?? '';
      const base = slugify(text);
      const n = (seen[base] = (seen[base] ?? 0) + 1);
      const id = n > 1 ? `${base}-${n}` : base;
      tok.attrSet('id', id);
      const level = Number(tok.tag.slice(1));
      if (level === 2 || level === 3) toc.push({ level, id, text });
    });
  });

  // Images: posts link them by absolute production URL; serve them from this
  // site instead so dev and previews don't depend on production.
  const defaultImage = md.renderer.rules.image!;
  md.renderer.rules.image = (tokens, idx, options, env, self) => {
    const tok = tokens[idx];
    const src = String(tok.attrGet('src') ?? '');
    if (src.startsWith(SITE_URL + '/')) tok.attrSet('src', src.slice(SITE_URL.length));
    tok.attrSet('loading', 'lazy');
    tok.attrSet('decoding', 'async');
    return defaultImage(tokens, idx, options, env, self);
  };

  // External links open in a new tab.
  const defaultLinkOpen =
    md.renderer.rules.link_open ?? ((tokens, idx, options, _env, self) => self.renderToken(tokens, idx, options));
  md.renderer.rules.link_open = (tokens, idx, options, env, self) => {
    const href = String(tokens[idx].attrGet('href') ?? '');
    if (/^https?:\/\//.test(href) && !href.startsWith(SITE_URL)) {
      tokens[idx].attrSet('target', '_blank');
      tokens[idx].attrSet('rel', 'noopener noreferrer');
    }
    return defaultLinkOpen(tokens, idx, options, env, self);
  };

  // Wide tables scroll on their own instead of pushing the page sideways.
  md.renderer.rules.table_open = () => '<div class="post-table"><table>';
  md.renderer.rules.table_close = () => '</table></div>';

  md.renderer.rules.fence = (tokens, idx, _options, env) => {
    const tok = tokens[idx];
    const info = tok.info.trim().split(/\s+/)[0] ?? '';

    if (info.startsWith('ad-')) {
      const kind = info.slice(3).toLowerCase();
      const lines = tok.content.split('\n');
      let title = kind.charAt(0).toUpperCase() + kind.slice(1);
      // Obsidian Admonition options sit on the first lines of the block.
      while (lines.length && /^(title|collapse|icon|color):/.test(lines[0])) {
        const [key, ...rest] = lines.shift()!.split(':');
        if (key === 'title' && rest.join(':').trim()) title = rest.join(':').trim();
      }
      const tone = CALLOUT_TONES[kind] ?? 'info';
      // Same env, so headings inside a callout still get unique ids.
      return `<aside class="post-callout post-callout--${tone}"><p class="post-callout__title">${md.renderInline(title, env)}</p>${md.render(lines.join('\n'), env)}</aside>\n`;
    }

    const lang = LANG_ALIASES[info] ?? info;
    const code = tok.content.replace(/\n$/, '');
    const body = loaded.has(lang)
      ? hl.codeToHtml(code, { lang, theme: 'vitesse-dark' })
      : `<pre class="shiki"><code>${escapeHtml(code)}</code></pre>`;
    const label = info && info !== 'text' ? escapeHtml(info) : 'text';
    return `<figure class="post-code"><figcaption><span>${label}</span><button type="button" class="post-copy" data-copy>Copy</button></figcaption>${body}</figure>\n`;
  };

  return md;
}

let renderer: ReturnType<typeof createRenderer> | undefined;

export async function renderPost(post: Post): Promise<RenderedPost> {
  const md = await (renderer ??= createRenderer());
  const env: { toc?: Heading[] } = {};
  const html = md.render(post.body, env);
  return { ...toMeta(post), html, toc: env.toc ?? [] };
}
