import type { Plugin } from 'vite';
import {
  arsenal,
  blogPosts,
  certifications,
  contact,
  learning,
  profile,
  projects,
  skillDomains,
  socials,
  timeline,
  ui,
} from '../src/data/content.ts';
import { tx, type Text } from '../src/i18n/text.ts';

/** Crawlers get the English copy — the language the page is declared in. */
const en = (text: Text) => tx(text, 'en');

const escape = (s: string) =>
  s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

/** Collapse whitespace and drop the `**emphasis**` markers. */
const prose = (s: string) => escape(s.replace(/\*\*(.+?)\*\*/g, '$1').replace(/\s+/g, ' ').trim());

const list = (items: readonly string[]) => `<ul>${items.map(i => `<li>${escape(i)}</li>`).join('')}</ul>`;

function fallback() {
  const entries = (kind: 'experience' | 'education') =>
    timeline
      .filter(e => e.kind === kind)
      .map(
        e => `<li>
        <h3>${escape(en(e.title))}</h3>
        <p>${escape(e.org)} · ${escape(en(e.location))} · ${escape(en(e.period))}</p>
        ${e.description ? `<p>${prose(en(e.description))}</p>` : ''}
        ${e.highlights ? list(e.highlights.en) : ''}
      </li>`
      )
      .join('');

  const work = projects
    .map(
      p => `<li>
        <h3>${escape(en(p.title))}</h3>
        <p>${prose(en(p.blurb))}</p>
        ${p.details.en.map(d => `<p>${prose(d)}</p>`).join('')}
        <p>Built with ${escape(p.tech.join(', '))}.</p>
        ${p.url ? `<p><a href="${escape(p.url)}">${escape(p.url)}</a></p>` : ''}
      </li>`
    )
    .join('');

  const domains = skillDomains
    .map(d => `<li><h3>${escape(en(d.title))} — ${d.level}%</h3>${list(d.tags)}</li>`)
    .join('');

  const certs = certifications
    .map(
      c => `<li>
        <h3>${escape(en(c.title))}</h3>
        <p>${escape(en(c.issuer))} · ${escape(en(c.detail))}${c.progress !== undefined ? ` · in progress (${c.progress}%)` : ''}</p>
        ${c.url ? `<p><a href="${escape(c.url)}">${escape(c.url)}</a></p>` : ''}
      </li>`
    )
    .join('');

  const posts = blogPosts
    .map(
      b => `<li>
        <h3><a href="${escape(b.url)}">${escape(en(b.title))}</a></h3>
        <p>${escape(b.date)} · ${prose(en(b.excerpt))}</p>
      </li>`
    )
    .join('');

  const links = [
    `<li><a href="mailto:${escape(profile.email)}">${escape(profile.email)}</a></li>`,
    `<li><a href="${escape(profile.cv)}">CV (PDF)</a></li>`,
    ...socials
      .filter(s => s.icon !== 'email')
      .map(s => `<li><a href="${escape(s.href)}">${escape(s.label)}</a></li>`),
  ].join('');

  // Scoped to the block and shipped with it, so it leaves with it. Tailwind's
  // preflight resets headings and lists to body text, which left the no-JS
  // view as one undifferentiated wall.
  const style = `<style>
    #seo-fallback { max-width: 48rem; margin: 0 auto; padding: clamp(2rem, 7vw, 4rem) clamp(1rem, 5vw, 1.5rem); line-height: 1.65; }
    #seo-fallback h1 { font-size: clamp(1.4rem, 5.5vw, 1.75rem); font-weight: 700; }
    #seo-fallback h2 { margin-top: clamp(2rem, 7vw, 3rem); font-size: clamp(1.15rem, 4vw, 1.35rem); font-weight: 600; }
    #seo-fallback h3 { margin-top: 1.75rem; font-size: 1.05rem; font-weight: 600; }
    #seo-fallback p { margin: 0.6rem 0; color: #a9b6c3; }
    #seo-fallback ul { margin: 0.6rem 0; padding-left: 1.25rem; list-style: disc; color: #a9b6c3; }
    /* The project and timeline entries are cards, not bullets — on a phone the
       marker plus its indent costs real width and buys nothing. */
    #seo-fallback > ul { padding-left: 0; }
    #seo-fallback > ul > li { margin-bottom: 1.5rem; list-style: none; }
    #seo-fallback a { color: #00f59b; overflow-wrap: anywhere; }
  </style>`;

  return `<div id="seo-fallback">${style}
    <h1>${escape(profile.fullName)} — ${escape(en(profile.role))}</h1>
    <p>${prose(profile.tagline.en)}</p>
    <p>${escape(en(profile.role))} · ${escape(profile.location.en)}</p>

    <h2>${escape(ui.about.title.en)}</h2>
    ${profile.bio.en.map(p => `<p>${prose(p)}</p>`).join('')}
    <h2>${escape(ui.about.experience.en)}</h2>
    <ul>${entries('experience')}</ul>
    <h2>${escape(ui.about.education.en)}</h2>
    <ul>${entries('education')}</ul>

    <h2>${escape(ui.projects.title.en)}</h2>
    <ul>${work}</ul>

    <h2>${escape(ui.skills.title.en)}</h2>
    ${list(arsenal)}
    <ul>${domains}</ul>
    <h3>${escape(learning.title.en)}</h3>
    <p>${prose(learning.text.en)}</p>
    ${list(learning.topics.en)}

    <h2>${escape(ui.certs.title.en)}</h2>
    <ul>${certs}</ul>

    <h2>${escape(ui.blog.title.en)}</h2>
    <ul>${posts}</ul>

    <h2>${escape(ui.contact.title.en)}</h2>
    <p>${prose(contact.intro.en)}</p>
    <ul>${links}</ul>
  </div>`;
}

/**
 * Writes the page's copy into #root as static HTML at build time.
 *
 * The site is a client-rendered SPA, so the document a crawler downloads would
 * otherwise hold only the boot overlay's few words. Googlebot does execute JS,
 * but rendering is a second queued pass that can trail the crawl by weeks.
 *
 * `createRoot().render()` clears its container, so React throws this away the
 * moment it mounts; it is drawn from the same content.ts the components
 * render, so the two can't drift. Nothing is hidden from anyone: the preloader
 * covers it for its first second, and with JS off the <noscript> rule in
 * index.html drops the preloader and leaves this as a plain, readable page.
 *
 * Build only — in dev the empty #root keeps HMR honest.
 */
export default function seoFallback(): Plugin {
  return {
    name: 'seo-fallback',
    apply: 'build',
    transformIndexHtml: {
      order: 'post',
      handler: html => html.replace('<div id="root"></div>', `<div id="root">${fallback()}</div>`),
    },
  };
}
