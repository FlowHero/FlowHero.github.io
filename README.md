# FlowHero.github.io

Portfolio of **ABAD Ayoub**, Cybersecurity Engineer. Live at **https://flowhero.github.io**.

A dark, WebGL-accented single page built with **Vite + React 19 + TypeScript + Tailwind v4**
and animated components from [React Bits](https://www.reactbits.dev/), in English and French.

```bash
npm install
npm run dev      # http://localhost:5173
npm run build    # typecheck + production build into dist/
npm run preview  # serve the built site
npm run lint     # oxlint
```

Node 20.19+ (CI uses 24).

## Editing the content

**Every word on the site lives in one file: [`src/data/content.ts`](src/data/content.ts)**,
in both languages. Edit it and the whole site follows: hero, bio, stats, timeline,
projects, skills radar, tool marquee, certifications, contact, and the interface labels
(`ui` at the bottom).

- A field typed `Text` takes a plain string, shown as-is in both languages (names, tools,
  acronyms), or `{ en: '…', fr: '…' }`.
- In the bio and project write-ups, `**like this**` renders as a highlighted phrase.
- Project cards clamp the `blurb` at three lines, so keep it under ~145 characters.
- Each tool in `arsenal` needs an entry in
  [`ToolTile.tsx`](src/components/layout/ToolTile.tsx) (brand mark and colour, or
  `cli: true` for a terminal-style tile). A missing one is a type error.

Outside that file:

| What | Where |
| --- | --- |
| Page title, meta description, JSON-LD, social preview tags | [`index.html`](index.html) |
| Social preview image (1200×630) | [`public/og-image.png`](public/og-image.png) |
| Portrait (transparent cutout, see below) | [`public/subject.webp`](public/subject.webp) |
| CV | [`public/assets/cv/cv.pdf`](public/assets/cv/cv.pdf) |
| Favicon / home-screen icon / menu logo | [`public/favicon.svg`](public/favicon.svg), [`public/apple-touch-icon.png`](public/apple-touch-icon.png), [`public/mark.svg`](public/mark.svg) |

Colours and fonts are design tokens at the top of [`src/index.css`](src/index.css):
`--color-ink-*` (backgrounds), `--color-mist-*` (text), `--color-signal-glow` (the
terminal green), `--color-cyan-glow`, `--color-threat` (offense red).

## Structure

```
src/
├── data/content.ts        ← edit this
├── i18n/                  ← language provider, useLang() hook, text helpers
├── index.css              ← design tokens, keyframes, vendored-component overrides
├── App.tsx                ← section order
├── sections/              ← Hero, About, Work, Skills, Certifications, Contact
├── components/            ← React Bits components (vendored, some modified, see below)
│   └── layout/            ← SideNav, LangToggle, GradientHeading, Timeline, AboutCard,
│                             ProjectDialog, SkillRadar, SkillDomains, ToolTile, …
└── lib/
    ├── asset.ts           ← resolves public/ paths against the deploy base
    └── cover.ts           ← generated cyber cover art for the project cards

vite/seo-fallback.ts       ← writes the English copy into #root at build time
public/404.html            ← standalone "bash: cd: no such file" page
public/assets/             ← the previous site's files, kept at their old URLs
```

The six sections map 1:1 onto the six rail items:

| Rail item | Section id | File |
| --- | --- | --- |
| Home | `#home` | `sections/Hero.tsx` |
| About | `#about` | `sections/About.tsx` (profile card + bio, then separate Work Experience and Education blocks at `#experience` / `#education`, the anchors the old site used) |
| Projects | `#projects` | `sections/Work.tsx` |
| Skills | `#skills` | `sections/Skills.tsx` (tool marquee, radar + domain cards, learning card) |
| Certs | `#certifications` | `sections/Certifications.tsx` |
| Contact | `#contact` | `sections/Contact.tsx` |

To add or reorder items, edit `navLinks` in `content.ts` **and** the matching
`<section id="…">`. The rail resolves sections by that id.

## Languages

`LangProvider` picks the language on first visit from the browser (French if the browser
prefers it, English otherwise), then remembers the visitor's choice in `localStorage`
under `lang`, the same key the previous version of the site used. It keeps `<html lang>`
and the tab title in step. The boot overlay reads the same key so its label is already in
the right language before React loads.

Search engines get the English copy: it is what `index.html` declares and what the
build-time SEO fallback writes.

## Deploying (GitHub Pages)

[`.github/workflows/deploy.yml`](.github/workflows/deploy.yml) builds the site and
publishes `dist/` on every push to `main`.

**One-time setup:** Settings → Pages → Build and deployment → Source: **GitHub Actions**.
The site now has a build step, so the old "Deploy from a branch" mode would serve the raw
source, which is a blank page. Make the switch before (or right as) this version reaches
`main`.

### Old URLs

Everything the previous static site served under `assets/` now lives in
`public/assets/` and is published at the same path: the CV at `/assets/cv/cv.pdf`, the
favicons, and the images from the 2023 blog (`/assets/images/shemas/…`), which other
pages may still link to. Most of those images are no longer used by the page itself and
can be pruned if nothing external depends on them.

## The portrait and the About row

`public/subject.webp` is the photo the previous site used
(`public/assets/images/profile_pic.png`), cut out of its white studio backdrop: the
backdrop was flood-filled from the circle crop's rim, the edges matted against white
(so no white fringe survives the card's luminosity blend), and the image fades out
below the chin, which also hides where the shoulders met the circle crop. To swap the
photo, keep the same shape: a transparent head-and-shoulders cutout that fades out at
the bottom.

ProfileCard sizes the portrait from the card's **height**, not its width (`.pc-fit` in
`src/index.css`): the face, which is 82% of the image's height, is fitted into the
window between the name/title and the user-info bar, capped so a tall card doesn't blow
it up. If a new photo frames the face differently, change the `0.82` there.

From `xl` the profile card and the About text sit side by side as one row: the grid
stretches both cells to the taller one and the card fills its cell, so the two always
start and end on the same lines. Below `xl` they stack.

## Regenerating the social preview

`public/og-image.png` is the live hero, captured at 1200×630 with the rail, language pill,
icon row and glitch slices hidden, once the tagline has decrypted and the first role is
showing. Re-capture it whenever the hero copy changes. LinkedIn caches previews by URL, so
give a replacement a new file name (and update `og:image` / `twitter:image`).

## Notes

Most of the architecture comes from the portfolio this one is modelled on, including these
rules worth keeping:

- **`CanvasBoundary`** wraps every WebGL background. `ogl` throws when a GL context is
  unavailable, and that would otherwise unmount the whole page.
- **The shader backdrops are lazy-loaded**: DarkVeil (hero, hue-shifted to green with CRT
  scanlines), LightRays (About), SoftAurora (Skills), Plasma (Contact). DarkVeil and
  SoftAurora are wrapped in `NearViewport` so they only draw near the screen.
  Certifications is deliberately shader-free (a CSS dot grid) to give the page a quiet beat
  between two animated sections.
- **The "Always Learning" card runs a cmatrix-style rain**
  ([`MatrixRain.tsx`](src/components/layout/MatrixRain.tsx)): a 2D canvas, not WebGL, of
  printable ASCII like cmatrix's default. Trails fade with `destination-out`, so the card's
  glass shows between streams, and a radial scrim behind the copy keeps it readable. It
  animates only while on screen and draws one still frame under reduced motion. Tune it
  with its props (`fps`, `fade` for trail length, `fontSize`, `chars`, colours).
- **The boot overlay** is plain markup and an inline script in `index.html`, not a
  component, so it paints on the first frame. Completion is driven by timers, not frames,
  and the hero's typed `whoami` and tagline decrypt wait for its `app:loaded` event.
- **`html` uses `overflow-x: clip`**, not `hidden`, so the sticky profile card and radar
  keep working.
- **Vendored components were modified.** Re-adding them from the registry overwrites these
  changes:
  - Inherited from the reference portfolio: `LightRays`, `GlitchText`, `ChromaGrid`,
    `ProfileCard`, `TargetCursor`, `OptionWheel`, `SpecularButton` (see that project's
    README for each reason).
  - Added here:
    - `ChromaGrid`: `badge` (the Red Team / Blue Team chip over the art) and a
      translatable `readMoreLabel`; the card background is retinted to the ink palette.
    - `StaggeredMenu`: `menuLabel`, `closeLabel`, `openAriaLabel`, `closeAriaLabel` and
      `socialsTitle`, so the mobile menu speaks French; the toggle relabels immediately
      when the language changes.
    - `SpecularButton`: a `download` pass-through for the CV button.
- **`npm run lint` warns about `src/components/*`**: those are upstream React Bits sources.
  Authored code (sections, layout, i18n, lib, data) is clean.
