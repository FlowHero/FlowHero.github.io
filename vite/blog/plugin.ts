/**
 * Wires content/posts/*.md into the site:
 *
 *  - `virtual:blog-posts` gives the React Blog section each post's metadata
 *    (no bodies — those never reach the app bundle).
 *  - At build: /blog/, /blog/<slug>/, /blog/index.xml (RSS) and sitemap.xml
 *    are written as static files that link the app's hashed stylesheet.
 *  - In dev: the same pages are rendered per request, and editing a post
 *    reloads the browser.
 */
import path from 'node:path';
import type { Plugin, ResolvedConfig, ViteDevServer } from 'vite';
import { loadPosts, POSTS_DIR, renderPost, toMeta, type Post } from './posts.ts';
import { indexPage, postPage, rssFeed, sitemap } from './page.ts';

const VIRTUAL_ID = 'virtual:blog-posts';
const RESOLVED_ID = '\0' + VIRTUAL_ID;

async function renderAll(posts: Post[], cssHref: string) {
  const metas = posts.map(toMeta);
  const files: Record<string, string> = {
    'blog/index.html': indexPage(metas, cssHref),
    'blog/index.xml': rssFeed(metas),
    'sitemap.xml': sitemap(metas),
  };
  for (const [i, post] of posts.entries()) {
    // Newest first, so the previous index is the newer post.
    files[`blog/${post.slug}/index.html`] = postPage(await renderPost(post), metas[i + 1], metas[i - 1], cssHref);
  }
  return files;
}

export default function blog(): Plugin {
  let config: ResolvedConfig;
  const postsDir = () => path.join(config.root, POSTS_DIR);

  return {
    name: 'blog',

    configResolved(resolved) {
      config = resolved;
    },

    resolveId(id) {
      return id === VIRTUAL_ID ? RESOLVED_ID : undefined;
    },

    load(id) {
      if (id !== RESOLVED_ID) return;
      const posts = loadPosts(config.root);
      for (const p of posts) this.addWatchFile(path.join(postsDir(), `${p.slug}.md`));
      return `export default ${JSON.stringify(posts.map(toMeta))};`;
    },

    configureServer(server: ViteDevServer) {
      // A new, edited or deleted post: refresh the cards and the open page.
      server.watcher.add(postsDir());
      const onChange = (file: string) => {
        if (!file.startsWith(postsDir())) return;
        const mod = server.moduleGraph.getModuleById(RESOLVED_ID);
        if (mod) server.moduleGraph.invalidateModule(mod);
        server.ws.send({ type: 'full-reload' });
      };
      server.watcher.on('add', onChange).on('change', onChange).on('unlink', onChange);

      server.middlewares.use(async (req, res, next) => {
        const url = (req.url ?? '').split(/[?#]/)[0];
        const m = url.match(/^\/blog(?:\/([a-z0-9-]+))?\/?(index\.xml)?$/);
        if (!m) return next();
        try {
          // Rendered fresh each time — there are only a handful of posts.
          const files = await renderAll(loadPosts(config.root), '/src/index.css');
          const key = m[2] ? 'blog/index.xml' : m[1] ? `blog/${m[1]}/index.html` : 'blog/index.html';
          const out = files[key];
          if (!out) return next();
          if (m[2]) {
            res.setHeader('Content-Type', 'application/xml; charset=utf-8');
            return res.end(out);
          }
          if (!url.endsWith('/')) {
            res.statusCode = 301;
            res.setHeader('Location', url + '/');
            return res.end();
          }
          res.setHeader('Content-Type', 'text/html; charset=utf-8');
          res.end(await server.transformIndexHtml(url, out));
        } catch (err) {
          next(err);
        }
      });
    },

    async generateBundle(_options, bundle) {
      if (config.command !== 'build') return;
      // The stylesheet the app entry pulled in — the same hashed file the
      // portfolio uses, so a visitor coming from it already has it cached.
      const entry = Object.values(bundle).find(
        (c): c is Extract<typeof c, { type: 'chunk' }> => c.type === 'chunk' && c.isEntry
      );
      const css = entry?.viteMetadata?.importedCss.values().next().value;
      if (!css) this.error('blog: could not find the app stylesheet in the bundle');
      const cssHref = config.base + css;

      const files = await renderAll(loadPosts(config.root), cssHref);
      for (const [fileName, source] of Object.entries(files)) {
        this.emitFile({ type: 'asset', fileName, source });
      }
    },
  };
}
