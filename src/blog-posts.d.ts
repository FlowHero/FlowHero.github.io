/** Provided by vite/blog/plugin.ts: every published post, newest first. */
declare module 'virtual:blog-posts' {
  const posts: import('./data/blog').PostMeta[];
  export default posts;
}
