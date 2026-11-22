/**
 * Blog post metadata, as the build hands it to the app. The posts themselves
 * are Markdown in content/posts/ — see vite/blog/posts.ts.
 */
export type PostMeta = {
  slug: string;
  title: string;
  titleFr?: string;
  description: string;
  summary: string;
  summaryFr?: string;
  /** YYYY-MM-DD, for display. */
  date: string;
  /** Full timestamp, for <time> and structured data. */
  datetime: string;
  image?: string;
  tags: string[];
  /** Site-relative, with trailing slash: /blog/<slug>/ */
  url: string;
  readingMinutes: number;
};
