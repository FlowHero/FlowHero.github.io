import { SiHackthebox, SiTryhackme } from 'react-icons/si';

type IconName = 'linkedin' | 'email' | 'tryhackme' | 'hackthebox';

/**
 * LinkedIn and email as inline paths — Simple Icons dropped LinkedIn's mark at
 * the company's request, so it is not in react-icons/si. The two platform
 * marks come from Simple Icons. All are filled on a 24px grid so they hold
 * the same weight side by side, and `currentColor` keeps the links' hover
 * transition working.
 */
const PATHS: Partial<Record<IconName, string>> = {
  linkedin:
    'M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.062 2.062 0 1 1 0-4.125 2.062 2.062 0 0 1 0 4.125zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.225 0z',
  email:
    'M0 5.25A2.25 2.25 0 0 1 2.25 3h19.5A2.25 2.25 0 0 1 24 5.25v.383l-11.46 6.303a1.125 1.125 0 0 1-1.08 0L0 5.633V5.25Zm0 3.02v10.48A2.25 2.25 0 0 0 2.25 21h19.5A2.25 2.25 0 0 0 24 18.75V8.27l-10.38 5.708a3.375 3.375 0 0 1-3.24 0L0 8.27Z',
};

export default function SocialIcon({
  name,
  className = 'h-[18px] w-[18px]',
}: {
  name: IconName;
  className?: string;
}) {
  if (name === 'tryhackme') return <SiTryhackme aria-hidden focusable="false" className={className} />;
  if (name === 'hackthebox') return <SiHackthebox aria-hidden focusable="false" className={className} />;
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden focusable="false" className={className}>
      <path d={PATHS[name]} />
    </svg>
  );
}

export type { IconName };
