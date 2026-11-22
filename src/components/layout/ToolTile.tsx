import type { IconType } from 'react-icons';
import {
  SiArgo,
  SiBurpsuite,
  SiClaude,
  SiDocker,
  SiElastic,
  SiFortinet,
  SiGitlab,
  SiGnubash,
  SiJenkins,
  SiKubernetes,
  SiLinux,
  SiMetasploit,
  SiPython,
  SiSplunk,
  SiTerraform,
  SiWireshark,
  SiZap,
} from 'react-icons/si';
// Simple Icons removed the Microsoft and Amazon marks at their owners'
// request; Tabler still draws them.
import { TbBrandAws, TbBrandAzure, TbBrandPowershell } from 'react-icons/tb';
import type { arsenal } from '@/data/content';

type ToolName = (typeof arsenal)[number];

type Tool =
  | { Icon: IconType; color: string; url: string }
  /** A command-line tool with no logo: drawn as a prompt in a terminal tile. */
  | { cli: true; url: string }
  /** A product with no mark in the icon sets: its name, set in brand colour. */
  | { word: string; color: string; url: string };

/**
 * Brand mark and colour per tool. Colours are the Simple Icons brand hexes,
 * except where the brand is near-black or deep navy, which would vanish on
 * the dark tiles — those are lifted to a lighter tint of the same hue.
 */
const tools: Record<ToolName, Tool> = {
  'Burp Suite': { Icon: SiBurpsuite, color: '#FF6633', url: 'https://portswigger.net/burp' },
  Metasploit: { Icon: SiMetasploit, color: '#2596CD', url: 'https://www.metasploit.com' },
  nmap: { cli: true, url: 'https://nmap.org' },
  Wireshark: { Icon: SiWireshark, color: '#2f8fd4', url: 'https://www.wireshark.org' },
  sqlmap: { cli: true, url: 'https://sqlmap.org' },
  'OWASP ZAP': { Icon: SiZap, color: '#4d9fff', url: 'https://www.zaproxy.org' },
  Python: { Icon: SiPython, color: '#4B8BBE', url: 'https://www.python.org' },
  Bash: { Icon: SiGnubash, color: '#4EAA25', url: 'https://www.gnu.org/software/bash/' },
  PowerShell: { Icon: TbBrandPowershell, color: '#5391FE', url: 'https://learn.microsoft.com/powershell/' },
  Linux: { Icon: SiLinux, color: '#FCC624', url: 'https://www.kernel.org' },
  Docker: { Icon: SiDocker, color: '#2496ED', url: 'https://www.docker.com' },
  Kubernetes: { Icon: SiKubernetes, color: '#326CE5', url: 'https://kubernetes.io' },
  AWS: { Icon: TbBrandAws, color: '#FF9900', url: 'https://aws.amazon.com' },
  Azure: { Icon: TbBrandAzure, color: '#3b9cf0', url: 'https://azure.microsoft.com' },
  Terraform: { Icon: SiTerraform, color: '#844FBA', url: 'https://www.terraform.io' },
  Jenkins: { Icon: SiJenkins, color: '#D24939', url: 'https://www.jenkins.io' },
  'Argo CD': { Icon: SiArgo, color: '#EF7B4D', url: 'https://argo-cd.readthedocs.io' },
  Elastic: { Icon: SiElastic, color: '#00BFB3', url: 'https://www.elastic.co' },
  GitLab: { Icon: SiGitlab, color: '#FC6D26', url: 'https://about.gitlab.com' },
  // Splunk's mark is black in Simple Icons; this is its classic brand green.
  Splunk: { Icon: SiSplunk, color: '#65A637', url: 'https://www.splunk.com' },
  // A Fortinet product, so it wears the Fortinet mark.
  FortiAnalyzer: { Icon: SiFortinet, color: '#EE3124', url: 'https://www.fortinet.com/products/management/fortianalyzer' },
  // Neither has a mark in Simple Icons or Tabler.
  'Check Point': { word: 'Check\nPoint', color: '#F0479B', url: 'https://www.checkpoint.com' },
  Sophos: { word: 'SOPHOS', color: '#5B8CFF', url: 'https://www.sophos.com' },
  Claude: { Icon: SiClaude, color: '#D97757', url: 'https://claude.ai' },
};

/**
 * One tool in the Skills marquee: a tile linking to the project's site, with
 * its name in a tooltip above. `cursor-target` is what TargetCursor locks
 * onto — the tile itself, so the crosshair frames the tile's rounded box.
 */
export default function ToolTile({ name }: { name: ToolName }) {
  const tool = tools[name];
  return (
    <a
      href={tool.url}
      target="_blank"
      rel="noopener noreferrer"
      aria-label={name}
      className="group/icon relative block shrink-0 cursor-pointer hover:z-20"
    >
      <span className="cursor-target relative flex h-16 w-16 items-center justify-center rounded-xl border border-white/[0.08] bg-ink-800/80 p-3 transition-colors duration-200 hover:border-signal-glow/40 hover:bg-ink-700/80">
        {'cli' in tool ? (
          // Absolutely positioned on purpose. LogoLoop sets each tile in an
          // inline-flex box on a 64px line, so in-flow text would hand the
          // tile a text baseline and drop it ~12px below the logo tiles,
          // which have none. Mono at a size that fits the longest name
          // ("sqlmap") in the tile without clipping.
          <span
            aria-hidden
            className="absolute inset-0 flex flex-col items-start justify-center gap-1 px-3 font-mono leading-none"
          >
            <span className="text-[10px] text-signal-glow/70">&gt;_</span>
            <span className="text-[10.5px] font-medium tracking-tight text-signal-glow">{name}</span>
          </span>
        ) : 'word' in tool ? (
          // Absolutely positioned for the same baseline reason as the CLI tile.
          <span
            aria-hidden
            className="absolute inset-0 flex items-center justify-center px-1.5 text-center font-display text-[12px] leading-[1.05] font-bold tracking-tight whitespace-pre-line"
            style={{ color: tool.color }}
          >
            {tool.word}
          </span>
        ) : (
          <tool.Icon aria-hidden className="h-full w-full" style={{ color: tool.color }} />
        )}
      </span>
      <span
        aria-hidden
        className="pointer-events-none absolute -top-10 left-1/2 z-10 -translate-x-1/2 rounded-lg border border-white/10 bg-ink-900/95 px-2.5 py-1 font-mono text-xs whitespace-nowrap text-mist-100 opacity-0 shadow-lg backdrop-blur-sm transition-opacity duration-200 group-hover/icon:opacity-100"
      >
        {name}
      </span>
    </a>
  );
}
