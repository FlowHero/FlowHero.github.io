import type { IconType } from 'react-icons';
import {
  SiArgo,
  SiBurpsuite,
  SiC,
  SiDocker,
  SiElastic,
  SiGitlab,
  SiGnubash,
  SiGrafana,
  SiHackthebox,
  SiJenkins,
  SiKubernetes,
  SiLinux,
  SiMetasploit,
  SiPrometheus,
  SiPython,
  SiSonarqubeserver,
  SiTerraform,
  SiTrivy,
  SiTryhackme,
  SiVault,
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
  | { cli: true; url: string };

/**
 * Brand mark and colour per tool. Colours are the Simple Icons brand hexes,
 * except where the brand is near-black or deep navy (TryHackMe, Vault's
 * black variant, Trivy), which would vanish on the dark tiles — those are
 * lifted to a lighter tint of the same hue.
 */
const tools: Record<ToolName, Tool> = {
  'Burp Suite': { Icon: SiBurpsuite, color: '#FF6633', url: 'https://portswigger.net/burp' },
  Metasploit: { Icon: SiMetasploit, color: '#2596CD', url: 'https://www.metasploit.com' },
  nmap: { cli: true, url: 'https://nmap.org' },
  Wireshark: { Icon: SiWireshark, color: '#2f8fd4', url: 'https://www.wireshark.org' },
  sqlmap: { cli: true, url: 'https://sqlmap.org' },
  'OWASP ZAP': { Icon: SiZap, color: '#4d9fff', url: 'https://www.zaproxy.org' },
  nuclei: { cli: true, url: 'https://github.com/projectdiscovery/nuclei' },
  'Hack The Box': { Icon: SiHackthebox, color: '#9FEF00', url: 'https://www.hackthebox.com' },
  TryHackMe: { Icon: SiTryhackme, color: '#E8EAF0', url: 'https://tryhackme.com' },
  Python: { Icon: SiPython, color: '#4B8BBE', url: 'https://www.python.org' },
  Bash: { Icon: SiGnubash, color: '#4EAA25', url: 'https://www.gnu.org/software/bash/' },
  PowerShell: { Icon: TbBrandPowershell, color: '#5391FE', url: 'https://learn.microsoft.com/powershell/' },
  C: { Icon: SiC, color: '#A8B9CC', url: 'https://en.cppreference.com/w/c' },
  Linux: { Icon: SiLinux, color: '#FCC624', url: 'https://www.kernel.org' },
  Docker: { Icon: SiDocker, color: '#2496ED', url: 'https://www.docker.com' },
  Kubernetes: { Icon: SiKubernetes, color: '#326CE5', url: 'https://kubernetes.io' },
  AWS: { Icon: TbBrandAws, color: '#FF9900', url: 'https://aws.amazon.com' },
  Azure: { Icon: TbBrandAzure, color: '#3b9cf0', url: 'https://azure.microsoft.com' },
  Terraform: { Icon: SiTerraform, color: '#844FBA', url: 'https://www.terraform.io' },
  Jenkins: { Icon: SiJenkins, color: '#D24939', url: 'https://www.jenkins.io' },
  'Argo CD': { Icon: SiArgo, color: '#EF7B4D', url: 'https://argo-cd.readthedocs.io' },
  Trivy: { Icon: SiTrivy, color: '#4f7dff', url: 'https://trivy.dev' },
  SonarQube: { Icon: SiSonarqubeserver, color: '#4E9BCD', url: 'https://www.sonarsource.com/products/sonarqube/' },
  Vault: { Icon: SiVault, color: '#FFEC6E', url: 'https://www.vaultproject.io' },
  gitleaks: { cli: true, url: 'https://github.com/gitleaks/gitleaks' },
  Prometheus: { Icon: SiPrometheus, color: '#E6522C', url: 'https://prometheus.io' },
  Grafana: { Icon: SiGrafana, color: '#F46800', url: 'https://grafana.com' },
  Elastic: { Icon: SiElastic, color: '#00BFB3', url: 'https://www.elastic.co' },
  GitLab: { Icon: SiGitlab, color: '#FC6D26', url: 'https://about.gitlab.com' },
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
          // ("gitleaks") in the tile without clipping.
          <span
            aria-hidden
            className="absolute inset-0 flex flex-col items-start justify-center gap-1 px-3 font-mono leading-none"
          >
            <span className="text-[10px] text-signal-glow/70">&gt;_</span>
            <span className="text-[10.5px] font-medium tracking-tight text-signal-glow">{name}</span>
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
