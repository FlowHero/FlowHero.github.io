/**
 * ────────────────────────────────────────────────────────────────
 *  EDIT THE PORTFOLIO HERE
 *  Every word on the site lives in this file, in English and French.
 * ────────────────────────────────────────────────────────────────
 *
 * Fields typed `Text` take either a plain string, shown in both languages
 * (names, tools, acronyms), or `{ en: '…', fr: '…' }`.
 *
 * Inside the bio and project write-ups, `**like this**` renders as a
 * highlighted phrase.
 */
import type { Localized, Text } from '../i18n/text.ts';

export const profile = {
  /** First name: the friendly "Hello! I'm ___" in About. */
  name: 'Ayoub',
  /** Shown in the hero, on the profile card and in every search result. */
  fullName: 'ABAD Ayoub',
  /** Handle on TryHackMe / GitHub, also the hostname in the hero prompt. */
  handle: 'FlowHero',
  /** The highlighted "I'm a ___" tag in the hero, and the profile card's title. */
  role: { en: 'Cybersecurity Engineer', fr: 'Ingénieur Cybersécurité' } satisfies Text,
  location: { en: 'Oujda, Morocco', fr: 'Oujda, Maroc' } satisfies Text,
  /** The pulsing chip above the name. */
  status: { en: 'Open to new opportunities', fr: 'Ouvert aux nouvelles opportunités' } satisfies Text,
  /** Decrypts in under the role. Keep it near ~110 characters. */
  tagline: {
    en: 'Specializing in SecOps, Penetration Testing & DevSecOps. Building defenses. Breaking assumptions.',
    fr: 'Spécialisé en SecOps, Tests d’Intrusion & DevSecOps. Construire des défenses. Briser les certitudes.',
  } satisfies Text,
  /** About card, one string per paragraph. */
  bio: {
    en: [
      'I’m a Cybersecurity Engineer based in Morocco, currently working as a **SecOps Engineer at Tessi**, where I monitor and investigate security alerts across Network, SaaS, Email, and Endpoint vectors using SIEM, NDR, EDR, WAF, and IPS/IDS solutions.',
      'I hold a State Engineer Diploma in Computer Security & Cybersecurity from **ENSA Oujda** (2019–2024). My background spans offensive security (web pentesting, bug bounty), defensive security (SOC, incident response), and cloud security (DevSecOps, Kubernetes, AWS/Azure).',
      'What drives me is the offensive/defensive duality, understanding attack techniques to build better defenses. From pentesting to incident response, I enjoy operating on both sides.',
    ],
    fr: [
      'Je suis Ingénieur Cybersécurité basé au Maroc, actuellement en poste en tant qu’**Ingénieur SecOps chez Tessi**, où je surveille et investigue les alertes de sécurité (Réseau, SaaS, Email, Endpoint) via les solutions SIEM, NDR, EDR, WAF et IPS/IDS.',
      'Je suis titulaire d’un Diplôme d’Ingénieur d’État en Sécurité Informatique & Cybersécurité de l’**ENSA Oujda** (2019–2024). Mon profil couvre la sécurité offensive (pentest web, bug bounty), la sécurité défensive (SOC, réponse aux incidents) et la sécurité cloud (DevSecOps, Kubernetes, AWS/Azure).',
      'Ce qui m’anime, c’est la dualité offensif/défensif, comprendre les techniques d’attaque pour construire de meilleures défenses. Du pentest à la réponse aux incidents, j’aime opérer des deux côtés.',
    ],
  } satisfies Localized<readonly string[]>,
  email: 'ayoub.02.abad@gmail.com',
  /** Served from public/ — the same URL the old site linked to. */
  cv: '/assets/cv/cv.pdf',
  spokenLanguages: {
    en: 'Arabic (Native) · English (Advanced) · French (Advanced)',
    fr: 'Arabe (Natif) · Anglais (Avancé) · Français (Avancé)',
  } satisfies Text,
} as const;

/** Headline number(s) on the About card, set beside the spoken languages. */
export const stats: { value: string; label: Text }[] = [
  { value: '2+', label: { en: 'Years experience', fr: 'Ans d’expérience' } },
];

/** Chips under "What drives me" on the About card. */
export const interests: Localized<readonly string[]> = {
  en: ['Offensive Security', 'Blue Team / SOC', 'Threat Hunting', 'Cloud Security', 'Bug Bounty', 'CTFs', 'Automation'],
  fr: ['Sécurité Offensive', 'Blue Team / SOC', 'Threat Hunting', 'Sécurité Cloud', 'Bug Bounty', 'CTF', 'Automatisation'],
};

/** `icon` keys into components/layout/SocialIcon.tsx. */
export const socials = [
  { label: 'LinkedIn', href: 'https://linkedin.com/in/abaa-youb', icon: 'linkedin' },
  { label: 'TryHackMe', href: 'https://tryhackme.com/p/FlowHero', icon: 'tryhackme' },
  { label: 'Email', href: 'mailto:ayoub.02.abad@gmail.com', icon: 'email' },
  // `as const` keeps `icon` a literal so it still satisfies SocialIcon's union.
] as const;

/**
 * The tool marquee in Skills, in scroll order. Each name needs an entry in
 * components/layout/ToolTile.tsx — `as const` makes a missing one a type error.
 * Command-line tools without a logo render as a terminal tile instead.
 */
export const arsenal = [
  'Burp Suite', 'Metasploit', 'nmap', 'Wireshark', 'sqlmap', 'OWASP ZAP', 'nuclei',
  'Hack The Box', 'TryHackMe', 'Python', 'Bash', 'PowerShell', 'C', 'Linux',
  'Docker', 'Kubernetes', 'AWS', 'Azure', 'Terraform', 'Jenkins', 'Argo CD',
  'Trivy', 'SonarQube', 'Vault', 'gitleaks', 'Prometheus', 'Grafana', 'Elastic', 'GitLab',
] as const;

export type SkillDomain = {
  title: Text;
  /** Axis label on the radar. */
  short: Text;
  /** 0–100, drawn on the radar and the card's bar. */
  level: number;
  /** Domain colour, reused by the projects and certifications in it. */
  color: string;
  icon: 'target' | 'shield' | 'layers' | 'terminal' | 'wrench' | 'check';
  tags: readonly string[];
};

/** The radar and the six cards beside it. */
export const skillDomains: SkillDomain[] = [
  {
    title: { en: 'Offensive Security', fr: 'Sécurité Offensive' },
    short: { en: 'Offensive', fr: 'Offensif' },
    level: 80,
    color: '#ff4d6d',
    icon: 'target',
    tags: ['Web App Pentesting', 'API Security', 'Bug Bounty', 'SQLi / XSS / LFI', 'Recon & OSINT', 'WAF Bypass', 'Active Directory Attacks'],
  },
  {
    title: { en: 'Defensive / SOC', fr: 'Défensif / SOC' },
    short: { en: 'Defensive', fr: 'Défensif' },
    level: 85,
    color: '#60a5fa',
    icon: 'shield',
    tags: ['SIEM', 'SOC Operations', 'Incident Response', 'Threat Hunting', 'NDR / EDR / WAF', 'CVE Management', 'Network Security'],
  },
  {
    title: 'Cloud & DevSecOps',
    short: 'Cloud',
    level: 66,
    color: '#a78bfa',
    icon: 'layers',
    tags: ['AWS', 'Microsoft Azure', 'Kubernetes', 'Docker', 'CI/CD', 'SAST / DAST / SCA'],
  },
  {
    title: { en: 'Programming & Scripting', fr: 'Programmation & Scripting' },
    short: 'Scripting',
    level: 76,
    color: '#00f59b',
    icon: 'terminal',
    tags: ['Python', 'Bash Scripting', 'PowerShell', 'Shell', 'C'],
  },
  {
    title: { en: 'Security Tools', fr: 'Outils de Sécurité' },
    short: { en: 'Tools', fr: 'Outils' },
    level: 83,
    color: '#fbbf24',
    icon: 'wrench',
    tags: ['Burp Suite', 'Metasploit', 'Nmap', 'Wireshark', 'SQLMap', 'Nuclei'],
  },
  {
    title: { en: 'Compliance & Frameworks', fr: 'Conformité & Frameworks' },
    short: { en: 'Compliance', fr: 'Conformité' },
    level: 55,
    color: '#94a3b8',
    icon: 'check',
    tags: ['PCI-DSS', 'ISO 27001', 'NIST', 'Network Security', 'IPSec VPN', 'DLP'],
  },
];

/** The card under the skills. Topics render as chips. */
export const learning = {
  title: { en: 'Always Learning', fr: 'Toujours en apprentissage' } satisfies Text,
  text: {
    en: 'Attackers don’t stand still, so neither do I. Right now that means Hack The Box’s Senior Web Penetration Tester path, Active Directory attack chains, digital forensics and memory analysis, and hardening cloud workloads on Azure and AWS.',
    fr: 'Les attaquants ne s’arrêtent jamais, moi non plus. En ce moment : le parcours Senior Web Penetration Tester de Hack The Box, les chaînes d’attaque Active Directory, la forensique numérique et l’analyse mémoire, et la sécurisation des workloads cloud sur Azure et AWS.',
  } satisfies Text,
  topics: {
    en: ['Advanced Web Exploitation', 'Active Directory', 'Digital Forensics', 'Memory Analysis', 'Threat Modeling', 'Cloud Security'],
    fr: ['Exploitation Web Avancée', 'Active Directory', 'Forensique Numérique', 'Analyse Mémoire', 'Modélisation des Menaces', 'Sécurité Cloud'],
  } satisfies Localized<readonly string[]>,
};

export type Project = {
  title: Text;
  /** Card copy. Keep it under ~145 characters: the card clamps it to three
   *  lines and anything longer is cut mid-sentence. */
  blurb: Text;
  /** The long version, one string per paragraph, shown in the dialog. */
  details: Localized<readonly string[]>;
  tech: readonly string[];
  /** Short label over the card art: which side of the house it sits on. */
  domain: string;
  /** Card accent — the hover border, the badge, and the cover art's tint. */
  accent: string;
  /** What the generated cover art draws (src/lib/cover.ts). */
  motif: 'pipeline' | 'map' | 'terminal' | 'code';
  /**
   * Optional screenshot, e.g. '/images/projects/eks.webp' (file goes in
   * public/), cropped to 19:10. Without one the card gets generated art.
   */
  image?: string;
  /** Repo or write-up. Shown as a button inside the dialog. */
  url?: string;
};

export const projects: Project[] = [
  {
    title: { en: 'Cloud-Native DevSecOps on AWS EKS', fr: 'DevSecOps Cloud-Native sur AWS EKS' },
    blurb: {
      en: 'An end-to-end DevSecOps pipeline for a 3-tier app on Amazon EKS, with a security gate at every stage from commit to cluster.',
      fr: 'Un pipeline DevSecOps bout-en-bout pour une application 3-tiers sur Amazon EKS, avec un contrôle de sécurité à chaque étape.',
    },
    details: {
      en: [
        'End-to-end DevSecOps pipeline for a 3-tier application on Amazon EKS. CI/CD runs on **Jenkins + ArgoCD**, with the infrastructure defined as code in **Terraform**.',
        'Security is embedded at every stage: GitLeaks pre-commit hooks, SAST tools, OWASP DependencyCheck (SCA), OWASP ZAP (DAST), Trivy for containers, Kubernetes and IaC, SonarQube for code quality, and Vault for secrets.',
        'Prometheus & Grafana handle monitoring, and an EFK stack provides centralized logging.',
      ],
      fr: [
        'Pipeline DevSecOps bout-en-bout pour une application 3-tiers sur Amazon EKS. La CI/CD repose sur **Jenkins + ArgoCD**, avec une infrastructure décrite en code via **Terraform**.',
        'La sécurité est intégrée à chaque étape : hooks pre-commit GitLeaks, outils SAST, OWASP DependencyCheck (SCA), OWASP ZAP (DAST), Trivy pour les conteneurs, Kubernetes et l’IaC, SonarQube pour la qualité du code et Vault pour les secrets.',
        'Prometheus & Grafana assurent la supervision, et une stack EFK centralise la journalisation.',
      ],
    },
    tech: ['AWS EKS', 'Kubernetes', 'Jenkins', 'Terraform', 'ArgoCD', 'Trivy', 'SonarQube', 'Vault'],
    domain: 'DevSecOps',
    accent: '#a78bfa',
    motif: 'pipeline',
  },
  {
    title: { en: 'RDP Brute-Force Map — Azure Sentinel', fr: 'Carte d’Attaques RDP — Azure Sentinel' },
    blurb: {
      en: 'A real-time global map of RDP brute-force attacks, built on Azure Sentinel with PowerShell log enrichment and geolocation.',
      fr: 'Une carte mondiale en temps réel des attaques RDP par force brute, sur Azure Sentinel avec enrichissement PowerShell.',
    },
    details: {
      en: [
        'Real-time global threat map tracking RDP brute-force attacks using **Azure Sentinel** SIEM.',
        'A custom PowerShell script extracts event metadata from Windows Event Viewer and enriches it via a geolocation API. Azure Log Analytics ingests the custom logs, and a Sentinel workbook visualizes global attacks by location and intensity.',
      ],
      fr: [
        'Carte de menaces mondiale en temps réel pour le suivi des attaques RDP par force brute via **Azure Sentinel** SIEM.',
        'Un script PowerShell personnalisé extrait les métadonnées d’événements Windows et les enrichit via une API de géolocalisation. Azure Log Analytics ingère les journaux, et un classeur Sentinel visualise les attaques mondiales par localisation et intensité.',
      ],
    },
    tech: ['Azure Sentinel', 'Log Analytics', 'PowerShell', 'SIEM', 'Geolocation API'],
    domain: 'Blue Team',
    accent: '#60a5fa',
    motif: 'map',
  },
  {
    title: { en: 'Web & API Pentest Automation', fr: 'Automatisation de Pentest Web & API' },
    blurb: {
      en: 'Bash tooling that automates the repetitive side of pentesting and bug bounty: recon, WAF bypass, fuzzing and vuln testing.',
      fr: 'Des scripts Bash qui automatisent le travail répétitif du pentest et du bug bounty : recon, bypass WAF, fuzzing et tests.',
    },
    details: {
      en: [
        'Suite of Bash scripts automating repetitive pentesting and bug bounty tasks.',
        'It covers recon, **WAF detection & bypass**, technology fingerprinting (WordPress, GraphQL), fuzzing, spidering, secrets scanning, and comprehensive vulnerability testing (LFI, SQLi, XSS).',
      ],
      fr: [
        'Suite de scripts Bash automatisant les tâches répétitives de pentest et de bug bounty.',
        'Elle couvre la reconnaissance, la **détection & le contournement de WAF**, le fingerprinting technologique (WordPress, GraphQL), le fuzzing, le spidering, le scan de secrets et des tests de vulnérabilités complets (LFI, SQLi, XSS).',
      ],
    },
    tech: ['Bash', 'Recon', 'WAF Bypass', 'Fuzzing', 'SQLi / XSS', 'Bug Bounty'],
    domain: 'Red Team',
    accent: '#ff4d6d',
    motif: 'terminal',
  },
  {
    title: { en: 'Web App Source Code Security Audit', fr: 'Audit de Sécurité du Code Source' },
    blurb: {
      en: 'A source code audit of PHP and Node.js apps, tracing input validation, authentication and business-logic flaws to fixes.',
      fr: 'Audit du code source d’applications PHP et Node.js : validation des entrées, authentification, logique métier et correctifs.',
    },
    details: {
      en: [
        'In-depth source code analysis of PHP and Node.js applications to identify critical vulnerabilities: input validation flaws, authentication weaknesses, error handling issues, and business logic bugs.',
        'Each finding came with a concrete remediation, including **secure coding practices**, input validation, and regular audits.',
      ],
      fr: [
        'Analyse approfondie du code source d’applications PHP et Node.js pour identifier les vulnérabilités critiques : failles de validation des entrées, faiblesses d’authentification, problèmes de gestion des erreurs et bugs de logique métier.',
        'Chaque faille s’accompagne d’une remédiation concrète, dont les **bonnes pratiques de codage sécurisé**, la validation des entrées et des audits réguliers.',
      ],
    },
    tech: ['PHP', 'Node.js', 'SAST', 'Code Review', 'OWASP Top 10'],
    domain: 'AppSec',
    accent: '#00f59b',
    motif: 'code',
  },
];

export type TimelineEntry = {
  period: Text;
  title: Text;
  org: string;
  location: Text;
  /** Small chip beside the organisation, e.g. an internship's length. */
  badge?: Text;
  description?: Text;
  /** Bullet points, rendered under the description. */
  highlights?: Localized<readonly string[]>;
  /** Rendered as chips. */
  tags?: readonly Text[];
  /** Optional logo from public/, shown beside the title. */
  logo?: string;
  /** Experience and education render as two separate blocks in About. */
  kind: 'education' | 'experience';
};

export const timeline: TimelineEntry[] = [
  {
    period: { en: 'Mar 2025 – Present', fr: 'Mars 2025 – Présent' },
    title: { en: 'SecOps Engineer', fr: 'Ingénieur SecOps' },
    org: 'Tessi',
    location: { en: 'Oujda, Morocco · Hybrid', fr: 'Oujda, Maroc · Hybride' },
    highlights: {
      en: [
        'Monitor, analyze and investigate security alerts (Network, SaaS, Email, Endpoint) via SIEM, NDR, EDR, WAF, and IPS/IDS.',
        'Critical vulnerability (CVE) monitoring, exposure analysis, and remediation tracking.',
        'Respond to client cybersecurity questionnaires (ISO 27001 compliance posture).',
        'Developed a Python dashboard with the IRIS API for incident/alert/CVE visualization and SOC KPI tracking (MTTD, MTTR).',
        'NDR solution POC integration and evaluation in a production environment: tuning, alert triage and investigation, detection coverage validation through attack simulation, comparative analysis with the existing solution, and definition of the final decision framework.',
      ],
      fr: [
        'Surveillance, analyse et investigation des alertes de sécurité (Réseau, SaaS, Email, Endpoint) via les solutions SIEM, NDR, EDR, WAF et IPS/IDS.',
        'Veille sur les vulnérabilités critiques (CVE), investigation, analyse d’exposition et suivi des remédiations.',
        'Réponse aux questionnaires de cybersécurité des clients (posture sécurité, conformité ISO 27001).',
        'Développement d’un dashboard Python interfacé avec l’API IRIS pour la visualisation des incidents, alertes et CVEs, avec suivi des KPIs SOC (MTTD, MTTR).',
        'Intégration et évaluation POC d’une solution NDR en environnement de production : tuning, triage et investigation des alertes, validation de la couverture de détection par simulation d’attaques, analyse comparative avec la solution existante et définition du cadre de décision final.',
      ],
    },
    tags: ['SIEM', 'EDR', 'NDR', 'SOC', 'Python', 'ISO 27001', 'CVE', 'Incident Response'],
    kind: 'experience',
  },
  {
    period: { en: 'Feb – Aug 2024', fr: 'Fév – Août 2024' },
    title: { en: 'Network & Security Engineer', fr: 'Ingénieur Réseaux & Sécurité' },
    org: 'Société Générale ABS',
    location: { en: 'Casablanca, Morocco', fr: 'Casablanca, Maroc' },
    badge: { en: 'Internship · 6 months', fr: 'Stage PFE · 6 mois' },
    highlights: {
      en: [
        'Built a secure network infrastructure connecting SG African subsidiaries to the public internet with NGFW, Proxy, and DLP layers.',
        'Configured IPSec VPN tunnels for site-to-site connectivity.',
        'Assisted with PCI-DSS compliance implementation.',
        'Contributed to EDR and IDS/IPS solution deployment.',
        'Managed HW & SW obsolescence.',
      ],
      fr: [
        'Construction d’une infrastructure réseau sécurisée reliant les filiales africaines de SG à l’internet public, avec couches NGFW, Proxy et DLP.',
        'Configuration des tunnels IPSec VPN pour la connectivité site-à-site.',
        'Assistance à la mise en conformité PCI-DSS.',
        'Contribution à l’implémentation et au déploiement de solutions EDR et IDS/IPS.',
        'Gestion de l’obsolescence matérielle & logicielle.',
      ],
    },
    tags: ['NGFW', 'IPSec VPN', 'PCI-DSS', 'EDR', 'IDS/IPS', 'DLP', 'Proxy'],
    kind: 'experience',
  },
  {
    period: { en: 'Jul – Sep 2023', fr: 'Juil – Sep 2023' },
    title: { en: 'Cybersecurity Engineer', fr: 'Ingénieur Cybersécurité' },
    org: 'Tisalabs',
    location: { en: 'Cork, Ireland · Remote', fr: 'Cork, Irlande · À distance' },
    badge: { en: 'Internship · 2 months', fr: 'Stage · 2 mois' },
    highlights: {
      en: [
        'Vulnerability Assessment and Penetration Testing (VAPT).',
        'Python development and Bash scripting for automation.',
        'Docker containerization and Kubernetes security.',
        'Agile methodology with GitLab workflows.',
      ],
      fr: [
        'Évaluation des vulnérabilités et tests de pénétration (VAPT).',
        'Développement Python et scripts Bash pour l’automatisation.',
        'Conteneurisation Docker et sécurité Kubernetes.',
        'Méthodologie Agile avec les workflows GitLab.',
      ],
    },
    tags: ['VAPT', 'Python', 'Bash', 'Docker', 'Kubernetes', 'GitLab'],
    kind: 'experience',
  },
  {
    period: '2019 – 2024',
    title: {
      en: 'State Engineer Diploma — Computer Security & Cybersecurity',
      fr: 'Diplôme d’Ingénieur d’État — Sécurité Informatique & Cybersécurité',
    },
    org: 'ENSA Oujda (École Nationale des Sciences Appliquées)',
    location: { en: 'Oujda, Morocco', fr: 'Oujda, Maroc' },
    logo: '/assets/images/ensao.webp',
    description: {
      en: '5-year engineering program covering networks, system administration, cryptography, mobile security, ethical hacking, penetration testing, cloud computing, big data, machine learning, and security audits.',
      fr: 'Formation d’ingénieur de 5 ans couvrant les réseaux, l’administration système, la cryptographie, la sécurité mobile, le hacking éthique, les tests d’intrusion, le cloud computing, le big data, le machine learning et les audits de sécurité.',
    },
    tags: [
      { en: 'Networking', fr: 'Réseaux' },
      { en: 'Cryptography', fr: 'Cryptographie' },
      { en: 'Ethical Hacking', fr: 'Hacking Éthique' },
      { en: 'Penetration Testing', fr: 'Tests d’Intrusion' },
      'Cloud Computing',
      'Machine Learning',
      { en: 'Security Audits', fr: 'Audits de Sécurité' },
    ],
    kind: 'education',
  },
];

export type Certification = {
  title: Text;
  issuer: Text;
  detail: Text;
  icon: 'htb' | 'thm' | 'azure' | 'aws' | 'trophy';
  /** Brand colour for the icon tile. */
  color: string;
  /** Chip in the card's corner. */
  badge?: Text;
  /** 0–100 for a path still in progress — draws a bar instead of a badge. */
  progress?: number;
  /** Proof: a public achievement page or profile. */
  url?: string;
  /** Lit border and first in line. */
  featured?: boolean;
};

export const certifications: Certification[] = [
  {
    title: { en: 'SOC Analyst', fr: 'Analyste SOC' },
    issuer: 'Hack The Box Academy',
    detail: { en: 'Blue Team Operations Track', fr: 'Parcours Opérations Blue Team' },
    icon: 'htb',
    color: '#9FEF00',
    badge: { en: 'Completed', fr: 'Terminé' },
    url: 'https://academy.hackthebox.com/achievement/257048/path/390',
    featured: true,
  },
  {
    title: { en: 'Top 1% Rank', fr: 'Rang Top 1%' },
    issuer: 'TryHackMe',
    detail: 'Web Fundamentals · Pre-Security · Jr. Pentester · Pentest+ · Cyber Defense',
    icon: 'thm',
    color: '#e8eaf0',
    url: 'https://tryhackme.com/p/FlowHero',
    featured: true,
  },
  {
    title: { en: 'Senior Web Penetration Tester', fr: 'Testeur d’Intrusion Web Senior' },
    issuer: 'Hack The Box Academy',
    detail: { en: 'Offensive Web Security Track', fr: 'Parcours Sécurité Offensive Web' },
    icon: 'htb',
    color: '#9FEF00',
    progress: 67,
  },
  {
    title: { en: 'Azure Security Engineer (AZ-500)', fr: 'Ingénieur Sécurité Azure (AZ-500)' },
    issuer: 'CloudGuru',
    detail: { en: 'Microsoft Azure Security', fr: 'Sécurité Microsoft Azure' },
    icon: 'azure',
    color: '#3b9cf0',
  },
  {
    title: 'AWS Cloud Practitioner + Security Fundamentals',
    issuer: 'CloudGuru',
    detail: 'Amazon Web Services',
    icon: 'aws',
    color: '#FF9900',
  },
  {
    title: { en: 'CTF Competition — 3rd Place', fr: 'Compétition CTF — 3ème Place' },
    issuer: { en: 'University CTF', fr: 'CTF Universitaire' },
    detail: { en: 'Competitive Hacking', fr: 'Hacking Compétitif' },
    icon: 'trophy',
    color: '#fbbf24',
    badge: { en: '3rd place', fr: '3ème place' },
  },
];

export type BlogPost = {
  title: Text;
  /** One or two sentences: the post's front-matter description. */
  excerpt: Text;
  /** ISO date the post was published. */
  date: string;
  /** Thumbnail, a path under public/. */
  image: string;
  /** The post on the Hugo blog. */
  url: string;
  tags: readonly string[];
};

/** Base of the Hugo blog (github.com/FlowHero/newblog). */
export const blogUrl = 'https://flowhero.github.io/newblog/';

/** Write-ups from the blog, newest first. Add a post here when it goes live. */
export const blogPosts: BlogPost[] = [
  {
    title: { en: 'Certified Kubernetes Security — Chapter 1 Notes', fr: 'Certified Kubernetes Security — Notes du Chapitre 1' },
    excerpt: {
      en: 'Cluster Setup from the CKS exam: network policies, CIS benchmarks with kube-bench, Ingress with TLS, locking down cluster components and verifying platform binaries.',
      fr: 'Le domaine Cluster Setup de l’examen CKS : network policies, benchmarks CIS avec kube-bench, Ingress avec TLS, sécurisation des composants du cluster et vérification des binaires.',
    },
    date: '2024-08-23',
    image: '/assets/images/kubesec.png',
    url: `${blogUrl}posts/cks/`,
    tags: ['Kubernetes', 'CKS', 'Cloud Security'],
  },
  {
    title: 'Fuzzing APIs',
    excerpt: {
      en: 'A deep dive into API fuzzing with Postman, Burp and Wfuzz: fuzzing wide and deep, finding improper assets management and bypassing input sanitization.',
      fr: 'Plongée dans le fuzzing d’API avec Postman, Burp et Wfuzz : fuzzing large et profond, gestion inappropriée des assets et contournement de la sanitisation des entrées.',
    },
    date: '2023-08-22',
    image: '/assets/images/apifuzzing.png',
    url: `${blogUrl}posts/fuzzing-apis/`,
    tags: ['API', 'Fuzzing', 'Burp Suite'],
  },
  {
    title: { en: 'JWT Attacks Cheat Sheet', fr: 'Cheat Sheet des Attaques JWT' },
    excerpt: {
      en: 'The most common JSON Web Token attacks: exposed JWKS, signature bypasses, weak secrets, key confusion, and the tooling to test each one.',
      fr: 'Les attaques JSON Web Token les plus courantes : JWKS exposés, contournement de signature, secrets faibles, confusion de clés, et les outils pour tester chacune.',
    },
    date: '2023-08-13',
    image: '/assets/images/jwts.png',
    url: `${blogUrl}posts/jwts-attacks/`,
    tags: ['JWT', 'Web', 'Auth'],
  },
  {
    title: { en: 'Bypassing WAFs', fr: 'Contourner les WAF' },
    excerpt: {
      en: 'Blocked by the web server you are testing? How WAFs detect you, and the techniques to get past them during bug hunting and pentests.',
      fr: 'Bloqué par le serveur que vous testez ? Comment les WAF vous détectent, et les techniques pour les contourner en bug hunting et en pentest.',
    },
    date: '2023-08-05',
    image: '/assets/images/wafbypassblog.png',
    url: `${blogUrl}posts/bypassing-wafs/`,
    tags: ['WAF', 'Evasion', 'Bug Bounty'],
  },
  {
    title: { en: 'Attacking GraphQL', fr: 'Attaquer GraphQL' },
    excerpt: {
      en: 'Getting started with GraphQL testing, from recon to exploitation, with a hands-on lab on DVGA.',
      fr: 'Débuter les tests GraphQL, de la reconnaissance à l’exploitation, avec un lab pratique sur DVGA.',
    },
    date: '2023-08-02',
    image: '/assets/images/b-10.webp',
    url: `${blogUrl}posts/graphql-exploitation/`,
    tags: ['GraphQL', 'API', 'Recon'],
  },
];

export const contact = {
  intro: {
    en: 'I’m open to new opportunities, collaborations, or just a good conversation about cybersecurity. Whether you have a project in mind or want to discuss the latest in threat intelligence, feel free to reach out.',
    fr: 'Je suis ouvert aux nouvelles opportunités, collaborations ou simplement une bonne conversation sur la cybersécurité. Que vous ayez un projet en tête ou souhaitiez discuter des dernières menaces, n’hésitez pas à me contacter.',
  } satisfies Text,
};

/**
 * Side-rail navigation. Keep these in section order — the rail resolves each
 * one by the matching `id` on a <section> in App.tsx.
 */
export const navLinks: { label: Text; href: string }[] = [
  { label: { en: 'Home', fr: 'Accueil' }, href: '#home' },
  { label: { en: 'About', fr: 'À propos' }, href: '#about' },
  { label: { en: 'Projects', fr: 'Projets' }, href: '#projects' },
  { label: { en: 'Skills', fr: 'Compétences' }, href: '#skills' },
  { label: { en: 'Certs', fr: 'Certifs' }, href: '#certifications' },
  { label: 'Blog', href: '#blog' },
  { label: 'Contact', href: '#contact' },
];

/** Interface copy: headings, buttons, labels. */
export const ui = {
  meta: {
    title: {
      en: 'ABAD Ayoub — Cybersecurity Engineer',
      fr: 'ABAD Ayoub — Ingénieur Cybersécurité',
    },
  },
  skipLink: { en: 'Skip to content', fr: 'Aller au contenu' },
  langToggle: { en: 'Language', fr: 'Langue' },
  hero: {
    iAmA: { en: 'I’m a', fr: 'Je suis' },
    ctaWork: { en: 'View my work', fr: 'Voir mes projets' },
    ctaCv: { en: 'Download CV', fr: 'Télécharger le CV' },
  },
  about: {
    title: { en: 'About Me', fr: 'À propos de moi' },
    lede: {
      en: 'Understanding attack techniques to build better defenses',
      fr: 'Comprendre les techniques d’attaque pour construire de meilleures défenses',
    },
    hello: { en: 'Hello! I’m', fr: 'Bonjour ! Je suis' },
    languages: { en: 'Languages', fr: 'Langues' },
    drives: { en: 'What Drives Me', fr: 'Ce qui m’anime' },
    experience: { en: 'Work Experience', fr: 'Expérience Professionnelle' },
    education: { en: 'Education', fr: 'Formation' },
    cardStatus: { en: 'Open to work', fr: 'Disponible' },
    cardContact: { en: 'Say hello', fr: 'Écrivez-moi' },
  },
  projects: {
    title: { en: 'Featured Projects', fr: 'Projets Phares' },
    lede: {
      en: 'Pipelines, detections and tooling from both sides of the house: offense, defense, and the code in between.',
      fr: 'Pipelines, détections et outillage des deux côtés : l’offensif, le défensif, et le code entre les deux.',
    },
    readMore: { en: 'Read more', fr: 'Lire la suite' },
    close: { en: 'Close', fr: 'Fermer' },
    visit: { en: 'View project', fr: 'Voir le projet' },
  },
  skills: {
    title: { en: 'Skills & Arsenal', fr: 'Compétences & Arsenal' },
    lede: {
      en: 'The tools I reach for on engagements, and where I stand across the security domains.',
      fr: 'Les outils que j’utilise en mission, et mon niveau dans chaque domaine de la sécurité.',
    },
    marquee: { en: 'Tools I work with', fr: 'Les outils que j’utilise' },
    proficiency: { en: 'proficiency', fr: 'maîtrise' },
    radarHint: { en: 'Hover a domain to trace it', fr: 'Survolez un domaine pour le tracer' },
  },
  certs: {
    title: { en: 'Certifications & Achievements', fr: 'Certifications & Réalisations' },
    lede: {
      en: 'Paths completed, rankings earned, and one still in progress.',
      fr: 'Parcours terminés, classements obtenus, et un parcours encore en cours.',
    },
    inProgress: { en: 'In progress', fr: 'En cours' },
    verify: { en: 'Verify', fr: 'Vérifier' },
  },
  blog: {
    title: { en: 'From the Blog', fr: 'Depuis le Blog' },
    lede: {
      en: 'Write-ups and cheat sheets from my notes: web and API attacks, evasion, and cloud security.',
      fr: 'Write-ups et cheat sheets tirés de mes notes : attaques web et API, évasion, et sécurité cloud.',
    },
    read: { en: 'Read post', fr: 'Lire l’article' },
    all: { en: 'All posts', fr: 'Tous les articles' },
  },
  contact: {
    title: { en: 'Get In Touch', fr: 'Me Contacter' },
    lede: {
      en: 'Have a role, a project or a finding to discuss? My inbox is open.',
      fr: 'Un poste, un projet ou une vulnérabilité à discuter ? Ma boîte mail est ouverte.',
    },
    connect: { en: 'Let’s Connect', fr: 'Restons en contact' },
    emailLabel: { en: 'Email', fr: 'E-mail' },
    follow: { en: 'Find Me Online', fr: 'Me retrouver en ligne' },
    cv: { en: 'Download my CV', fr: 'Télécharger mon CV' },
    role: { en: 'Cybersecurity Engineer', fr: 'Ingénieur Cybersécurité' },
    credit: { en: 'Built with ❤ & 0s and 1s', fr: 'Construit avec ❤ & des 0 et des 1' },
  },
  menu: {
    open: { en: 'Menu', fr: 'Menu' },
    close: { en: 'Close', fr: 'Fermer' },
    socials: { en: 'Socials', fr: 'Réseaux' },
    openAria: { en: 'Open menu', fr: 'Ouvrir le menu' },
    closeAria: { en: 'Close menu', fr: 'Fermer le menu' },
    goTo: { en: 'Go to section', fr: 'Aller à la section' },
  },
} as const;
