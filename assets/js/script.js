'use strict';

/* =========================================================
   ABAD Ayoub — Portfolio JS
   ========================================================= */

// ─── TRANSLATIONS ──────────────────────────────────────────
const t = {
  en: {
    'nav.about': 'About', 'nav.skills': 'Skills', 'nav.experience': 'Experience',
    'nav.education': 'Education', 'nav.projects': 'Projects',
    'nav.certs': 'Certs', 'nav.contact': 'Contact',

    'hero.badge': 'Open to new opportunities',
    'hero.bio': 'Cybersecurity Engineer specializing in SecOps, Penetration Testing &amp; DevSecOps.',
    'hero.tagline': 'Building defenses. Breaking assumptions.',
    'hero.cta1': 'Get in Touch', 'hero.cta2': 'View Projects',
    'hero.stat2': 'HTB Web Tester', 'hero.stat3': 'Years Exp.', 'hero.scroll': 'Scroll',

    'about.title': 'About <span class="accent">Me</span>',
    'about.p1': 'I\'m a Cybersecurity Engineer based in Morocco, currently working as a <strong class="accent">SecOps Engineer at Tessi</strong>, where I monitor and investigate security alerts across Network, SaaS, Email, and Endpoint vectors using SIEM, NDR, EDR, WAF, and IPS/IDS solutions.',
    'about.p2': 'I hold a State Engineer Diploma in Computer Security &amp; Cybersecurity from <strong class="accent">ENSA Oujda</strong> (2019–2024). My background spans offensive security (web pentesting, bug bounty), defensive security (SOC, incident response), and cloud security (DevSecOps, Kubernetes, AWS/Azure).',
    'about.p3': 'I\'m passionate about the intersection of automation and security — from building secure CI/CD pipelines to developing custom Python tooling for SOC operations and threat intelligence.',
    'about.loc.label': 'Location', 'about.loc.value': 'Oujda, Morocco',
    'about.email.label': 'Email', 'about.lang.label': 'Languages',
    'about.lang.value': 'Arabic (Native) · English (Advanced) · French (Advanced)',

    'card.off.title': 'Offensive Security', 'card.off.desc': 'Web App Pentesting, VAPT, Bug Bounty, CTF competitions',
    'card.def.title': 'Defensive / SOC', 'card.def.desc': 'SIEM operations, Incident Response, Threat Hunting, CVE management',
    'card.cloud.title': 'Cloud &amp; DevSecOps', 'card.cloud.desc': 'AWS, Azure, Kubernetes security, CI/CD pipelines, IaC scanning',
    'card.forensics.title': 'Digital Forensics', 'card.forensics.desc': 'Linux, Windows &amp; Android forensics, memory analysis',

    'skills.title': 'Technical <span class="accent">Skills</span>',
    'skill.cat.offensive': 'Offensive Security', 'skill.cat.defensive': 'Defensive / SOC',
    'skill.cat.cloud': 'Cloud &amp; DevSecOps', 'skill.cat.prog': 'Programming &amp; Scripting',
    'skill.cat.tools': 'Security Tools', 'skill.cat.compliance': 'Compliance &amp; Frameworks',
    'skill.webpentest': 'Web App Pentesting', 'skill.soc': 'SOC Operations',
    'skill.ir': 'Incident Response', 'skill.th': 'Threat Hunting',
    'skill.cve': 'CVE Management', 'skill.dfir': 'Digital Forensics',
    'skill.tm': 'Threat Modeling', 'skill.secrets': 'Secrets Management',
    'skill.monitoring': 'Monitoring &amp; Logging', 'skill.netsec': 'Network Security',

    'exp.title': 'Work <span class="accent">Experience</span>',
    'job1.role': 'SecOps Engineer', 'job1.date': 'Mar 2025 – Present', 'job1.loc': 'Oujda, Morocco · Hybrid',
    'job1.b1': 'Monitor, analyze and investigate security alerts (Network, SaaS, Email, Endpoint) via SIEM, NDR, EDR, WAF, and IPS/IDS',
    'job1.b2': 'Critical vulnerability (CVE) monitoring, exposure analysis, and remediation tracking',
    'job1.b3': 'Respond to client cybersecurity questionnaires (ISO 27001 compliance posture)',
    'job1.b4': 'Developed a Python dashboard with IRIS API for incident/alert/CVE visualization and SOC KPI tracking (MTTD, MTTR)',
    'job1.b5': 'NDR solution POC integration and evaluation in a production environment: tuning, alert triage and investigation, detection coverage validation through attack simulation, comparative analysis with the existing solution, and definition of the final decision framework.',
    'job2.role': 'Network &amp; Security Engineer', 'job2.badge': 'Internship · 6 months',
    'job2.date': 'Feb 2024 – Aug 2024', 'job2.loc': 'Casablanca, Morocco',
    'job2.b1': 'Built a secure network infrastructure connecting SG African subsidiaries to the public internet with NGFW, Proxy, and DLP layers',
    'job2.b2': 'Configured IPSec VPN tunnels for site-to-site connectivity',
    'job2.b3': 'Assisted with PCI-DSS compliance implementation',
    'job2.b4': 'Contributed to EDR and IDS/IPS solution deployment',
    'job2.b5': 'Managed HW &amp; SW obsolescence',
    'job3.role': 'Cybersecurity Engineer', 'job3.badge': 'Internship · 2 months',
    'job3.date': 'Jul 2023 – Sep 2023', 'job3.loc': 'Cork, Ireland · Remote',
    'job3.b1': 'Vulnerability Assessment and Penetration Testing (VAPT)',
    'job3.b2': 'Python development and Bash scripting for automation',
    'job3.b3': 'Docker containerization and Kubernetes security',
    'job3.b4': 'Agile methodology — GitLab workflows',

    'edu.title': 'Education',
    'edu.degree': 'State Engineer Diploma — Computer Security &amp; Cybersecurity',
    'edu.school': 'ENSA Oujda (École Nationale des Sciences Appliquées)',
    'edu.loc': 'Oujda, Morocco',
    'edu.desc': '5-year engineering program covering networks, system administration, cryptography, mobile security, ethical hacking, penetration testing, cloud computing, big data, machine learning, and security audits.',
    'edu.tag1': 'Networking', 'edu.tag2': 'Cryptography', 'edu.tag3': 'Ethical Hacking',
    'edu.tag4': 'Penetration Testing', 'edu.tag5': 'Cloud Computing',
    'edu.tag6': 'Machine Learning', 'edu.tag7': 'Security Audits',

    'proj.title': 'Recent <span class="accent">Projects</span>', 'proj.featured': 'Featured',
    'proj1.title': 'Cloud-Native DevSecOps on AWS EKS',
    'proj1.desc': 'End-to-end DevSecOps pipeline for a 3-tier application on Amazon EKS. CI/CD with Jenkins + ArgoCD + Terraform IaC. Security embedded at every stage: GitLeaks pre-commit hooks, SAST tools, OWASP DependencyCheck (SCA), OWASP ZAP (DAST), Trivy for containers/Kubernetes/IaC, SonarQube for code quality, Vault for secrets, Prometheus &amp; Grafana for monitoring, and EFK for centralized logging.',
    'proj2.title': 'RDP Brute-Force Map — Azure Sentinel',
    'proj2.desc': 'Real-time global threat map tracking RDP brute-force attacks using Azure Sentinel SIEM. A custom PowerShell script extracts event metadata from Windows Event Viewer and enriches it via geolocation API. Azure Log Analytics ingests custom logs; a Sentinel workbook visualizes global attacks by location and intensity.',
    'proj3.title': 'Web &amp; API Pentest Automation',
    'proj3.desc': 'Suite of Bash scripts automating repetitive pentesting and bug bounty tasks: recon, WAF detection &amp; bypass, technology fingerprinting (WordPress, GraphQL), fuzzing, spidering, secrets scanning, and comprehensive vulnerability testing (LFI, SQLi, XSS).',
    'proj4.title': 'Web App Source Code Security Audit',
    'proj4.desc': 'In-depth source code analysis of PHP and Node.js applications to identify critical vulnerabilities — input validation flaws, authentication weaknesses, error handling issues, and business logic bugs. Proposed concrete remediations including secure coding practices, input validation, and regular audits.',

    'cert.title': 'Achievements &amp; <span class="accent">Certifications</span>',
    'cert1.desc': 'Web Fundamentals · Pre-Security · Jr. Pentester · Pentest+ · Cyber Defense',
    'cert2.title': 'HackTheBox — Senior Web Penetration Tester', 'cert2.desc': 'Offensive Web Security Track',
    'cert3.title': 'HackTheBox — SOC Analyst', 'cert3.desc': 'Blue Team Operations Track',
    'cert4.title': 'Azure Security Engineer (AZ-500)', 'cert4.desc': 'CloudGuru · Microsoft Azure Security',
    'cert5.title': 'AWS Cloud Practitioner + Security Fundamentals', 'cert5.desc': 'CloudGuru · Amazon Web Services',
    'cert6.title': 'CTF Competition — 3rd Place', 'cert6.desc': 'University CTF · Competitive Hacking',

    'contact.title': 'Get In <span class="accent">Touch</span>',
    'contact.intro': 'I\'m open to new opportunities, collaborations, or just a good conversation about cybersecurity. Whether you have a project in mind or want to discuss the latest in threat intelligence — feel free to reach out.',
    'contact.email.label': 'Email', 'contact.thm.value': 'Top 1% Rank',
    'contact.cta': 'Send a Message',
    'footer.copy': '&copy; 2025 ABAD Ayoub &middot; Cybersecurity Engineer',
    'footer.credit': 'Built with <span class="accent">&#10084;</span> &amp; 0s and 1s',
  },

  fr: {
    'nav.about': 'À propos', 'nav.skills': 'Compétences', 'nav.experience': 'Expérience',
    'nav.education': 'Formation', 'nav.projects': 'Projets',
    'nav.certs': 'Certifs', 'nav.contact': 'Contact',

    'hero.badge': 'Ouvert aux nouvelles opportunités',
    'hero.bio': 'Ingénieur Cybersécurité spécialisé en SecOps, Tests d\'Intrusion &amp; DevSecOps.',
    'hero.tagline': 'Construire des défenses. Briser les certitudes.',
    'hero.cta1': 'Me Contacter', 'hero.cta2': 'Voir les Projets',
    'hero.stat2': 'HTB Web Tester', 'hero.stat3': 'Ans d\'Exp.', 'hero.scroll': 'Défiler',

    'about.title': 'À propos <span class="accent">de Moi</span>',
    'about.p1': 'Je suis Ingénieur Cybersécurité basé au Maroc, actuellement en poste en tant qu\'<strong class="accent">Ingénieur SecOps chez Tessi</strong>, où je surveille et investigate les alertes de sécurité (Réseau, SaaS, Email, Endpoint) via les solutions SIEM, NDR, EDR, WAF et IPS/IDS.',
    'about.p2': 'Je suis titulaire d\'un Diplôme d\'Ingénieur d\'État en Sécurité Informatique &amp; Cybersécurité de l\'<strong class="accent">ENSA Oujda</strong> (2019–2024). Mon profil couvre la sécurité offensive (pentest web, bug bounty), la sécurité défensive (SOC, réponse aux incidents) et la sécurité cloud (DevSecOps, Kubernetes, AWS/Azure).',
    'about.p3': 'Ce qui m\'anime, c\'est la dualité offensif/défensif — comprendre les techniques d\'attaque pour construire de meilleures défenses. Du pentest à la réponse aux incidents, j\'aime opérer des deux côtés.',
    'about.loc.label': 'Localisation', 'about.loc.value': 'Oujda, Maroc',
    'about.email.label': 'E-mail', 'about.lang.label': 'Langues',
    'about.lang.value': 'Arabe (Natif) · Anglais (Avancé) · Français (Avancé)',

    'card.off.title': 'Sécurité Offensive', 'card.off.desc': 'Tests d\'intrusion Web, VAPT, Bug Bounty, Compétitions CTF',
    'card.def.title': 'Défensif / SOC', 'card.def.desc': 'Opérations SIEM, Réponse aux incidents, Threat Hunting, Gestion des CVE',
    'card.cloud.title': 'Cloud &amp; DevSecOps', 'card.cloud.desc': 'Sécurité AWS, Azure, Kubernetes, Pipelines CI/CD, Scan IaC',
    'card.forensics.title': 'Forensique Numérique', 'card.forensics.desc': 'Forensique Linux, Windows &amp; Android, analyse mémoire',

    'skills.title': 'Compétences <span class="accent">Techniques</span>',
    'skill.cat.offensive': 'Sécurité Offensive', 'skill.cat.defensive': 'Défensif / SOC',
    'skill.cat.cloud': 'Cloud &amp; DevSecOps', 'skill.cat.prog': 'Programmation &amp; Scripting',
    'skill.cat.tools': 'Outils de Sécurité', 'skill.cat.compliance': 'Conformité &amp; Frameworks',
    'skill.webpentest': 'Pentest Applications Web', 'skill.soc': 'Opérations SOC',
    'skill.ir': 'Réponse aux Incidents', 'skill.th': 'Threat Hunting',
    'skill.cve': 'Gestion des CVE', 'skill.dfir': 'Forensique Numérique',
    'skill.tm': 'Modélisation des Menaces', 'skill.secrets': 'Gestion des Secrets',
    'skill.monitoring': 'Supervision &amp; Journalisation', 'skill.netsec': 'Sécurité Réseau',

    'exp.title': 'Expérience <span class="accent">Professionnelle</span>',
    'job1.role': 'Ingénieur SecOps', 'job1.date': 'Mar 2025 – Présent', 'job1.loc': 'Oujda, Maroc · Hybride',
    'job1.b1': 'Surveillance, analyse et investigation des alertes de sécurité (Réseau, SaaS, Email, Endpoint) via les solutions SIEM, NDR, EDR, WAF et IPS/IDS',
    'job1.b2': 'Veille sur les vulnérabilités critiques (CVE), investigation, analyse d\'exposition et suivi des remédiations',
    'job1.b3': 'Réponse aux questionnaires de cybersécurité des clients (posture sécurité, conformité ISO 27001)',
    'job1.b4': 'Développement d\'un dashboard Python interfacé avec l\'API IRIS pour la visualisation des incidents, alertes et CVEs, avec suivi des KPIs SOC (MTTD, MTTR)',
    'job1.b5': 'Intégration et évaluation POC d\'une solution NDR en environnement de production : tuning, triage et investigation des alertes, validation de la couverture de détection par simulation d\'attaques, analyse comparative avec la solution existante et définition du cadre de décision final.',
    'job2.role': 'Ingénieur Réseaux &amp; Sécurité', 'job2.badge': 'Stage PFE · 6 mois',
    'job2.date': 'Fév 2024 – Août 2024', 'job2.loc': 'Casablanca, Maroc',
    'job2.b1': 'Construction d\'une infrastructure réseau sécurisée reliant les filiales africaines de SG à l\'internet public, avec couches NGFW, Proxy et DLP',
    'job2.b2': 'Configuration des tunnels IPSec VPN pour la connectivité site-à-site',
    'job2.b3': 'Assistance à la mise en conformité PCI-DSS',
    'job2.b4': 'Contribution à l\'implémentation et au déploiement de solutions EDR et IDS/IPS',
    'job2.b5': 'Gestion de l\'obsolescence matérielle &amp; logicielle',
    'job3.role': 'Ingénieur Cybersécurité', 'job3.badge': 'Stage · 2 mois',
    'job3.date': 'Juil 2023 – Sep 2023', 'job3.loc': 'Cork, Irlande · À distance',
    'job3.b1': 'Évaluation des vulnérabilités et tests de pénétration (VAPT)',
    'job3.b2': 'Développement Python et scripts Bash pour l\'automatisation',
    'job3.b3': 'Conteneurisation Docker et sécurité Kubernetes',
    'job3.b4': 'Méthodologie Agile — Workflows GitLab',

    'edu.title': 'Formation',
    'edu.degree': 'Diplôme d\'Ingénieur d\'État — Sécurité Informatique &amp; Cybersécurité',
    'edu.school': 'ENSA Oujda (École Nationale des Sciences Appliquées)',
    'edu.loc': 'Oujda, Maroc',
    'edu.desc': 'Formation d\'ingénieur de 5 ans couvrant les réseaux, l\'administration système, la cryptographie, la sécurité mobile, le hacking éthique, les tests d\'intrusion, le cloud computing, le big data, le machine learning et les audits de sécurité.',
    'edu.tag1': 'Réseaux', 'edu.tag2': 'Cryptographie', 'edu.tag3': 'Hacking Éthique',
    'edu.tag4': 'Tests d\'Intrusion', 'edu.tag5': 'Cloud Computing',
    'edu.tag6': 'Machine Learning', 'edu.tag7': 'Audits de Sécurité',

    'proj.title': 'Projets <span class="accent">Récents</span>', 'proj.featured': 'À la une',
    'proj1.title': 'DevSecOps Cloud-Native sur AWS EKS',
    'proj1.desc': 'Pipeline DevSecOps bout-en-bout pour une application 3-tiers sur Amazon EKS. CI/CD avec Jenkins + ArgoCD + Terraform IaC. Sécurité intégrée à chaque étape : hooks pre-commit GitLeaks, outils SAST, OWASP DependencyCheck (SCA), OWASP ZAP (DAST), Trivy pour conteneurs/Kubernetes/IaC, SonarQube pour la qualité du code, Vault pour les secrets, Prometheus &amp; Grafana pour la supervision, et EFK pour la journalisation.',
    'proj2.title': 'Carte d\'Attaques RDP — Azure Sentinel',
    'proj2.desc': 'Carte de menaces mondiale en temps réel pour le suivi des attaques RDP par force brute via Azure Sentinel SIEM. Un script PowerShell personnalisé extrait les métadonnées d\'événements Windows et les enrichit via une API de géolocalisation. Azure Log Analytics ingère les journaux ; un classeur Sentinel visualise les attaques globales par localisation et intensité.',
    'proj3.title': 'Automatisation de Pentest Web &amp; API',
    'proj3.desc': 'Suite de scripts Bash automatisant les tâches répétitives de pentest et de bug bounty : reconnaissance, détection &amp; contournement de WAF, fingerprinting technologique (WordPress, GraphQL), fuzzing, spidering, scan de secrets et tests de vulnérabilités complets (LFI, SQLi, XSS).',
    'proj4.title': 'Audit de Sécurité du Code Source',
    'proj4.desc': 'Analyse approfondie du code source d\'applications PHP et Node.js pour identifier les vulnérabilités critiques : failles de validation des entrées, faiblesses d\'authentification, problèmes de gestion des erreurs et bugs de logique métier. Propositions de remédiation incluant les bonnes pratiques de codage sécurisé, la validation des entrées et des audits réguliers.',

    'cert.title': 'Réalisations &amp; <span class="accent">Certifications</span>',
    'cert1.desc': 'Web Fundamentals · Pre-Security · Jr. Pentester · Pentest+ · Cyber Defense',
    'cert2.title': 'HackTheBox — Testeur d\'Intrusion Web Senior', 'cert2.desc': 'Parcours Sécurité Offensive Web',
    'cert3.title': 'HackTheBox — Analyste SOC', 'cert3.desc': 'Parcours Opérations Blue Team',
    'cert4.title': 'Ingénieur Sécurité Azure (AZ-500)', 'cert4.desc': 'CloudGuru · Sécurité Microsoft Azure',
    'cert5.title': 'AWS Cloud Practitioner + Security Fundamentals', 'cert5.desc': 'CloudGuru · Amazon Web Services',
    'cert6.title': 'Compétition CTF — 3ème Place', 'cert6.desc': 'CTF Universitaire · Hacking Compétitif',

    'contact.title': 'Me <span class="accent">Contacter</span>',
    'contact.intro': 'Je suis ouvert aux nouvelles opportunités, collaborations ou simplement une bonne conversation sur la cybersécurité. Que vous ayez un projet en tête ou souhaitiez discuter des dernières menaces — n\'hésitez pas à me contacter.',
    'contact.email.label': 'E-mail', 'contact.thm.value': 'Rang Top 1%',
    'contact.cta': 'Envoyer un Message',
    'footer.copy': '&copy; 2025 ABAD Ayoub &middot; Ingénieur Cybersécurité',
    'footer.credit': 'Construit avec <span class="accent">&#10084;</span> &amp; des 0 et des 1',
  }
};

const typingRoles = {
  en: ['Cybersecurity Engineer', 'SecOps Analyst', 'Penetration Tester', 'DevSecOps Engineer', 'Bug Hunter'],
  fr: ['Ingénieur Cybersécurité', 'Analyste SecOps', 'Testeur d\'Intrusion', 'Ingénieur DevSecOps', 'Bug Hunter'],
};

let currentLang = localStorage.getItem('lang') || 'en';

function applyLang(lang) {
  currentLang = lang;
  localStorage.setItem('lang', lang);
  document.documentElement.lang = lang;

  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.dataset.i18n;
    if (t[lang][key] !== undefined) el.innerHTML = t[lang][key];
  });

  document.querySelectorAll('.lang-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.lang === lang);
  });
}


// ─── PARTICLES CANVAS ──────────────────────────────────────
(function () {
  const canvas = document.getElementById('particles-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  let particles = [], raf, W, H;

  function resize() { W = canvas.width = window.innerWidth; H = canvas.height = window.innerHeight; }

  function make() {
    particles = [];
    const n = Math.min(Math.floor((W * H) / 12000), 90);
    for (let i = 0; i < n; i++) {
      particles.push({ x: Math.random()*W, y: Math.random()*H,
        vx: (Math.random()-0.5)*0.35, vy: (Math.random()-0.5)*0.35,
        r: Math.random()*1.4+0.4, a: Math.random()*0.45+0.08 });
    }
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);
    for (let x = 0; x < W; x += 42)
      for (let y = 0; y < H; y += 42) {
        ctx.beginPath(); ctx.arc(x, y, 0.7, 0, Math.PI*2);
        ctx.fillStyle = 'rgba(0,212,255,0.04)'; ctx.fill();
      }
    for (const p of particles) {
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0) p.x = W; if (p.x > W) p.x = 0;
      if (p.y < 0) p.y = H; if (p.y > H) p.y = 0;
      ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI*2);
      ctx.fillStyle = `rgba(0,212,255,${p.a})`; ctx.fill();
    }
    for (let i = 0; i < particles.length; i++)
      for (let j = i+1; j < particles.length; j++) {
        const dx = particles[i].x-particles[j].x, dy = particles[i].y-particles[j].y;
        const d = Math.sqrt(dx*dx+dy*dy);
        if (d < 110) {
          ctx.beginPath(); ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.strokeStyle = `rgba(0,212,255,${0.06*(1-d/110)})`; ctx.lineWidth = 0.6; ctx.stroke();
        }
      }
    raf = requestAnimationFrame(draw);
  }

  resize(); make(); draw();
  let timer;
  window.addEventListener('resize', () => {
    clearTimeout(timer); timer = setTimeout(() => { cancelAnimationFrame(raf); resize(); make(); draw(); }, 150);
  });
}());


// ─── TYPING ANIMATION ──────────────────────────────────────
(function () {
  const el = document.getElementById('typing-text');
  if (!el) return;
  let ri = 0, ci = 0, deleting = false;

  function tick() {
    const roles = typingRoles[currentLang];
    const word = roles[ri % roles.length];
    if (!deleting) {
      el.textContent = word.slice(0, ++ci);
      if (ci === word.length) { deleting = true; setTimeout(tick, 2200); return; }
    } else {
      el.textContent = word.slice(0, --ci);
      if (ci === 0) { deleting = false; ri = (ri + 1) % roles.length; }
    }
    setTimeout(tick, deleting ? 45 : 90);
  }
  setTimeout(tick, 800);
}());


// ─── LANGUAGE TOGGLE ───────────────────────────────────────
document.querySelectorAll('.lang-btn').forEach(btn => {
  btn.addEventListener('click', () => applyLang(btn.dataset.lang));
});
applyLang(currentLang);


// ─── NAVBAR SCROLL ─────────────────────────────────────────
(function () {
  const nav = document.getElementById('navbar');
  if (!nav) return;
  window.addEventListener('scroll', () => nav.classList.toggle('scrolled', window.scrollY > 40), { passive: true });
}());


// ─── MOBILE MENU ───────────────────────────────────────────
(function () {
  const toggle = document.getElementById('nav-toggle');
  const menu   = document.getElementById('mobile-menu');
  if (!toggle || !menu) return;
  toggle.addEventListener('click', () => { toggle.classList.toggle('open'); menu.classList.toggle('open'); });
  menu.querySelectorAll('a').forEach(a => a.addEventListener('click', () => {
    toggle.classList.remove('open'); menu.classList.remove('open');
  }));
}());


// ─── ACTIVE NAV LINK ───────────────────────────────────────
(function () {
  const sections = document.querySelectorAll('section[id]');
  const links    = document.querySelectorAll('.nav-links a, .mobile-menu a');
  if (!sections.length) return;
  const io = new IntersectionObserver(entries => {
    for (const e of entries)
      if (e.isIntersecting)
        links.forEach(a => a.classList.toggle('active', a.getAttribute('href') === `#${e.target.id}`));
  }, { rootMargin: '-50% 0px -50% 0px' });
  sections.forEach(s => io.observe(s));
}());


// ─── SCROLL REVEAL ─────────────────────────────────────────
(function () {
  const els = document.querySelectorAll('.reveal');
  if (!els.length) return;
  const io = new IntersectionObserver(entries => {
    entries.forEach(e => {
      if (!e.isIntersecting) return;
      const siblings = Array.from(e.target.parentElement.querySelectorAll('.reveal'));
      e.target.style.transitionDelay = `${siblings.indexOf(e.target) * 0.07}s`;
      e.target.classList.add('visible');
      io.unobserve(e.target);
    });
  }, { threshold: 0.08, rootMargin: '0px 0px -36px 0px' });
  els.forEach(el => io.observe(el));
}());


// ─── SKILL LEVEL BARS ──────────────────────────────────────
(function () {
  const levels = document.querySelectorAll('.skill-level');
  if (!levels.length) return;
  const io = new IntersectionObserver(entries => {
    entries.forEach(e => {
      if (!e.isIntersecting) return;
      const lvl = e.target;
      const bar = lvl.querySelector('.sl-bar');
      if (bar) {
        setTimeout(() => {
          bar.style.width = lvl.dataset.slLevel + '%';
          lvl.classList.add('sl-done');
        }, 80);
      }
      io.unobserve(lvl);
    });
  }, { threshold: 0.3 });
  levels.forEach(l => io.observe(l));
}());


// ─── RADAR CHART ───────────────────────────────────────────
(function () {
  const canvas = document.getElementById('skillsRadar');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  const data = [
    { label: 'Offensive',  value: 87, color: '#ff4d6d' },
    { label: 'Defensive',  value: 85, color: '#00d4ff' },
    { label: 'Cloud',      value: 66, color: '#8b5cf6' },
    { label: 'Scripting',  value: 76, color: '#00e676' },
    { label: 'Tools',      value: 83, color: '#fbbf24' },
    { label: 'Compliance', value: 55, color: '#94a3b8' },
  ];

  const N = data.length;
  let progress = 0, started = false, sz = 0;
  let highlighted = -1;
  let pulseT = 0, pulseRaf = null;

  function setup() {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    sz = canvas.offsetWidth;
    if (!sz) return;
    canvas.width  = sz * dpr;
    canvas.height = sz * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function pt(i, r) {
    const a  = (i / N) * Math.PI * 2 - Math.PI / 2;
    const cx = sz / 2, R = sz * 0.26;
    return { x: cx + r * R * Math.cos(a), y: cx + r * R * Math.sin(a), a };
  }

  function draw(prog) {
    if (!sz) return;
    const cx = sz / 2, R = sz * 0.26, lR = R * 1.3;
    ctx.clearRect(0, 0, sz, sz);

    // Grid rings
    [0.2, 0.4, 0.6, 0.8, 1].forEach((t, idx) => {
      ctx.beginPath();
      for (let i = 0; i < N; i++) {
        const p = pt(i, t);
        i === 0 ? ctx.moveTo(p.x, p.y) : ctx.lineTo(p.x, p.y);
      }
      ctx.closePath();
      ctx.strokeStyle = idx === 4 ? 'rgba(255,255,255,0.1)' : 'rgba(255,255,255,0.04)';
      ctx.lineWidth = 0.8;
      ctx.stroke();
    });

    // Axis lines
    for (let i = 0; i < N; i++) {
      const p = pt(i, 1);
      const isHl = i === highlighted;
      ctx.beginPath(); ctx.moveTo(cx, cx); ctx.lineTo(p.x, p.y);
      ctx.strokeStyle = isHl
        ? data[i].color.replace(')', ',0.4)').replace('rgb', 'rgba')
        : 'rgba(255,255,255,0.06)';
      ctx.lineWidth = isHl ? 1.5 : 0.8;
      ctx.stroke();
    }

    // Filled polygon — dim when highlighting
    ctx.beginPath();
    for (let i = 0; i < N; i++) {
      const p = pt(i, (data[i].value / 100) * prog);
      i === 0 ? ctx.moveTo(p.x, p.y) : ctx.lineTo(p.x, p.y);
    }
    ctx.closePath();
    const g = ctx.createRadialGradient(cx, cx, 0, cx, cx, R);
    const alpha = highlighted >= 0 ? 0.13 : 0.28;
    g.addColorStop(0,   `rgba(0,212,255,${alpha})`);
    g.addColorStop(0.6, `rgba(139,92,246,${alpha * 0.5})`);
    g.addColorStop(1,   'rgba(0,212,255,0.02)');
    ctx.fillStyle = g;
    ctx.fill();
    ctx.strokeStyle = highlighted >= 0 ? 'rgba(0,212,255,0.3)' : 'rgba(0,212,255,0.8)';
    ctx.lineWidth = 1.5;
    ctx.shadowColor = '#00d4ff';
    ctx.shadowBlur = highlighted >= 0 ? 4 : 10;
    ctx.stroke();
    ctx.shadowBlur = 0;

    // Dots — dim non-highlighted
    for (let i = 0; i < N; i++) {
      const p = pt(i, (data[i].value / 100) * prog);
      const isHl = i === highlighted;
      const r = isHl ? sz * 0.022 : sz * 0.013;
      ctx.beginPath(); ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
      ctx.fillStyle = isHl ? data[i].color : (highlighted >= 0 ? data[i].color + '55' : data[i].color);
      ctx.shadowColor = data[i].color;
      ctx.shadowBlur = isHl ? 16 : (highlighted >= 0 ? 3 : 9);
      ctx.fill();
      ctx.shadowBlur = 0;
    }

    // Highlighted axis: glowing arm + pulse ring + value label
    if (highlighted >= 0) {
      const hi = highlighted;
      const hp = pt(hi, (data[hi].value / 100) * prog);

      // Glowing arm from center
      ctx.beginPath();
      ctx.moveTo(cx, cx);
      ctx.lineTo(hp.x, hp.y);
      ctx.strokeStyle = data[hi].color;
      ctx.lineWidth = 1.5;
      ctx.shadowColor = data[hi].color;
      ctx.shadowBlur = 12;
      ctx.setLineDash([4, 3]);
      ctx.stroke();
      ctx.setLineDash([]);
      ctx.shadowBlur = 0;

      // Pulse ring
      const pulse = 0.5 + 0.5 * Math.sin(pulseT * 3);
      const ringR = sz * 0.03 + pulse * sz * 0.018;
      ctx.beginPath();
      ctx.arc(hp.x, hp.y, ringR, 0, Math.PI * 2);
      ctx.strokeStyle = data[hi].color;
      ctx.globalAlpha = 0.3 * (1 - pulse * 0.6);
      ctx.lineWidth = 1.5;
      ctx.stroke();
      ctx.globalAlpha = 1;

      // Value label near dot
      const angle = (hi / N) * Math.PI * 2 - Math.PI / 2;
      const offX = Math.cos(angle) * sz * 0.07;
      const offY = Math.sin(angle) * sz * 0.07;
      ctx.font = `700 ${sz * 0.042}px 'JetBrains Mono', monospace`;
      ctx.fillStyle = '#fff';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.shadowColor = data[hi].color;
      ctx.shadowBlur = 8;
      ctx.fillText(data[hi].value + '%', hp.x + offX, hp.y + offY);
      ctx.shadowBlur = 0;
    }

    // Labels
    for (let i = 0; i < N; i++) {
      const a  = (i / N) * Math.PI * 2 - Math.PI / 2;
      const lx = cx + lR * Math.cos(a);
      const ly = cx + lR * Math.sin(a);
      ctx.textAlign    = Math.abs(Math.cos(a)) < 0.15 ? 'center' : Math.cos(a) > 0 ? 'left' : 'right';
      ctx.textBaseline = Math.sin(a) < -0.6 ? 'bottom' : Math.sin(a) > 0.6 ? 'top' : 'middle';
      ctx.font         = `${i === highlighted ? 700 : 600} ${i === highlighted ? sz * 0.032 : sz * 0.027}px Inter, sans-serif`;
      ctx.fillStyle    = i === highlighted ? '#fff' : (highlighted >= 0 ? data[i].color + '66' : data[i].color);
      if (i === highlighted) {
        ctx.shadowColor = data[i].color;
        ctx.shadowBlur = 10;
      }
      ctx.fillText(data[i].label, lx, ly);
      ctx.shadowBlur = 0;
    }
  }

  function animate() {
    progress = Math.min(progress + 0.022, 1);
    draw(progress);
    if (progress < 1) requestAnimationFrame(animate);
  }

  function pulseLoop() {
    if (highlighted < 0) { pulseRaf = null; return; }
    pulseT += 0.03;
    draw(progress);
    pulseRaf = requestAnimationFrame(pulseLoop);
  }

  // Public API
  window.radarHighlight = function(idx) {
    highlighted = idx;
    // Update tooltip
    const tooltip = document.getElementById('sm-radar-tooltip');
    if (tooltip) {
      if (idx >= 0) {
        const hex = data[idx].color;
        tooltip.innerHTML = `<strong style="color:${hex}">${data[idx].label}</strong> &mdash; <span style="color:${hex}">${data[idx].value}%</span> proficiency`;
      } else {
        tooltip.innerHTML = '&nbsp;';
      }
    }
    // Update legend items
    document.querySelectorAll('.sm-rl-item').forEach((el, i) => {
      el.classList.toggle('sm-rl-active', i === idx);
    });
    // Start pulse loop
    if (idx >= 0 && !pulseRaf) pulseLoop();
    else if (idx < 0) draw(progress);
  };

  const io = new IntersectionObserver(([e]) => {
    if (e.isIntersecting && !started) {
      started = true; setup(); animate(); io.disconnect();
    }
  }, { threshold: 0.3 });
  io.observe(canvas);

  let resizeT;
  window.addEventListener('resize', () => {
    clearTimeout(resizeT);
    resizeT = setTimeout(() => { setup(); draw(progress); }, 150);
  });
}());


// // ─── SKILLS MATRIX BARS ──────────────────────────────────────────────────
(function () {
  const cards = document.querySelectorAll('.sm-card');
  if (!cards.length) return;
  const io = new IntersectionObserver(entries => {
    entries.forEach(e => {
      if (!e.isIntersecting) return;
      const bar = e.target.querySelector('.sm-bar');
      const pct = e.target.dataset.smPct;
      if (bar && pct) setTimeout(() => { bar.style.width = pct + '%'; }, 120);
      io.unobserve(e.target);
    });
  }, { threshold: 0.25 });

  cards.forEach(c => {
    io.observe(c);

    // Mouse glow tracking
    c.addEventListener('mousemove', e => {
      const r = c.getBoundingClientRect();
      c.style.setProperty('--mx', ((e.clientX - r.left) / r.width  * 100).toFixed(1) + '%');
      c.style.setProperty('--my', ((e.clientY - r.top)  / r.height * 100).toFixed(1) + '%');
    });

    // Radar interactivity
    c.addEventListener('mouseenter', () => {
      const idx = parseInt(c.dataset.skillIndex);
      if (!isNaN(idx) && window.radarHighlight) window.radarHighlight(idx);
      c.classList.add('sm-active');
    });
    c.addEventListener('mouseleave', () => {
      if (window.radarHighlight) window.radarHighlight(-1);
      c.classList.remove('sm-active');
    });
  });

  // Legend items also trigger highlight
  document.querySelectorAll('.sm-rl-item[data-skill-index]').forEach(el => {
    const idx = parseInt(el.dataset.skillIndex);
    el.addEventListener('mouseenter', () => {
      if (window.radarHighlight) window.radarHighlight(idx);
      // Also activate the matching card
      cards.forEach(c => c.classList.toggle('sm-active', parseInt(c.dataset.skillIndex) === idx));
    });
    el.addEventListener('mouseleave', () => {
      if (window.radarHighlight) window.radarHighlight(-1);
      cards.forEach(c => c.classList.remove('sm-active'));
    });
  });
}());


// ─── SMOOTH ANCHOR SCROLL ──────────────────────────────────
document.querySelectorAll('a[href^="#"]').forEach(a => {
  a.addEventListener('click', function (e) {
    const target = document.querySelector(this.getAttribute('href'));
    if (!target) return;
    e.preventDefault();
    const offset = document.getElementById('navbar').offsetHeight;
    window.scrollTo({ top: target.getBoundingClientRect().top + window.scrollY - offset, behavior: 'smooth' });
  });
});
