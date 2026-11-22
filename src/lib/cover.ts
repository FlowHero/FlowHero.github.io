/**
 * Generates project card artwork as an inline SVG data URI, so every card has
 * on-theme art with zero binary assets to manage. Each motif sketches what the
 * project actually does — swap in a screenshot through a project's `image`
 * whenever there is one.
 *
 * The art is an <img>, which cannot see the page's webfonts, so its text uses
 * the platform's monospace stack. It is texture on the 350px card and only
 * becomes legible in the dialog, which is the intent.
 */
type Motif = 'pipeline' | 'map' | 'terminal' | 'code';

const W = 760;
const H = 400;
const MONO = `ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace`;

/** Small seeded PRNG (mulberry32) so a title always draws the same art. */
function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

function text(x: number, y: number, body: string, attrs = '') {
  return `<text x="${x}" y="${y}" font-family="${MONO}" ${attrs}>${body}</text>`;
}

/** Faint rows of hex, the texture every cover shares. */
function hexField(rand: () => number, accent: string) {
  const rows: string[] = [];
  for (let r = 0; r < 14; r++) {
    const bytes = Array.from({ length: 24 }, () =>
      Math.floor(rand() * 256)
        .toString(16)
        .padStart(2, '0')
    ).join(' ');
    rows.push(text(18, 26 + r * 28, bytes, `font-size="13" fill="${accent}" fill-opacity="0.07"`));
  }
  return rows.join('');
}

function windowFrame(x: number, y: number, w: number, h: number, title: string) {
  return `
  <rect x="${x}" y="${y}" width="${w}" height="${h}" rx="14" fill="#060a0e" fill-opacity="0.9" stroke="#ffffff" stroke-opacity="0.12"/>
  <path d="M${x} ${y + 36}h${w}" stroke="#ffffff" stroke-opacity="0.08"/>
  <circle cx="${x + 22}" cy="${y + 18}" r="6" fill="#ff5f57"/>
  <circle cx="${x + 42}" cy="${y + 18}" r="6" fill="#febc2e"/>
  <circle cx="${x + 62}" cy="${y + 18}" r="6" fill="#28c840"/>
  ${text(x + w / 2, y + 23, esc(title), `font-size="13" fill="#8b98a6" text-anchor="middle"`)}`;
}

function pipeline(accent: string) {
  const stages = ['commit', 'SAST', 'SCA', 'image', 'DAST', 'deploy'];
  const nodeW = 88;
  const gap = (W - 80 - stages.length * nodeW) / (stages.length - 1);
  const y = 212;
  let out = '';
  // A shield behind the line — the gate everything has to pass.
  out += `<path d="M380 54 l92 34 v70 c0 70 -50 112 -92 132 c-42 -20 -92 -62 -92 -132 v-70z" fill="${accent}" fill-opacity="0.06" stroke="${accent}" stroke-opacity="0.28" stroke-width="2"/>`;
  out += `<path d="M346 168 l24 24 l46 -50" fill="none" stroke="${accent}" stroke-opacity="0.45" stroke-width="7" stroke-linecap="round" stroke-linejoin="round"/>`;
  stages.forEach((label, i) => {
    const x = 40 + i * (nodeW + gap);
    if (i > 0) {
      const from = x - gap + 4;
      out += `<path d="M${from} ${y + 24}H${x - 8}" stroke="${accent}" stroke-opacity="0.55" stroke-width="2" stroke-dasharray="4 5"/>`;
      out += `<path d="M${x - 14} ${y + 18}l7 6l-7 6" fill="none" stroke="${accent}" stroke-opacity="0.8" stroke-width="2"/>`;
    }
    out += `<rect x="${x}" y="${y}" width="${nodeW}" height="48" rx="10" fill="#071017" stroke="${accent}" stroke-opacity="0.7" stroke-width="1.5"/>`;
    out += text(x + nodeW / 2, y + 30, esc(label), `font-size="15" fill="#e6edf3" text-anchor="middle"`);
    // Pass marker under every stage.
    out += `<circle cx="${x + nodeW / 2}" cy="${y + 78}" r="11" fill="#00f59b" fill-opacity="0.14" stroke="#00f59b" stroke-opacity="0.8"/>`;
    out += `<path d="M${x + nodeW / 2 - 5} ${y + 78}l3.5 3.5l6.5 -7" fill="none" stroke="#00f59b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>`;
  });
  out += text(40, 360, '$ trivy image app:latest  →  0 CRITICAL · 0 HIGH', `font-size="14" fill="#00f59b" fill-opacity="0.75"`);
  return out;
}

function map(accent: string, rand: () => number) {
  const cx = 500;
  const cy = 205;
  const r = 150;
  let out = '';
  // Wireframe globe: meridians as narrowing ellipses, parallels as chords.
  out += `<circle cx="${cx}" cy="${cy}" r="${r}" fill="${accent}" fill-opacity="0.04" stroke="${accent}" stroke-opacity="0.35" stroke-width="1.5"/>`;
  for (const rx of [110, 62, 18]) {
    out += `<ellipse cx="${cx}" cy="${cy}" rx="${rx}" ry="${r}" fill="none" stroke="${accent}" stroke-opacity="0.2"/>`;
  }
  for (const dy of [-100, -50, 0, 50, 100]) {
    const half = Math.sqrt(r * r - dy * dy);
    out += `<path d="M${cx - half} ${cy + dy}H${cx + half}" stroke="${accent}" stroke-opacity="0.18"/>`;
  }
  // The honeypot VM, and brute-force attempts arcing in from all over.
  const tx = cx + 34;
  const ty = cy + 18;
  for (let i = 0; i < 11; i++) {
    const a = rand() * Math.PI * 2;
    const d = 120 + rand() * 210;
    const sx = Math.max(24, Math.min(W - 24, tx + Math.cos(a) * d * 1.4));
    const sy = Math.max(24, Math.min(H - 24, ty + Math.sin(a) * d * 0.62));
    const mx = (sx + tx) / 2 + (rand() - 0.5) * 80;
    const my = Math.min(sy, ty) - 40 - rand() * 70;
    out += `<path d="M${sx.toFixed(1)} ${sy.toFixed(1)}Q${mx.toFixed(1)} ${my.toFixed(1)} ${tx} ${ty}" fill="none" stroke="#ff4d6d" stroke-opacity="${(0.35 + rand() * 0.4).toFixed(2)}" stroke-width="1.6"/>`;
    out += `<circle cx="${sx.toFixed(1)}" cy="${sy.toFixed(1)}" r="4" fill="#ff4d6d" fill-opacity="0.9"/>`;
  }
  for (const [rr, op] of [[10, 0.9], [22, 0.45], [36, 0.2]] as const) {
    out += `<circle cx="${tx}" cy="${ty}" r="${rr}" fill="none" stroke="${accent}" stroke-opacity="${op}" stroke-width="2"/>`;
  }
  out += `<circle cx="${tx}" cy="${ty}" r="5" fill="${accent}"/>`;
  out += `<rect x="34" y="282" width="238" height="86" rx="10" fill="#060a0e" fill-opacity="0.88" stroke="#ffffff" stroke-opacity="0.1"/>`;
  out += text(52, 310, 'RDP :3389', `font-size="15" fill="${accent}"`);
  out += text(52, 334, 'EventID 4625 · failed logon', `font-size="13" fill="#a9b6c3"`);
  out += text(52, 356, 'src: geo-enriched · live', `font-size="13" fill="#6f8090"`);
  return out;
}

function terminal(accent: string) {
  const x = 66;
  const y = 44;
  let out = windowFrame(x, y, 628, 312, 'recon.sh — bash');
  const lines: [string, string][] = [
    ['#00f59b', '$ ./recon.sh -d target.tld --api'],
    [accent, '[+] 142 subdomains · 37 live hosts'],
    [accent, '[+] tech: nginx · wordpress · graphql'],
    ['#fbbf24', '[*] WAF detected → bypass: ok'],
    ['#a9b6c3', '[*] fuzzing /api/v1/FUZZ  1204 req'],
    ['#ff4d6d', '[!] SQLi   ?id=   boolean-based'],
    ['#ff4d6d', '[!] XSS    ?q=    reflected'],
  ];
  lines.forEach(([color, line], i) => {
    out += text(x + 26, y + 72 + i * 31, esc(line), `font-size="16" fill="${color}"`);
  });
  out += text(x + 26, y + 72 + lines.length * 31, '$', `font-size="16" fill="#00f59b"`);
  out += `<rect x="${x + 44}" y="${y + 58 + lines.length * 31}" width="10" height="18" fill="#00f59b" fill-opacity="0.85"/>`;
  return out;
}

function code(accent: string) {
  const x = 56;
  const y = 40;
  let out = windowFrame(x, y, 560, 320, 'UserController.php');
  const rows: [string, string, string?][] = [
    ['12', '$id  = $_GET[\'id\'];'],
    ['13', '$sql = "SELECT * FROM users', 'vuln'],
    ['14', '        WHERE id = $id";', 'vuln'],
    ['15', '$res = mysqli_query($db, $sql);'],
    ['16', 'if (!$res) die(mysqli_error($db));', 'warn'],
    ['17', ''],
    ['18', '// fix: parameterised query', 'fix'],
    ['19', '$q = $db->prepare(\'... id = ?\');', 'fix'],
  ];
  rows.forEach(([n, line, kind], i) => {
    const ly = y + 70 + i * 30;
    if (kind === 'vuln') out += `<rect x="${x + 1}" y="${ly - 20}" width="558" height="29" fill="#ff4d6d" fill-opacity="0.16"/>`;
    if (kind === 'warn') out += `<rect x="${x + 1}" y="${ly - 20}" width="558" height="29" fill="#fbbf24" fill-opacity="0.1"/>`;
    out += text(x + 34, ly, n, `font-size="14" fill="#4b5966" text-anchor="end"`);
    const color = kind === 'fix' ? accent : kind === 'vuln' ? '#ffb3c1' : '#c9d4de';
    out += text(x + 50, ly, esc(line), `font-size="15" fill="${color}"`);
  });
  out += `<rect x="${x + 404}" y="${y + 56}" width="92" height="24" rx="12" fill="#ff4d6d" fill-opacity="0.22" stroke="#ff4d6d" stroke-opacity="0.7"/>`;
  out += text(x + 450, y + 73, 'CWE-89', `font-size="13" fill="#ff8fa3" text-anchor="middle"`);
  // The reviewer's lens, over the flagged lines.
  out += `<circle cx="640" cy="236" r="62" fill="${accent}" fill-opacity="0.05" stroke="${accent}" stroke-opacity="0.85" stroke-width="5"/>`;
  out += `<path d="M684 280 L726 322" stroke="${accent}" stroke-opacity="0.85" stroke-width="12" stroke-linecap="round"/>`;
  return out;
}

export function projectCover({ accent, title, motif }: { accent: string; title: string; motif: Motif }): string {
  const seed = [...title].reduce((a, c) => (a * 31 + c.charCodeAt(0)) >>> 0, 7);
  const rand = rng(seed);
  const gx = 20 + Math.floor(rand() * 60);
  const gy = 10 + Math.floor(rand() * 40);

  const art =
    motif === 'pipeline' ? pipeline(accent) : motif === 'map' ? map(accent, rand) : motif === 'terminal' ? terminal(accent) : code(accent);

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#0c141c"/>
      <stop offset="1" stop-color="#04070a"/>
    </linearGradient>
    <radialGradient id="glow" cx="${gx}%" cy="${gy}%" r="75%">
      <stop offset="0" stop-color="${accent}" stop-opacity="0.34"/>
      <stop offset="1" stop-color="${accent}" stop-opacity="0"/>
    </radialGradient>
    <pattern id="grid" width="38" height="38" patternUnits="userSpaceOnUse">
      <path d="M38 0H0v38" fill="none" stroke="#ffffff" stroke-opacity="0.045"/>
    </pattern>
    <pattern id="scan" width="4" height="4" patternUnits="userSpaceOnUse">
      <rect width="4" height="1" fill="#ffffff" fill-opacity="0.03"/>
    </pattern>
    <radialGradient id="vig" cx="50%" cy="50%" r="72%">
      <stop offset="0.55" stop-color="#000" stop-opacity="0"/>
      <stop offset="1" stop-color="#000" stop-opacity="0.55"/>
    </radialGradient>
  </defs>
  <rect width="${W}" height="${H}" fill="url(#bg)"/>
  <rect width="${W}" height="${H}" fill="url(#glow)"/>
  <rect width="${W}" height="${H}" fill="url(#grid)"/>
  ${hexField(rand, accent)}
  ${art}
  <rect width="${W}" height="${H}" fill="url(#scan)"/>
  <rect width="${W}" height="${H}" fill="url(#vig)"/>
</svg>`;

  return `data:image/svg+xml,${encodeURIComponent(svg)}`;
}
