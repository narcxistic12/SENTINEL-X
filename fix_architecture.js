const fs = require('fs');

// 1. Fix ManusHero.tsx
let heroTsx = fs.readFileSync('c:/omniroute/components/scanner/ManusHero.tsx', 'utf-8');
if (!heroTsx.includes("'use client'")) {
    heroTsx = "'use client';\n" + heroTsx;
}
heroTsx = heroTsx.replace(/import '\.\/manus-hero\.css';\n?/g, '');
fs.writeFileSync('c:/omniroute/components/scanner/ManusHero.tsx', heroTsx);

// 2. Sanitize manus-hero.css and merge into globals.css safely
let globalsCss = fs.readFileSync('c:/omniroute/app/globals.css', 'utf-8');
let manusCss = fs.readFileSync('c:/omniroute/components/scanner/manus-hero.css', 'utf-8');

let fontImport = '';
manusCss = manusCss.replace(/@import url\([^)]+\);/g, (match) => {
    fontImport = match;
    return '';
});
if (fontImport && !globalsCss.includes(fontImport)) {
    globalsCss = fontImport + '\n' + globalsCss;
}

manusCss = manusCss.replace(/@import "tailwindcss";/g, '');
manusCss = manusCss.replace(/@import "tw-animate-css";/g, '');
manusCss = manusCss.replace(/:root \{[^\}]+\}/g, (match) => {
    return match.replace(/font-family:[^;]+;/, '').replace(/color:[^;]+;/, '').replace(/background:[^;]+;/, '').replace(/font-synthesis:[^;]+;/, '');
});
manusCss = manusCss.replace(/\* \{ box-sizing: border-box; \}/g, '');
manusCss = manusCss.replace(/html \{ scroll-behavior: smooth; \}/g, '');
manusCss = manusCss.replace(/body \{ margin: 0; min-width: 320px; background: var\(--bg\); color: #e7f5f6; \}/g, '');
manusCss = manusCss.replace(/button, input \{ font: inherit; \}/g, '');
manusCss = manusCss.replace(/button \{ cursor: pointer; \}/g, '');

if (!globalsCss.includes('.sentinel-shell')) {
    globalsCss += '\n/* --- MANUS HERO STYLES --- */\n' + manusCss;
}
fs.writeFileSync('c:/omniroute/app/globals.css', globalsCss);

// 3. Re-apply Branding Cleanup
let footer = fs.readFileSync('c:/omniroute/components/layout/Footer.tsx', 'utf-8');
footer = footer.replace(
  'PHISH<span className="text-cyber-500">GUARD</span>',
  'SENTINEL<span className="text-cyber-500">X</span>'
);
footer = footer.replace(
  'Detect Phishing. Verify Before You Trust. Know Before You Click.',
  'Intelligent URL Threat Detection'
);
fs.writeFileSync('c:/omniroute/components/layout/Footer.tsx', footer);

let readme = fs.readFileSync('c:/omniroute/README.md', 'utf-8');
readme = readme.replace(
  '> **Detect Phishing. Verify Before You Trust. Know Before You Click.**',
  '> **Intelligent URL Threat Detection**'
);
fs.writeFileSync('c:/omniroute/README.md', readme);
