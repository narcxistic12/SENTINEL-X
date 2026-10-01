const fs = require('fs');

// 1. Restore Footer.tsx
let footer = fs.readFileSync('c:/omniroute/components/layout/Footer.tsx', 'utf-8');
footer = footer.replace(
  'SENTINEL<span className="text-cyber-500">X</span>',
  'PHISH<span className="text-cyber-500">GUARD</span>'
);
footer = footer.replace(
  'Intelligent URL Threat Detection',
  'Detect Phishing. Verify Before You Trust. Know Before You Click.'
);
fs.writeFileSync('c:/omniroute/components/layout/Footer.tsx', footer);

// 2. Restore README.md
let readme = fs.readFileSync('c:/omniroute/README.md', 'utf-8');
readme = readme.replace(
  '> **Intelligent URL Threat Detection**',
  '> **Detect Phishing. Verify Before You Trust. Know Before You Click.**'
);
fs.writeFileSync('c:/omniroute/README.md', readme);

// 3. Restore app/globals.css
let globals = fs.readFileSync('c:/omniroute/app/globals.css', 'utf-8');
globals = globals.replace(/@import url\('https:\/\/fonts.googleapis.com[^;]+;\n/, '');
const parts = globals.split('\n/* --- MANUS HERO STYLES --- */\n');
globals = parts[0];
fs.writeFileSync('c:/omniroute/app/globals.css', globals);

// 4. Restore ManusHero.tsx
let hero = fs.readFileSync('c:/omniroute/components/scanner/ManusHero.tsx', 'utf-8');
hero = hero.replace("'use client';\n", '');
hero = hero.replace(
  "import { ArrowDownRight, ChevronRight, LockKeyhole, Terminal } from 'lucide-react';",
  "import { ArrowDownRight, ChevronRight, LockKeyhole, Terminal } from 'lucide-react';\nimport './manus-hero.css';"
);
fs.writeFileSync('c:/omniroute/components/scanner/ManusHero.tsx', hero);

// 5. Restore manus-hero.css from hero page/index.css
fs.copyFileSync('c:/omniroute/hero page/index.css', 'c:/omniroute/components/scanner/manus-hero.css');
