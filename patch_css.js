const fs = require('fs');

// 1. Remove import from ManusHero.tsx
let heroTsx = fs.readFileSync('c:/omniroute/components/scanner/ManusHero.tsx', 'utf-8');
heroTsx = heroTsx.replace(/import '\.\/manus-hero\.css';\n?/g, '');
fs.writeFileSync('c:/omniroute/components/scanner/ManusHero.tsx', heroTsx);

// 2. Add import to app/globals.css
let globalsCss = fs.readFileSync('c:/omniroute/app/globals.css', 'utf-8');
if (!globalsCss.includes('manus-hero.css')) {
  globalsCss = globalsCss.replace('@tailwind utilities;', '@tailwind utilities;\n\n@import "../components/scanner/manus-hero.css";');
  fs.writeFileSync('c:/omniroute/app/globals.css', globalsCss);
}

// 3. Clean up manus-hero.css
let manusCss = fs.readFileSync('c:/omniroute/components/scanner/manus-hero.css', 'utf-8');
manusCss = manusCss.replace(/:root \{[^\}]+\}/g, (match) => {
  return match.replace(/font-family:[^;]+;/, '').replace(/color:[^;]+;/, '').replace(/background:[^;]+;/, '').replace(/font-synthesis:[^;]+;/, '');
});
manusCss = manusCss.replace(/\* \{ box-sizing: border-box; \}/g, '');
manusCss = manusCss.replace(/html \{ scroll-behavior: smooth; \}/g, '');
manusCss = manusCss.replace(/body \{ margin: 0; min-width: 320px; background: var\(--bg\); color: #e7f5f6; \}/g, '');
manusCss = manusCss.replace(/button, input \{ font: inherit; \}/g, '');
manusCss = manusCss.replace(/button \{ cursor: pointer; \}/g, '');

fs.writeFileSync('c:/omniroute/components/scanner/manus-hero.css', manusCss);
