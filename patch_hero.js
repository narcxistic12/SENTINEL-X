const fs = require('fs');
let content = fs.readFileSync('c:/omniroute/components/scanner/ManusHero.tsx', 'utf-8');
if (!content.includes("'use client'")) {
  content = "'use client';\n" + content;
  fs.writeFileSync('c:/omniroute/components/scanner/ManusHero.tsx', content);
}
