const fs = require('fs');
let page = fs.readFileSync('c:/omniroute/app/page.tsx', 'utf-8');
page = page.replace(
  "import { ManusHero } from '@/components/scanner/ManusHero';",
  "import dynamic from 'next/dynamic';\nconst ManusHero = dynamic(() => import('@/components/scanner/ManusHero').then((mod) => mod.ManusHero), { ssr: false });"
);
fs.writeFileSync('c:/omniroute/app/page.tsx', page);
