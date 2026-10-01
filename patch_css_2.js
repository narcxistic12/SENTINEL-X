const fs = require('fs');

let globalsCss = fs.readFileSync('c:/omniroute/app/globals.css', 'utf-8');
let manusCss = fs.readFileSync('c:/omniroute/components/scanner/manus-hero.css', 'utf-8');

// Remove the import from globals.css
globalsCss = globalsCss.replace('@import "../components/scanner/manus-hero.css";', '');

// Extract the font import
let fontImport = '';
manusCss = manusCss.replace(/@import url\([^)]+\);/g, (match) => {
  fontImport = match;
  return '';
});

// Put font import at the very top of globals.css if not there
if (fontImport && !globalsCss.includes(fontImport)) {
  globalsCss = fontImport + '\n' + globalsCss;
}

// Append the rest of manusCss to the end of globals.css
if (!globalsCss.includes('.sentinel-shell')) {
  globalsCss += '\n/* --- MANUS HERO STYLES --- */\n' + manusCss;
}

fs.writeFileSync('c:/omniroute/app/globals.css', globalsCss);
