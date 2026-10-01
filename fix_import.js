const fs = require('fs');
let css = fs.readFileSync('c:/omniroute/components/scanner/manus-hero.css', 'utf-8');
css = css.replace(/@import "tw-animate-css";/g, '');
fs.writeFileSync('c:/omniroute/components/scanner/manus-hero.css', css);
