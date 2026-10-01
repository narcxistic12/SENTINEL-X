const fs = require('fs');
let code = fs.readFileSync('c:/omniroute/lib/detection/providers/threat-intel.ts', 'utf-8');

code = code.replace(/status:\s*'UNAVAILABLE'/g, "status: 'ERROR'");
code = code.replace(/status:\s*'ERROR',(\s*)isFlagged:\s*false,(\s*)details:\s*'URLhaus API request timed out/g, "status: 'TIMEOUT',$1isFlagged: false,$2details: 'URLhaus API request timed out");
code = code.replace(/status:\s*'ERROR',(\s*)isFlagged:\s*false,(\s*)details:\s*'PhishTank API request timed out/g, "status: 'TIMEOUT',$1isFlagged: false,$2details: 'PhishTank API request timed out");

fs.writeFileSync('c:/omniroute/lib/detection/providers/threat-intel.ts', code);
