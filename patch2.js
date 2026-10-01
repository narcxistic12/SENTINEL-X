const fs = require('fs');
let code = fs.readFileSync('c:/omniroute/lib/detection/providers/threat-intel.ts', 'utf-8');

code = code.replace(/status:\s*'TIMEOUT',/g, "status: 'TIMEOUT' as const,");
code = code.replace(/status:\s*'ERROR',/g, "status: 'ERROR' as const,");
code = code.replace(/status:\s*'CLEAN',\s*isFlagged:\s*false/g, "status: 'CLEAN' as const, isFlagged: false");

fs.writeFileSync('c:/omniroute/lib/detection/providers/threat-intel.ts', code);
