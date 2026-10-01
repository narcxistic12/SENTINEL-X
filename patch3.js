const fs = require('fs');
let code = fs.readFileSync('c:/omniroute/lib/scoring/risk-engine.ts', 'utf-8');

const targetStr = `  // ==========================================
  // 2. Domain & DNS Intelligence`;

const insertStr = `
  // Brand Impersonation
  if (urlFeatures.brandImpersonation?.detected) {
    totalRisk += 35;
    signals.push({
      id: 'url-brand-impersonation',
      title: \`Brand Impersonation Detected (\${urlFeatures.brandImpersonation.brandFound})\`,
      explanation: urlFeatures.brandImpersonation.evidence,
      severity: 'critical',
      status: 'fail',
      source: 'LOCAL ANALYSIS',
      points: 35,
    });
  }

  // ==========================================
  // 2. Domain & DNS Intelligence`;

code = code.replace(targetStr, insertStr);

fs.writeFileSync('c:/omniroute/lib/scoring/risk-engine.ts', code);
