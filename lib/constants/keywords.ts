export interface KeywordDefinition {
  word: string;
  category: 'authentication' | 'payment' | 'urgency' | 'impersonation';
  weight: number;
}

export const SUSPICIOUS_KEYWORDS: KeywordDefinition[] = [
  // Authentication & Credentials
  { word: 'login', category: 'authentication', weight: 4 },
  { word: 'signin', category: 'authentication', weight: 4 },
  { word: 'sign-in', category: 'authentication', weight: 4 },
  { word: 'log-in', category: 'authentication', weight: 4 },
  { word: 'logon', category: 'authentication', weight: 3 },
  { word: 'verify', category: 'authentication', weight: 5 },
  { word: 'verification', category: 'authentication', weight: 5 },
  { word: 'authorize', category: 'authentication', weight: 4 },
  { word: 'auth', category: 'authentication', weight: 3 },
  { word: 'password', category: 'authentication', weight: 6 },
  { word: 'passcode', category: 'authentication', weight: 5 },
  { word: 'credential', category: 'authentication', weight: 6 },
  { word: 'recover', category: 'authentication', weight: 4 },
  { word: 'recovery', category: 'authentication', weight: 4 },
  { word: 'reset-password', category: 'authentication', weight: 6 },
  { word: 'account', category: 'authentication', weight: 3 },
  { word: 'update', category: 'authentication', weight: 3 },
  { word: 'secure', category: 'authentication', weight: 3 },
  { word: 'security', category: 'authentication', weight: 3 },
  { word: 'support', category: 'authentication', weight: 3 },
  { word: 'unlock', category: 'authentication', weight: 4 },
  { word: 'confirm', category: 'authentication', weight: 4 },
  { word: 'reset', category: 'authentication', weight: 4 },
  { word: 'security-check', category: 'authentication', weight: 5 },

  // Financial & Payment
  { word: 'paypal', category: 'payment', weight: 5 },
  { word: 'wallet', category: 'payment', weight: 4 },
  { word: 'metamask', category: 'payment', weight: 6 },
  { word: 'coinbase', category: 'payment', weight: 5 },
  { word: 'binance', category: 'payment', weight: 5 },
  { word: 'banking', category: 'payment', weight: 5 },
  { word: 'chase', category: 'payment', weight: 4 },
  { word: 'wellsfargo', category: 'payment', weight: 5 },
  { word: 'bankofamerica', category: 'payment', weight: 5 },
  { word: 'creditcard', category: 'payment', weight: 6 },
  { word: 'billing', category: 'payment', weight: 4 },
  { word: 'invoice', category: 'payment', weight: 3 },
  { word: 'payment', category: 'payment', weight: 4 },
  { word: 'crypto', category: 'payment', weight: 4 },
  { word: 'refund', category: 'payment', weight: 4 },

  // Urgency & Fear Tactics
  { word: 'suspended', category: 'urgency', weight: 6 },
  { word: 'restricted', category: 'urgency', weight: 5 },
  { word: 'locked', category: 'urgency', weight: 5 },
  { word: 'unusual-activity', category: 'urgency', weight: 6 },
  { word: 'action-required', category: 'urgency', weight: 5 },
  { word: 'urgent', category: 'urgency', weight: 4 },
  { word: 'immediate-action', category: 'urgency', weight: 6 },
  { word: 'confirm-now', category: 'urgency', weight: 5 },
  { word: 'deactivation', category: 'urgency', weight: 6 },
  { word: 'security-alert', category: 'urgency', weight: 5 },

  // Brand Impersonation Patterns
  { word: 'microsoft-online', category: 'impersonation', weight: 6 },
  { word: 'apple-support', category: 'impersonation', weight: 6 },
  { word: 'google-drive', category: 'impersonation', weight: 5 },
  { word: 'dropbox-share', category: 'impersonation', weight: 5 },
  { word: 'netflix-update', category: 'impersonation', weight: 5 },
  { word: 'amazon-orders', category: 'impersonation', weight: 5 },
];
