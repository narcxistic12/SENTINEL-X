import type { Metadata } from 'next';
import './globals.css';
import { ThemeProvider } from '@/components/theme/ThemeProvider';
import { Navbar } from '@/components/layout/Navbar';
import { Footer } from '@/components/layout/Footer';

export const metadata: Metadata = {
  title: 'SENTINELX - Intelligent URL Threat Detection',
  description:
    'Advanced cybersecurity scanner that analyzes URLs using multi-factor heuristics, live DNS records, SSL/TLS handshakes, and SSRF-shielded redirect chains to detect phishing.',
  keywords: [
    'phishing scanner',
    'url scanner',
    'security',
    'malware',
    'threat intelligence',
    'SSRF protection',
  ],
  authors: [{ name: 'SENTINELX Security Team' }],
  viewport: 'width=device-width, initial-scale=1',
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <body className="min-h-screen flex flex-col justify-between">
        <ThemeProvider>
          <div className="flex flex-col min-h-screen">
            <Navbar />
            <main className="flex-1">{children}</main>
            <Footer />
          </div>
        </ThemeProvider>
      </body>
    </html>
  );
}
