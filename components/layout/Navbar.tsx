'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Shield, Menu, X, ArrowRight, Activity } from 'lucide-react';
import { ThemeToggle } from '@/components/ui/ThemeToggle';

export function Navbar() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const pathname = usePathname();

  const navLinks = [
    { href: '/', label: 'Home' },
    { href: '/scanner', label: 'Scanner' },
    { href: '/dashboard', label: 'Dashboard' },
    { href: '/history', label: 'History' },
    { href: '/methodology', label: 'Methodology' },
    { href: '/about', label: 'About' },
  ];

  const isActive = (href: string) => {
    if (href === '/' && pathname !== '/') return false;
    return pathname.startsWith(href);
  };

  return (
    <header className="sticky top-0 z-50 w-full border-b border-slate-200/80 dark:border-cyber-800/80 bg-white/80 dark:bg-cyber-950/80 backdrop-blur-md transition-colors">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Brand Logo */}
        <Link
          href="/"
          className="flex items-center gap-2.5 group focus:outline-none focus-visible:ring-2 focus-visible:ring-cyber-500 rounded-lg"
        >
          <div className="relative flex items-center justify-center w-9 h-9 rounded-xl bg-gradient-to-br from-cyber-500 to-cyber-700 text-white shadow-md shadow-cyber-500/20 group-hover:scale-105 transition-transform">
            <Shield className="w-5 h-5 text-white" />
            <div className="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 bg-emerald-400 border-2 border-cyber-950 rounded-full" />
          </div>
          <div className="flex flex-col">
            <span className="font-extrabold text-base tracking-tight font-mono text-slate-900 dark:text-white group-hover:text-cyber-600 dark:group-hover:text-cyber-300 transition-colors">
              SENTINEL<span className="text-cyber-500">X</span>
            </span>
            <span className="text-[10px] uppercase font-mono tracking-widest text-slate-400 dark:text-cyber-400 -mt-1 hidden sm:inline">
              Threat Intel
            </span>
          </div>
        </Link>

        {/* Desktop Navigation Links */}
        <nav className="hidden md:flex items-center gap-1">
          {navLinks.map((link) => {
            const active = isActive(link.href);
            return (
              <Link
                key={link.href}
                href={link.href}
                className={`px-3.5 py-1.5 rounded-lg text-sm font-medium transition-all ${
                  active
                    ? 'bg-cyber-500/10 dark:bg-cyber-500/20 text-cyber-700 dark:text-cyber-200 font-semibold'
                    : 'text-slate-600 dark:text-cyber-300 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-cyber-850'
                }`}
              >
                {link.label}
              </Link>
            );
          })}
        </nav>

        {/* Right Side CTAs & Theme Toggle */}
        <div className="hidden md:flex items-center gap-3">
          <ThemeToggle />
          <Link
            href="/scanner"
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-cyber-600 to-cyber-500 hover:from-cyber-500 hover:to-cyber-400 text-white font-medium text-sm transition-all shadow-md shadow-cyber-900/20 active:scale-95"
          >
            <Activity className="w-4 h-4" />
            <span>Scan URL</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>

        {/* Mobile Hamburger Button */}
        <div className="flex md:hidden items-center gap-2">
          <ThemeToggle />
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            type="button"
            aria-label="Toggle Navigation Menu"
            className="p-2 rounded-lg text-slate-600 dark:text-cyber-200 hover:bg-slate-100 dark:hover:bg-cyber-800 transition-colors"
          >
            {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>
      </div>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div className="md:hidden border-b border-slate-200 dark:border-cyber-800 bg-white dark:bg-cyber-950 px-4 pt-2 pb-6 space-y-2">
          {navLinks.map((link) => {
            const active = isActive(link.href);
            return (
              <Link
                key={link.href}
                href={link.href}
                onClick={() => setMobileMenuOpen(false)}
                className={`block px-4 py-2.5 rounded-lg text-sm font-medium ${
                  active
                    ? 'bg-cyber-500/10 dark:bg-cyber-500/20 text-cyber-700 dark:text-white font-semibold'
                    : 'text-slate-600 dark:text-cyber-300 hover:bg-slate-100 dark:hover:bg-cyber-850'
                }`}
              >
                {link.label}
              </Link>
            );
          })}
          <div className="pt-3">
            <Link
              href="/scanner"
              onClick={() => setMobileMenuOpen(false)}
              className="flex items-center justify-center gap-2 w-full py-3 rounded-xl bg-cyber-600 hover:bg-cyber-500 text-white font-semibold text-sm transition-all shadow-md"
            >
              <Activity className="w-4 h-4" />
              <span>Launch URL Scanner</span>
            </Link>
          </div>
        </div>
      )}
    </header>
  );
}
