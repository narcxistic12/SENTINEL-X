'use client';
import React, { useEffect, useMemo, useRef, useState } from 'react';
import { animate } from 'animejs';
import { ArrowDownRight, ChevronRight, LockKeyhole, Terminal } from 'lucide-react';
import { ScanReport } from '@/types/security';

type ScanState = 'idle' | 'scanning' | 'safe' | 'low_risk' | 'suspicious' | 'high_risk' | 'malicious' | 'unknown';

interface ManusHeroProps {
  onScan: (url: string) => void;
  isScanning: boolean;
  scanResult: ScanReport | null;
}

const keyRows = [
  ['Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P'],
  ['A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L'],
  ['Z', 'X', 'C', 'V', 'B', 'N', 'M', ':', '/', '.'],
  ['SHIFT', '-', '_', 'SPACE', 'BACKSPACE', 'ENTER'],
];

export function ManusHero({ onScan, isScanning, scanResult }: ManusHeroProps) {
  const [url, setUrl] = useState('');
  const [lastKey, setLastKey] = useState('');
  const [cursor, setCursor] = useState({ x: 0, y: 0 });
  const inputRef = useRef<HTMLInputElement>(null);
  const roomRef = useRef<HTMLDivElement>(null);

  // Derive state from props
  let state: ScanState = 'idle';
  if (isScanning) {
    state = 'scanning';
  } else if (scanResult) {
    const v = scanResult.verdict;
    if (v === 'SAFE') state = 'safe';
    else if (v === 'LOW_RISK') state = 'low_risk';
    else if (v === 'SUSPICIOUS') state = 'suspicious';
    else if (v === 'HIGH_RISK') state = 'high_risk';
    else if (v === 'CRITICAL') state = 'malicious';
    else state = 'unknown';
  }

  const isTyping = url.length > 0 && state === 'idle';
  
  let accent = '#79e9ff';
  if (state === 'malicious' || state === 'high_risk') accent = '#ff4d5f';
  else if (state === 'suspicious') accent = '#f2ae4b';
  else if (state === 'safe' || state === 'low_risk') accent = '#7df5c6';

  const verdict = useMemo(() => {
    switch (state) {
      case 'idle': return { icon: '•-O', title: 'AWAITING TARGET', sub: 'TYPE A URL TO BEGIN' };
      case 'scanning': return { icon: '•-O', title: 'ANALYZING TARGET', sub: 'SIGNALS IN MOTION' };
      case 'safe':
      case 'low_risk': return { icon: '•o"', title: 'TARGET VERIFIED', sub: 'SAFE TO VISIT' };
      case 'suspicious': return { icon: '!', title: 'SUSPICIOUS TARGET', sub: 'PROCEED WITH CAUTION' };
      case 'high_risk':
      case 'malicious': return { icon: '!', title: 'THREAT DETECTED', sub: 'MALICIOUS URL' };
      case 'unknown':
      default: return { icon: '?', title: 'TARGET UNKNOWN', sub: 'INSUFFICIENT EVIDENCE' };
    }
  }, [state]);

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      if (target && ['INPUT', 'TEXTAREA'].includes(target.tagName) && target !== inputRef.current) return;
      if (event.key === 'Escape') {
        setUrl('');
        return;
      }
      if (event.key === 'Enter' && document.activeElement === inputRef.current) {
        event.preventDefault();
        if (url.trim()) onScan(url);
        return;
      }
      if (document.activeElement !== inputRef.current) return;
      if (event.key.length === 1 || ['Backspace', 'Delete', ' '].includes(event.key)) {
        setLastKey(event.key === ' ' ? 'SPACE' : event.key.toUpperCase());
        window.setTimeout(() => setLastKey(''), 180);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [url, onScan]);

  useEffect(() => {
    const moveHandler = (e: MouseEvent) => {
      const x = (e.clientX / window.innerWidth - 0.5) * 2;
      const y = (e.clientY / window.innerHeight - 0.5) * 2;
      setCursor({ x, y });
    };
    window.addEventListener('mousemove', moveHandler);
    return () => window.removeEventListener('mousemove', moveHandler);
  }, []);

  useEffect(() => {
    if (roomRef.current) {
      animate(roomRef.current, {
        translateX: cursor.x * 4,
        translateY: cursor.y * 3,
        duration: 500,
        ease: 'out(3)'
      });
    }
  }, [cursor]);

  function focusInput() {
    inputRef.current?.focus();
    inputRef.current?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }

  const pressKey = (key: string) => {
    if (key === 'ENTER') {
      if (url.trim()) onScan(url);
    }
    else if (key === 'BACKSPACE') setUrl((value) => value.slice(0, -1));
    else if (key === 'SPACE') setUrl((value) => `${value} `);
    else if (key.length === 1 || key === ':' || key === '/') setUrl((value) => `${value}${key.toLowerCase()}`);
    
    setLastKey(key);
    window.setTimeout(() => setLastKey(''), 180);
    focusInput();
  };

  return (
    <div className="sentinel-shell" style={{ "--signal": accent, minHeight: "unset", position: "relative", width: "100%", padding: "40px 0" } as React.CSSProperties}>
      <div className="grain" style={{ position: "absolute", zIndex: 0 }} />
      <section className="hero-grid" ref={roomRef} style={{ position: "relative", zIndex: 10, margin: "0 auto", padding: "20px 0" }}>
        <div className="hero-copy reveal-up">
          <div className="eyebrow"><span>INTELLIGENT URL THREAT DETECTION</span><i /></div>
          <h1>Detect the threat.<br /><em>Before you click.</em></h1>
          <p className="lede">A cinematic threat-analysis node that turns your keyboard into a first line of defense.</p>
          <div className="cta-row">
            <button className="primary-cta" onClick={focusInput}><span className="cta-icon"><Terminal size={16} /></span> TYPE A URL <ArrowDownRight size={16} /></button>
          </div>
          <div className="privacy-note"><LockKeyhole size={13} /> Input stays in this browser. No unrelated keystrokes are captured.</div>
        </div>

        <div className="ops-room" aria-label="Interactive cybersecurity operations room">
          <div className="room-grid" />
          <div className="scan-beam" />
          <div className="monitor monitor-left"><div className="monitor-head">DNS / RESOLUTION <span>LIVE</span></div><div className="waveform"><i /><i /><i /><i /><i /><i /><i /><i /></div><div className="monitor-foot">resolver.path <strong>08:32:19</strong></div></div>
          <div className="monitor monitor-top"><div className="monitor-head">NETWORK ACTIVITY <span className="amber">WATCH</span></div><div className="network-map"><b /><b /><b /><b /><b /><svg viewBox="0 0 220 70"><path d="M8 52 L54 18 L102 52 L155 12 L210 43" /><path d="M54 18 L102 52 L155 12" /></svg></div><div className="monitor-foot">packets / symbolic view</div></div>
          <div className="monitor monitor-right"><div className="monitor-head">THREAT INTEL <span>ARMED</span></div><div className="intel-lines"><span /><span /><span /><span /></div><div className="monitor-foot">heuristics layer / 07</div></div>

          <div className={`analyst ${state} ${isTyping ? "typing" : ""}`}><div className="analyst-halo" /><div className="hood"><div className="hood-opening"><div className="shadow-face" /></div><span className="hood-seam" /></div><div className="hoodie-neck" /><div className="jacket"><span className="collar" /><span className="badge">SX</span><span className="hoodie-string string-a" /><span className="hoodie-string string-b" /></div><div className="arm arm-a" /><div className="arm arm-b" /><div className="hand hand-a" /><div className="hand hand-b" /></div>

          <div className={`laptop ${state}`} onClick={focusInput} role="button" tabIndex={0} aria-label="Focus URL target input">
            <div className="laptop-screen">
              <div className="screen-top"><span>SENTINELX://ANALYSIS</span><span className="screen-live"><i /> SECURE</span></div>
              <div className="terminal-body">
                <div className="terminal-line muted">&gt; NODE_07 // TARGET INPUT</div>
                <label htmlFor="url-target" className="target-line">
                  <span>&gt;</span>
                  <input id="url-target" ref={inputRef} value={url} onChange={(event) => setUrl(event.target.value)} placeholder="type a URL..." aria-label="URL to scan" autoComplete="off" spellCheck={false} />
                  <span className="caret" />
                </label>
                {state === "scanning" && <div className="terminal-line active">&gt; TARGET ACQUIRED<br />&gt; ANALYZING URL...</div>}
                {state !== "idle" && state !== "scanning" && <div className={`terminal-verdict ${state}`}><strong>{verdict.icon} {verdict.title}</strong><span>{verdict.sub}</span></div>}
              </div>
              <div className="screen-bottom"><span>INPUT: LOCAL</span><span>ADAPTER: LIVE</span></div>
            </div>
            <div className="laptop-base">
              <div className="laptop-logo">SX</div>
              <div className="kali-badge" aria-label="Kali Linux environment"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 18c5-1 5-7 8-13 2 3 2 6 0 8 2-1 4-1 7 0-2 1-3 3-4 5H4Z" /><path d="M13 13c2-2 4-3 7-2-1 2-2 3-4 4" /></svg><span>KALI</span></div>
            </div>
          </div>

          <div className="desk">
            <div className="keyboard" aria-label="On-screen keyboard">
              <div className="key-row-label">ANALYST KEYBOARD / <span>LISTENING</span></div>
              {keyRows.map((row, rowIndex) => 
                <div className="key-row" key={rowIndex}>
                  {row.map((key) => <button key={key} className={`key ${key.toLowerCase()} ${lastKey === key ? "pressed" : ""}`} onClick={() => pressKey(key)}>{key}</button>)}
                </div>
              )}
            </div>
            <div className="desk-line" />
            <div className="desk-light" />
          </div>
          <div className="verdict-rail" style={{ color: accent }}><span className="verdict-icon">{verdict.icon}</span><div><small>ANALYST STATUS</small><strong>{verdict.title}</strong><em>{verdict.sub}</em></div><div className="signal-meter"><i /><i /><i /><i /><i /></div></div>
        </div>
      </section>
    </div>
  );
}
