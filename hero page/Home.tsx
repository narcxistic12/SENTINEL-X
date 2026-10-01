import { useEffect, useMemo, useRef, useState } from "react";
import { animate } from "animejs";
import { ArrowDownRight, ChevronRight, Crosshair, LockKeyhole, Radio, ScanLine, ShieldCheck, Terminal, TriangleAlert, Wifi } from "lucide-react";

type ScanState = "idle" | "scanning" | "safe" | "suspicious" | "malicious" | "unknown";

const scanStages = ["URL STRUCTURE", "DOMAIN", "DNS", "TLS / SSL", "REDIRECTS", "THREAT INTEL", "HEURISTICS"];
const keyRows = [
  ["Q", "W", "E", "R", "T", "Y", "U", "I", "O", "P"],
  ["A", "S", "D", "F", "G", "H", "J", "K", "L"],
  ["Z", "X", "C", "V", "B", "N", "M", ":", "/", "."],
  ["SHIFT", "-", "_", "SPACE", "BACKSPACE", "ENTER"],
];

function inferDemoResult(url: string): Exclude<ScanState, "idle" | "scanning"> {
  const value = url.toLowerCase();
  if (value.includes("malware") || value.includes("phish") || value.includes("evil")) return "malicious";
  if (value.includes("suspicious") || value.includes("verify") || value.includes("login")) return "suspicious";
  if (value.includes("unknown") || value.includes("example")) return "unknown";
  return "safe";
}

export default function Home() {
  const [url, setUrl] = useState("");
  const [state, setState] = useState<ScanState>("idle");
  const [activeStage, setActiveStage] = useState(-1);
  const [lastKey, setLastKey] = useState("");
  const [cursor, setCursor] = useState({ x: 0, y: 0 });
  const inputRef = useRef<HTMLInputElement>(null);
  const roomRef = useRef<HTMLDivElement>(null);

  const isTyping = url.length > 0 && state === "idle";
  const accent = state === "malicious" ? "#ff4d5f" : state === "suspicious" ? "#f2ae4b" : state === "safe" ? "#7df5c6" : "#79e9ff";
  const verdict = useMemo(() => ({
    idle: { icon: "◌", title: "AWAITING TARGET", sub: "TYPE A URL TO BEGIN" },
    scanning: { icon: "◌", title: "ANALYZING TARGET", sub: "SIGNALS IN MOTION" },
    safe: { icon: "✓", title: "TARGET VERIFIED", sub: "SAFE TO VISIT" },
    suspicious: { icon: "!", title: "SUSPICIOUS TARGET", sub: "PROCEED WITH CAUTION" },
    malicious: { icon: "!", title: "THREAT DETECTED", sub: "MALICIOUS URL" },
    unknown: { icon: "?", title: "TARGET UNKNOWN", sub: "INSUFFICIENT EVIDENCE" },
  } as const)[state], [state]);

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      if (target && ["INPUT", "TEXTAREA"].includes(target.tagName) && target !== inputRef.current) return;
      if (event.key === "Escape") {
        setUrl(""); setState("idle"); setActiveStage(-1); return;
      }
      if (event.key === "Enter" && document.activeElement === inputRef.current) {
        event.preventDefault(); runScan(); return;
      }
      if (document.activeElement !== inputRef.current) return;
      if (event.key.length === 1 || ["Backspace", "Delete", " "].includes(event.key)) {
        setLastKey(event.key === " " ? "SPACE" : event.key.toUpperCase());
        window.setTimeout(() => setLastKey(""), 180);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  });

  useEffect(() => {
    const onMove = (event: MouseEvent) => {
      setCursor({ x: (event.clientX / window.innerWidth - 0.5) * 2, y: (event.clientY / window.innerHeight - 0.5) * 2 });
    };
    window.addEventListener("mousemove", onMove);
    return () => window.removeEventListener("mousemove", onMove);
  }, []);

  useEffect(() => {
    if (!roomRef.current) return;
    animate(roomRef.current, { translateX: cursor.x * 4, translateY: cursor.y * 3, duration: 500, ease: "out(3)" });
  }, [cursor]);

  useEffect(() => {
    if (state !== "scanning") return;
    let stage = 0;
    setActiveStage(0);
    const timer = window.setInterval(() => {
      stage += 1;
      setActiveStage(stage);
      if (stage >= scanStages.length) {
        window.clearInterval(timer);
        window.setTimeout(() => setState(inferDemoResult(url)), 420);
      }
    }, 390);
    return () => window.clearInterval(timer);
  }, [state, url]);

  function runScan() {
    if (!/^https?:\/\/[^\s]+$/i.test(url)) {
      setState("unknown");
      setActiveStage(-1);
      return;
    }
    setState("scanning");
    setActiveStage(0);
  }

  function focusInput() {
    inputRef.current?.focus();
    inputRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  const pressKey = (key: string) => {
    if (key === "ENTER") return runScan();
    if (key === "BACKSPACE") setUrl((value) => value.slice(0, -1));
    else if (key === "SPACE") setUrl((value) => `${value} `);
    else if (key.length === 1 || key === ":" || key === "/") setUrl((value) => `${value}${key.toLowerCase()}`);
    setLastKey(key);
    window.setTimeout(() => setLastKey(""), 180);
    focusInput();
  };

  return (
    <main className="sentinel-shell" style={{ "--signal": accent } as React.CSSProperties}>
      <div className="grain" />
      <header className="topbar">
        <div className="brand-lockup"><span className="brand-mark"><Crosshair size={17} /></span><span>SENTINEL<span className="brand-x">X</span></span></div>
        <div className="top-status"><span className="pulse-dot" /> NODE_07 / ONLINE <span className="status-divider" /> <LockKeyhole size={13} /> CLIENT-SIDE MODE</div>
        <button className="nav-link" onClick={focusInput}>ENTER SCANNER <ChevronRight size={15} /></button>
      </header>

      <section className="hero-grid" ref={roomRef}>
        <div className="hero-copy reveal-up">
          <div className="eyebrow"><span>INTELLIGENT URL THREAT DETECTION</span><i /></div>
          <h1>Detect the threat.<br /><em>Before you click.</em></h1>
          <p className="lede">A cinematic threat-analysis node that turns your keyboard into a first line of defense.</p>
          <div className="cta-row">
            <button className="primary-cta" onClick={focusInput}><span className="cta-icon"><Terminal size={16} /></span> TYPE A URL <ArrowDownRight size={16} /></button>
            <button className="ghost-cta" onClick={() => document.getElementById("scanner")?.scrollIntoView({ behavior: "smooth" })}>VIEW PROTOCOL <ChevronRight size={15} /></button>
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
            <div className="laptop-screen"><div className="screen-top"><span>SENTINELX://ANALYSIS</span><span className="screen-live"><i /> SECURE</span></div><div className="terminal-body"><div className="terminal-line muted">&gt; NODE_07 // TARGET INPUT</div><label htmlFor="url-target" className="target-line"><span>&gt;</span><input id="url-target" ref={inputRef} value={url} onChange={(event) => { setUrl(event.target.value); setState("idle"); setActiveStage(-1); }} placeholder="type a URL..." aria-label="URL to scan" autoComplete="off" spellCheck={false} /><span className="caret" /></label>{state === "scanning" && <div className="terminal-line active">&gt; TARGET ACQUIRED<br />&gt; ANALYZING URL...</div>}{state !== "idle" && state !== "scanning" && <div className={`terminal-verdict ${state}`}><strong>{verdict.icon} {verdict.title}</strong><span>{verdict.sub}</span></div>}</div><div className="screen-bottom"><span>INPUT: LOCAL</span><span>ADAPTER: DEMO</span></div></div>
            <div className="laptop-base"><div className="laptop-logo">SX</div><div className="kali-badge" aria-label="Kali Linux environment"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 18c5-1 5-7 8-13 2 3 2 6 0 8 2-1 4-1 7 0-2 1-3 3-4 5H4Z" /><path d="M13 13c2-2 4-3 7-2-1 2-2 3-4 4" /></svg><span>KALI</span></div></div>
          </div>

          <div className="desk"><div className="keyboard" aria-label="On-screen keyboard"><div className="key-row-label">ANALYST KEYBOARD / <span>LISTENING</span></div>{keyRows.map((row, rowIndex) => <div className="key-row" key={rowIndex}>{row.map((key) => <button key={key} className={`key ${key.toLowerCase()} ${lastKey === key ? "pressed" : ""}`} onClick={() => pressKey(key)}>{key}</button>)}</div>)}</div><div className="desk-line" /><div className="desk-light" /></div>
          <div className="verdict-rail" style={{ color: accent }}><span className="verdict-icon">{verdict.icon}</span><div><small>ANALYST STATUS</small><strong>{verdict.title}</strong><em>{verdict.sub}</em></div><div className="signal-meter"><i /><i /><i /><i /><i /></div></div>
        </div>
      </section>

      <section className="scanner-section" id="scanner">
        <div className="section-label"><span>01 / THE PROTOCOL</span><i /></div><div className="scanner-intro"><h2>Make the first click<br /><em>an informed one.</em></h2><p>Every URL has a shape. SentinelX reads the signals before a browser opens the door.</p></div>
        <div className="protocol-grid"><div className="protocol-card"><Radio size={18} /><span>01</span><h3>Observe</h3><p>URL structure, DNS paths, TLS posture and redirects are surfaced as the node comes alive.</p></div><div className="protocol-card active"><ScanLine size={18} /><span>02</span><h3>Analyze</h3><p>Typed characters travel from your keyboard to the analyst's terminal in real time.</p></div><div className="protocol-card"><ShieldCheck size={18} /><span>03</span><h3>Decide</h3><p>Safe, suspicious, malicious or unknown. No verdict is presented as real without a connected engine.</p></div></div>
        <div className="scan-console"><div className="console-title"><span><Wifi size={14} /> SIGNAL PIPELINE</span><small>ADAPTER STATUS / DEMO FALLBACK</small></div>{scanStages.map((stage, index) => <div className={`scan-row ${state === "scanning" && index <= activeStage ? "lit" : ""}`} key={stage}><span className="scan-index">0{index + 1}</span><span>{stage}</span><span className="scan-progress">{state === "scanning" && index <= activeStage ? "SCANNING" : state === "idle" ? "STANDBY" : "READY"}</span></div>)}</div>
        <div className="demo-callout"><TriangleAlert size={16} /><span><strong>DEMO / FALLBACK STATE</strong> This frontend includes a clean adapter seam. Connect your SentinelX API to replace the local demonstration heuristic with a real verdict.</span></div>
      </section>
      <footer><div className="brand-lockup"><span className="brand-mark"><Crosshair size={15} /></span><span>SENTINEL<span className="brand-x">X</span></span></div><span>THREAT DETECTION, BEFORE THE BROWSER.</span><span>NODE_07 / 2026</span></footer>
    </main>
  );
}
