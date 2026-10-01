'use client';

import React, { useState, useEffect, useRef, useMemo, Suspense } from 'react';
import { Canvas, useFrame, useThree } from '@react-three/fiber';
import { OrbitControls, Stars, Float, Text, Instances, Instance, Line, Html, Environment } from '@react-three/drei';
import * as THREE from 'three';
import { ScanReport, RiskVerdict } from '@/types/security';

export interface HeroVisualProps {
  isScanning?: boolean;
  currentStage?: number;
  scanResult?: ScanReport | null;
}

// -----------------------------------------------------
// 2D FALLBACK (Original logic with minor tweaks)
// -----------------------------------------------------
function Fallback2D() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let width = (canvas.width = canvas.parentElement?.clientWidth || 600);
    let height = (canvas.height = 320);

    const handleResize = () => {
      if (!canvas || !canvas.parentElement) return;
      width = canvas.width = canvas.parentElement.clientWidth;
      height = canvas.height = 320;
    };
    window.addEventListener('resize', handleResize);

    const nodeCount = 28;
    const nodes: { x: number; y: number; vx: number; vy: number; radius: number; pulse: number }[] = [];
    for (let i = 0; i < nodeCount; i++) {
      nodes.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.4,
        vy: (Math.random() - 0.5) * 0.4,
        radius: Math.random() * 2 + 1.5,
        pulse: Math.random() * Math.PI * 2,
      });
    }

    let radarAngle = 0;

    const render = () => {
      ctx.clearRect(0, 0, width, height);
      ctx.strokeStyle = 'rgba(65, 90, 136, 0.08)';
      ctx.lineWidth = 1;
      const gridSize = 40;
      for (let x = 0; x < width; x += gridSize) {
        ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, height); ctx.stroke();
      }
      for (let y = 0; y < height; y += gridSize) {
        ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(width, y); ctx.stroke();
      }

      const centerX = width / 2;
      const centerY = height / 2;
      const radarRadius = Math.min(width, height) * 0.45;

      radarAngle += 0.015;
      const gradient = ctx.createRadialGradient(centerX, centerY, 5, centerX, centerY, radarRadius);
      gradient.addColorStop(0, 'rgba(14, 165, 233, 0.08)');
      gradient.addColorStop(1, 'rgba(14, 165, 233, 0.0)');

      ctx.fillStyle = gradient;
      ctx.beginPath(); ctx.arc(centerX, centerY, radarRadius, 0, Math.PI * 2); ctx.fill();

      ctx.strokeStyle = 'rgba(14, 165, 233, 0.25)';
      ctx.lineWidth = 1.5;
      ctx.beginPath(); ctx.moveTo(centerX, centerY);
      ctx.lineTo(centerX + Math.cos(radarAngle) * radarRadius, centerY + Math.sin(radarAngle) * radarRadius);
      ctx.stroke();

      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[i].x - nodes[j].x;
          const dy = nodes[i].y - nodes[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 110) {
            const alpha = (1 - dist / 110) * 0.22;
            ctx.strokeStyle = `rgba(56, 189, 248, ${alpha})`;
            ctx.lineWidth = 1;
            ctx.beginPath(); ctx.moveTo(nodes[i].x, nodes[i].y); ctx.lineTo(nodes[j].x, nodes[j].y); ctx.stroke();
          }
        }
      }

      for (const node of nodes) {
        node.x += node.vx; node.y += node.vy;
        if (node.x < 10 || node.x > width - 10) node.vx *= -1;
        if (node.y < 10 || node.y > height - 10) node.vy *= -1;
        node.pulse += 0.03;
        const currentRadius = node.radius + Math.sin(node.pulse) * 0.8;
        ctx.fillStyle = 'rgba(56, 189, 248, 0.7)';
        ctx.beginPath(); ctx.arc(node.x, node.y, Math.max(1, currentRadius), 0, Math.PI * 2); ctx.fill();
      }
      animationFrameId = requestAnimationFrame(render);
    };

    render();
    return () => {
      window.removeEventListener('resize', handleResize);
      cancelAnimationFrame(animationFrameId);
    };
  }, []);

  return (
    <div className="relative w-full h-[400px] rounded-2xl overflow-hidden border border-slate-200 dark:border-cyber-800/80 bg-slate-50/50 dark:bg-cyber-950/60 shadow-inner select-none pointer-events-none">
      <canvas ref={canvasRef} className="w-full h-full block" />
    </div>
  );
}

// -----------------------------------------------------
// 3D CORE COMPONENT
// -----------------------------------------------------

function CyberCore({ isScanning, currentStage, scanResult }: HeroVisualProps) {
  const groupRef = useRef<THREE.Group>(null);
  const outerRingRef = useRef<THREE.Mesh>(null);
  const innerRingRef = useRef<THREE.Mesh>(null);
  const coreRef = useRef<THREE.Mesh>(null);
  const particlesRef = useRef<THREE.Group>(null);
  const { clock } = useThree();

  // State colors
  const idleColor = new THREE.Color('#38bdf8'); // sky-400
  const scanningColor = new THREE.Color('#a855f7'); // purple-500
  const safeColor = new THREE.Color('#10b981'); // emerald-500
  const warningColor = new THREE.Color('#f59e0b'); // amber-500
  const dangerColor = new THREE.Color('#f43f5e'); // rose-500

  // Dynamic values
  const currentTargetColor = useMemo(() => new THREE.Color(), []);
  
  useFrame((state, delta) => {
    if (!groupRef.current) return;

    const t = state.clock.getElapsedTime();
    
    // Rotation logic
    let rotationSpeed = 0.2;
    if (isScanning) rotationSpeed = 0.8 + (currentStage || 0) * 0.1;
    else if (scanResult) {
      if (scanResult.verdict === 'CRITICAL' || scanResult.verdict === 'HIGH_RISK') rotationSpeed = 1.2;
      else if (scanResult.verdict === 'SAFE') rotationSpeed = 0.1;
      else rotationSpeed = 0.4;
    }

    groupRef.current.rotation.y += rotationSpeed * delta;
    groupRef.current.rotation.z = Math.sin(t * 0.5) * 0.1;
    
    if (outerRingRef.current) outerRingRef.current.rotation.x += rotationSpeed * 1.5 * delta;
    if (innerRingRef.current) innerRingRef.current.rotation.y -= rotationSpeed * 2 * delta;

    // Color transition logic
    let targetC = idleColor;
    if (isScanning) {
      targetC = scanningColor;
    } else if (scanResult) {
      if (scanResult.verdict === 'SAFE') targetC = safeColor;
      else if (scanResult.verdict === 'LOW_RISK' || scanResult.verdict === 'SUSPICIOUS') targetC = warningColor;
      else targetC = dangerColor;
    }

    currentTargetColor.lerp(targetC, delta * 3);

    // Apply color to core materials
    if (coreRef.current) {
      (coreRef.current.material as THREE.MeshStandardMaterial).color.copy(currentTargetColor);
      (coreRef.current.material as THREE.MeshStandardMaterial).emissive.copy(currentTargetColor).multiplyScalar(isScanning ? 0.8 : 0.4);
    }
    if (outerRingRef.current) {
      (outerRingRef.current.material as THREE.MeshStandardMaterial).color.copy(currentTargetColor);
    }
  });

  return (
    <group ref={groupRef}>
      <Float speed={2} rotationIntensity={0.5} floatIntensity={1}>
        {/* Core Icosahedron */}
        <mesh ref={coreRef} scale={1.5}>
          <icosahedronGeometry args={[1, 1]} />
          <meshStandardMaterial 
            color="#38bdf8" 
            wireframe 
            emissive="#38bdf8"
            emissiveIntensity={0.5}
            transparent 
            opacity={0.8} 
          />
        </mesh>

        {/* Inner Solid Core */}
        <mesh scale={0.8}>
          <octahedronGeometry args={[1, 0]} />
          <meshStandardMaterial color="#0f172a" roughness={0.2} metalness={0.8} />
        </mesh>

        {/* Outer Ring */}
        <mesh ref={outerRingRef} rotation={[Math.PI / 3, 0, 0]}>
          <torusGeometry args={[2.5, 0.02, 16, 100]} />
          <meshStandardMaterial color="#38bdf8" emissive="#38bdf8" emissiveIntensity={0.5} />
        </mesh>

        {/* Inner Ring */}
        <mesh ref={innerRingRef} rotation={[0, Math.PI / 4, 0]}>
          <torusGeometry args={[2, 0.01, 16, 100]} />
          <meshStandardMaterial color="#ffffff" transparent opacity={0.3} />
        </mesh>
      </Float>
      
      {/* Dynamic Data Nodes (Labels) */}
      <DataNodes isScanning={isScanning} scanResult={scanResult} currentStage={currentStage} />
    </group>
  );
}

function DataNodes({ isScanning, scanResult, currentStage }: HeroVisualProps) {
  const nodes = [
    { label: 'URL', pos: [3, 2, 0] },
    { label: 'DNS', pos: [-3, 1, 1] },
    { label: 'SSL', pos: [2, -2, 2] },
    { label: 'RISK', pos: [-2, -2, -1] },
    { label: 'AI DETECT', pos: [0, 3, -2] },
  ];

  return (
    <group>
      {nodes.map((node, i) => (
        <Float key={i} speed={1.5 + i * 0.2} floatIntensity={2} position={node.pos as [number, number, number]}>
          <Html center zIndexRange={[100, 0]}>
            <div className={`px-2 py-1 rounded text-[10px] font-mono border backdrop-blur-md transition-all duration-500 ${
              isScanning 
                ? 'border-purple-500/50 bg-purple-900/40 text-purple-200' 
                : scanResult 
                  ? 'border-cyber-500/50 bg-cyber-900/40 text-cyber-200' 
                  : 'border-slate-700/50 bg-slate-900/40 text-slate-400'
            }`}>
              {node.label}
              {isScanning && <span className="ml-1 animate-pulse">...</span>}
            </div>
          </Html>
        </Float>
      ))}
    </group>
  );
}

function StatusText({ isScanning, scanResult }: HeroVisualProps) {
  let status = 'SYSTEM READY';
  let color = '#94a3b8'; // slate-400

  if (isScanning) {
    status = 'SCANNING THREAT INTEL...';
    color = '#c084fc'; // purple-400
  } else if (scanResult) {
    status = `VERDICT: ${scanResult.verdict.replace('_', ' ')}`;
    if (scanResult.verdict === 'SAFE') color = '#34d399';
    else if (scanResult.verdict === 'LOW_RISK' || scanResult.verdict === 'SUSPICIOUS') color = '#fbbf24';
    else color = '#fb7185';
  }

  return (
    <Text
      position={[0, -3.5, 0]}
      fontSize={0.25}
      color={color}
      font="https://fonts.gstatic.com/s/robotomono/v22/L0xuDF4xlVMF-BfR8bXMIhJHg45mwgGEFl0_3vrtSM1J-gEPO96OIT8.woff"
      anchorX="center"
      anchorY="middle"
      letterSpacing={0.1}
    >
      {status}
    </Text>
  );
}

function Scene({ isScanning, currentStage, scanResult }: HeroVisualProps) {
  const { camera } = useThree();

  // Gentle idle camera movement based on mouse
  useFrame((state) => {
    const targetX = (state.mouse.x * Math.PI) / 10;
    const targetY = (state.mouse.y * Math.PI) / 10;
    
    // Smooth camera interpolation
    camera.position.x += (targetX - camera.position.x) * 0.05;
    camera.position.y += (targetY - camera.position.y) * 0.05;
    camera.lookAt(0, 0, 0);
  });

  return (
    <>
      <ambientLight intensity={0.2} />
      <directionalLight position={[10, 10, 5]} intensity={1} color="#38bdf8" />
      <directionalLight position={[-10, -10, -5]} intensity={0.5} color="#a855f7" />
      
      <CyberCore isScanning={isScanning} currentStage={currentStage} scanResult={scanResult} />
      <StatusText isScanning={isScanning} scanResult={scanResult} />
      
      <Stars radius={50} depth={50} count={3000} factor={4} saturation={0} fade speed={1} />
      
      <OrbitControls 
        enableZoom={false} 
        enablePan={false}
        enableDamping
        dampingFactor={0.05}
        autoRotate={!isScanning && !scanResult}
        autoRotateSpeed={0.5}
        maxPolarAngle={Math.PI / 1.5}
        minPolarAngle={Math.PI / 3}
      />
    </>
  );
}

// Main component with WebGL fallback detection
export function HeroVisual(props: HeroVisualProps) {
  const [hasWebGL, setHasWebGL] = useState(true);
  const [reducedMotion, setReducedMotion] = useState(false);

  useEffect(() => {
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) setHasWebGL(false);
    } catch (e) {
      setHasWebGL(false);
    }
    
    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    setReducedMotion(mediaQuery.matches);
    const listener = (e: MediaQueryListEvent) => setReducedMotion(e.matches);
    mediaQuery.addEventListener('change', listener);
    return () => mediaQuery.removeEventListener('change', listener);
  }, []);

  if (!hasWebGL || reducedMotion) {
    return <Fallback2D />;
  }

  return (
    <div className="relative w-full h-[400px] sm:h-[450px] lg:h-[500px] rounded-2xl overflow-hidden border border-slate-200 dark:border-cyber-800/80 bg-slate-900 shadow-2xl transition-all duration-700">
      <Suspense fallback={<div className="w-full h-full flex items-center justify-center text-cyber-500 font-mono text-sm">INITIALIZING CORE...</div>}>
        <Canvas camera={{ position: [0, 0, 8], fov: 45 }} dpr={[1, 2]}>
          <Scene {...props} />
        </Canvas>
      </Suspense>
      
      {/* HUD Overlays */}
      <div className="absolute top-4 left-4 flex items-center gap-2 pointer-events-none z-10">
        <span className={`w-2 h-2 rounded-full ${props.isScanning ? 'bg-purple-400 animate-ping' : props.scanResult ? (props.scanResult.verdict === 'SAFE' ? 'bg-emerald-400' : 'bg-rose-500 animate-pulse') : 'bg-emerald-400'} shadow-lg`} />
        <span className="text-[10px] font-mono tracking-wider text-slate-300 uppercase bg-slate-900/50 px-2 py-0.5 rounded backdrop-blur">
          {props.isScanning ? 'ACTIVE TELEMETRY' : 'THREAT GRID: ONLINE'}
        </span>
      </div>
      <div className="absolute bottom-4 right-4 hidden sm:block pointer-events-none z-10">
        <span className="text-[10px] font-mono text-slate-500 bg-slate-900/50 px-2 py-0.5 rounded backdrop-blur">
          WebGL Core v2.0
        </span>
      </div>
    </div>
  );
}
