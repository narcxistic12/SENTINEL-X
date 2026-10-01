'use client';

import React, { useEffect, useState } from 'react';
import { RiskVerdict } from '@/types/security';

interface RiskGaugeProps {
  score: number; // 0 to 100
  verdict?: RiskVerdict;
  size?: number;
  strokeWidth?: number;
}

export function RiskGauge({ score, verdict, size = 180, strokeWidth = 14 }: RiskGaugeProps) {
  const [displayedScore, setDisplayedScore] = useState(0);

  useEffect(() => {
    // Check prefers-reduced-motion
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (prefersReducedMotion) {
      setDisplayedScore(score);
      return;
    }

    // Smooth animation from 0 to score over 1.2 seconds
    let startTime: number | null = null;
    const duration = 1200;

    const animate = (timestamp: number) => {
      if (!startTime) startTime = timestamp;
      const progress = Math.min((timestamp - startTime) / duration, 1);
      // Ease out cubic
      const easeProgress = 1 - Math.pow(1 - progress, 3);
      setDisplayedScore(Math.round(easeProgress * score));

      if (progress < 1) {
        requestAnimationFrame(animate);
      }
    };

    const animId = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(animId);
  }, [score]);

  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  // Use a 270-degree arc for an open gauge aesthetic
  const arcPercentage = 0.75;
  const totalArcLength = circumference * arcPercentage;
  const offset = totalArcLength - (displayedScore / 100) * totalArcLength;

  // Determine stroke color and name based on verdict if provided, otherwise score
  let strokeColor = '#10b981'; // Default Safe
  let riskName = 'SAFE';

  if (verdict) {
    switch (verdict) {
      case 'CRITICAL': strokeColor = '#ef4444'; riskName = 'CRITICAL'; break;
      case 'HIGH_RISK': strokeColor = '#f97316'; riskName = 'HIGH RISK'; break;
      case 'SUSPICIOUS': strokeColor = '#f59e0b'; riskName = 'SUSPICIOUS'; break;
      case 'LOW_RISK': strokeColor = '#0ea5e9'; riskName = 'LOW RISK'; break;
      case 'UNKNOWN': strokeColor = '#64748b'; riskName = 'UNKNOWN'; break;
      case 'SAFE': strokeColor = '#10b981'; riskName = 'SAFE'; break;
    }
  } else {
    // Fallback if no verdict provided
    if (score >= 80) {
      strokeColor = '#ef4444'; // Critical
      riskName = 'CRITICAL';
    } else if (score >= 60) {
      strokeColor = '#f97316'; // High
      riskName = 'HIGH RISK';
    } else if (score >= 40) {
      strokeColor = '#f59e0b'; // Suspicious
      riskName = 'SUSPICIOUS';
    } else if (score >= 20) {
      strokeColor = '#0ea5e9'; // Low
      riskName = 'LOW RISK';
    }
  }

  return (
    <div className="flex flex-col items-center justify-center relative select-none">
      <div className="relative" style={{ width: size, height: size }}>
        <svg
          width={size}
          height={size}
          className="transform -rotate-[135deg]"
          viewBox={`0 0 ${size} ${size}`}
        >
          {/* Background Track */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="transparent"
            stroke="currentColor"
            className="text-slate-200 dark:text-cyber-800/80"
            strokeWidth={strokeWidth}
            strokeDasharray={`${totalArcLength} ${circumference}`}
            strokeLinecap="round"
          />

          {/* Animated Value Arc */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="transparent"
            stroke={strokeColor}
            strokeWidth={strokeWidth}
            strokeDasharray={`${totalArcLength} ${circumference}`}
            strokeDashoffset={offset}
            strokeLinecap="round"
            className="transition-all duration-300 ease-out"
          />
        </svg>

        {/* Center Readout */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <span className="text-4xl sm:text-5xl font-extrabold tracking-tight font-mono text-slate-900 dark:text-white">
            {displayedScore}
          </span>
          <span className="text-xs uppercase tracking-wider font-semibold text-slate-500 dark:text-cyber-400 mt-0.5">
            / 100 Risk
          </span>
        </div>
      </div>

      <div className="text-center mt-1">
        <span
          className="text-xs font-bold tracking-wider px-2.5 py-0.5 rounded-full font-mono"
          style={{
            backgroundColor: `${strokeColor}15`,
            color: strokeColor,
          }}
        >
          {riskName}
        </span>
      </div>
    </div>
  );
}
