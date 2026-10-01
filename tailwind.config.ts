import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          950: "#06090e",
          900: "#0a0f18",
          850: "#0f1624",
          800: "#141e30",
          750: "#1a263c",
          700: "#22314d",
          600: "#2f4368",
          500: "#415a88",
          400: "#607ea9",
          300: "#8fa9cf",
          200: "#c2d4ec",
          100: "#e5effa",
          50: "#f4f8fd",
        },
        risk: {
          safe: "#10b981",
          low: "#0ea5e9",
          suspicious: "#f59e0b",
          high: "#f97316",
          critical: "#ef4444",
          unknown: "#64748b",
        },
      },
      fontFamily: {
        sans: ["var(--font-inter)", "system-ui", "sans-serif"],
        mono: ["var(--font-jetbrains)", "monospace"],
      },
      animation: {
        "pulse-subtle": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "scan-line": "scanline 2.5s ease-in-out infinite",
        "radar-sweep": "radar 4s linear infinite",
      },
      keyframes: {
        scanline: {
          "0%, 100%": { transform: "translateY(-100%)" },
          "50%": { transform: "translateY(1000%)" },
        },
        radar: {
          "0%": { transform: "rotate(0deg)" },
          "100%": { transform: "rotate(360deg)" },
        },
      },
    },
  },
  plugins: [],
};

export default config;
