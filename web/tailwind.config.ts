import type { Config } from "tailwindcss";

// Brand tokens carried over from the existing landing page. Phase 0 uses a
// LIGHT background (white / gray) instead of the landing page's dark hero,
// while keeping the same red accent, serif headlines, and mono eyebrows.
const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./lib/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        black: "#0c0c0c",
        "black-mid": "#1a1a1a",
        red: {
          DEFAULT: "#da3434",
          lt: "#e86060",
          dk: "#c22020",
        },
        white: "#ffffff",
        gray: {
          DEFAULT: "#f4f4f4",
          line: "#e8e8e8",
        },
        ink: {
          DEFAULT: "#0c0c0c",
          mid: "#4a4a4a",
          lt: "#888888",
        },
      },
      fontFamily: {
        serif: ["var(--font-serif)", "Georgia", "serif"],
        sans: ["var(--font-sans)", "system-ui", "sans-serif"],
        mono: ["var(--font-mono)", "monospace"],
      },
      maxWidth: {
        content: "1100px",
      },
    },
  },
  plugins: [],
};

export default config;
