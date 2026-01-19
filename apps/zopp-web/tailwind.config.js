/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.rs",
    "./index.html",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'SF Mono', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [require("daisyui")],
  daisyui: {
    themes: [
      {
        // Light theme - Coral/Amber warm palette (matches docs)
        zopp: {
          "primary": "#f97316",           // Orange-500
          "primary-content": "#ffffff",
          "secondary": "#ea580c",         // Orange-600
          "secondary-content": "#ffffff",
          "accent": "#fb923c",            // Orange-400
          "accent-content": "#1a1412",
          "neutral": "#44403c",           // Stone-700
          "neutral-content": "#fafaf9",
          "base-100": "#fffbf7",          // Warm white
          "base-200": "#fff7f0",          // Warm light
          "base-300": "#ffedd5",          // Orange-100
          "base-content": "#1c1917",      // Stone-900
          "info": "#0ea5e9",
          "info-content": "#ffffff",
          "success": "#22c55e",
          "success-content": "#ffffff",
          "warning": "#eab308",
          "warning-content": "#1a1412",
          "error": "#ef4444",
          "error-content": "#ffffff",
          "--rounded-box": "0.75rem",
          "--rounded-btn": "0.5rem",
          "--rounded-badge": "0.375rem",
          "--animation-btn": "0.2s",
          "--animation-input": "0.2s",
          "--btn-focus-scale": "0.98",
          "--border-btn": "1px",
          "--tab-border": "1px",
          "--tab-radius": "0.5rem",
        },
      },
      {
        // Dark theme - Warm dark palette (matches docs dark mode)
        "zopp-dark": {
          "primary": "#fb923c",           // Orange-400
          "primary-content": "#1a1412",
          "secondary": "#f97316",         // Orange-500
          "secondary-content": "#1a1412",
          "accent": "#fdba74",            // Orange-300
          "accent-content": "#1a1412",
          "neutral": "#a8a29e",           // Stone-400
          "neutral-content": "#1a1412",
          "base-100": "#1a1412",          // Warm dark
          "base-200": "#231c18",          // Warm dark surface
          "base-300": "#2d1f18",          // Warm dark elevated
          "base-content": "#fafaf9",      // Stone-50
          "info": "#38bdf8",
          "info-content": "#1a1412",
          "success": "#4ade80",
          "success-content": "#1a1412",
          "warning": "#facc15",
          "warning-content": "#1a1412",
          "error": "#f87171",
          "error-content": "#1a1412",
          "--rounded-box": "0.75rem",
          "--rounded-btn": "0.5rem",
          "--rounded-badge": "0.375rem",
          "--animation-btn": "0.2s",
          "--animation-input": "0.2s",
          "--btn-focus-scale": "0.98",
          "--border-btn": "1px",
          "--tab-border": "1px",
          "--tab-radius": "0.5rem",
        },
      },
    ],
    darkTheme: "zopp-dark",
    base: true,
    styled: true,
    utils: true,
    prefix: "",
    logs: true,
    themeRoot: ":root",
  },
}
