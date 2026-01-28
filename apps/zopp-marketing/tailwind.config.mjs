/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Vault backgrounds (dark mode primary)
        vault: {
          base: 'var(--vault-base)',
          50: 'var(--vault-50)',
          100: 'var(--vault-100)',
          200: 'var(--vault-200)',
          inset: 'var(--vault-inset)',
        },
        // Cipher text colors
        cipher: {
          text: 'var(--cipher-text)',
          secondary: 'var(--cipher-secondary)',
          muted: 'var(--cipher-muted)',
          faint: 'var(--cipher-faint)',
        },
        // Terminal borders
        terminal: {
          border: 'var(--terminal-border)',
          'border-strong': 'var(--terminal-border-strong)',
          'border-subtle': 'var(--terminal-border-subtle)',
        },
        // Amber accent
        amber: {
          DEFAULT: 'var(--amber)',
          hover: 'var(--amber-hover)',
          muted: 'var(--amber-muted)',
          text: 'var(--amber-text)',
        },
        // Semantic colors
        success: 'var(--success)',
        warning: 'var(--warning)',
        error: 'var(--error)',
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
    },
  },
  plugins: [],
};
