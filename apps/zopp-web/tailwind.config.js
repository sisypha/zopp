/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.rs",
    "./index.html",
  ],
  darkMode: 'media',
  theme: {
    extend: {
      colors: {
        vault: {
          base: 'var(--vault-base)',
          100: 'var(--vault-surface-100)',
          200: 'var(--vault-surface-200)',
          300: 'var(--vault-surface-300)',
          inset: 'var(--vault-inset)',
        },
        cipher: {
          text: 'var(--cipher-text)',
          secondary: 'var(--cipher-text-secondary)',
          muted: 'var(--cipher-text-muted)',
          faint: 'var(--cipher-text-faint)',
        },
        amber: {
          DEFAULT: 'var(--amber)',
          hover: 'var(--amber-hover)',
          text: 'var(--amber-text)',
          muted: 'var(--amber-muted)',
        },
        terminal: {
          border: 'var(--terminal-border)',
          'border-subtle': 'var(--terminal-border-subtle)',
          'border-strong': 'var(--terminal-border-strong)',
          'border-focus': 'var(--terminal-border-focus)',
        },
        control: {
          bg: 'var(--control-bg)',
          border: 'var(--control-border)',
          focus: 'var(--control-focus)',
        },
        success: {
          DEFAULT: 'var(--success)',
          muted: 'var(--success-muted)',
        },
        warning: {
          DEFAULT: 'var(--warning)',
          muted: 'var(--warning-muted)',
        },
        error: {
          DEFAULT: 'var(--error)',
          muted: 'var(--error-muted)',
        },
        info: {
          DEFAULT: 'var(--info)',
          muted: 'var(--info-muted)',
        },
      },
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'SF Mono', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
      borderRadius: {
        sm: '4px',
        md: '6px',
        lg: '8px',
      },
      spacing: {
        '18': '4.5rem',
        '22': '5.5rem',
      },
    },
  },
  plugins: [],
}
