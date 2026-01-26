# Zopp Design System

## Direction: Amber Terminal

**Feel:** Industrial precision. Cold neutrals with amber signal color. Like server equipment LEDs against steel. Serious cryptographic tool that happens to be beautiful.

**Who:** Developers and DevOps engineers managing secrets. Working hours or late nights. They want security they can trust, not security that looks friendly.

**Task:** Manage encrypted secrets. Grant access. Audit permissions. The interface should make them feel in control of their security posture.

---

## Color Architecture

### Philosophy

Amber doesn't mean warm. Against cold neutrals, amber becomes a signal — attention, action, focus. Use it sparingly. Gray builds the structure. Amber communicates.

Both light and dark themes are equal citizens. The interface respects `prefers-color-scheme`.

### Token Naming

Tokens evoke the domain: `--vault-*`, `--cipher-*`, `--terminal-*`

---

### Light Theme

```css
@media (prefers-color-scheme: light) {
  :root {
    /* Base surfaces - cool slate whites */
    --vault-base: #f8fafc;
    --vault-surface-100: #ffffff;
    --vault-surface-200: #ffffff;
    --vault-surface-300: #ffffff;
    --vault-inset: #f1f5f9;        /* Recessed areas, code blocks */

    /* Text hierarchy - slate grays */
    --cipher-text: #1e293b;
    --cipher-text-secondary: #64748b;
    --cipher-text-muted: #94a3b8;
    --cipher-text-faint: #cbd5e1;

    /* Borders - subtle definition */
    --terminal-border: rgba(0, 0, 0, 0.08);
    --terminal-border-subtle: rgba(0, 0, 0, 0.05);
    --terminal-border-strong: rgba(0, 0, 0, 0.12);
    --terminal-border-focus: rgba(217, 119, 6, 0.4);

    /* Amber accent - deeper for light backgrounds */
    --amber: #d97706;
    --amber-hover: #b45309;
    --amber-muted: rgba(217, 119, 6, 0.1);
    --amber-text: #92400e;

    /* Semantic */
    --success: #059669;
    --success-muted: rgba(5, 150, 105, 0.1);
    --warning: #d97706;
    --warning-muted: rgba(217, 119, 6, 0.1);
    --error: #dc2626;
    --error-muted: rgba(220, 38, 38, 0.1);
    --info: #2563eb;
    --info-muted: rgba(37, 99, 235, 0.1);

    /* Controls */
    --control-bg: #ffffff;
    --control-border: rgba(0, 0, 0, 0.1);
    --control-focus: rgba(217, 119, 6, 0.3);
  }
}
```

---

### Dark Theme

```css
@media (prefers-color-scheme: dark) {
  :root {
    /* Base surfaces - cold slate, not warm */
    --vault-base: #0f1114;
    --vault-surface-100: #16191d;
    --vault-surface-200: #1c2027;
    --vault-surface-300: #242830;
    --vault-inset: #0a0c0e;        /* Recessed areas, code blocks */

    /* Text hierarchy - cool grays */
    --cipher-text: #e8eaed;
    --cipher-text-secondary: #9aa0a6;
    --cipher-text-muted: #5f6368;
    --cipher-text-faint: #3c4043;

    /* Borders - subtle definition */
    --terminal-border: rgba(255, 255, 255, 0.06);
    --terminal-border-subtle: rgba(255, 255, 255, 0.04);
    --terminal-border-strong: rgba(255, 255, 255, 0.10);
    --terminal-border-focus: rgba(251, 146, 60, 0.5);

    /* Amber accent - brighter for dark backgrounds */
    --amber: #f59e0b;
    --amber-hover: #fbbf24;
    --amber-muted: rgba(245, 158, 11, 0.15);
    --amber-text: #fcd34d;

    /* Semantic - slightly desaturated for dark */
    --success: #34d399;
    --success-muted: rgba(52, 211, 153, 0.15);
    --warning: #fbbf24;
    --warning-muted: rgba(251, 191, 36, 0.15);
    --error: #f87171;
    --error-muted: rgba(248, 113, 113, 0.15);
    --info: #60a5fa;
    --info-muted: rgba(96, 165, 250, 0.15);

    /* Controls */
    --control-bg: #1c2027;
    --control-border: rgba(255, 255, 255, 0.08);
    --control-focus: rgba(245, 158, 11, 0.4);
  }
}
```

---

## Typography

### Font Stack

```css
--font-sans: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
--font-mono: 'JetBrains Mono', 'Fira Code', 'SF Mono', monospace;
```

### Scale

| Role | Size | Weight | Tracking |
|------|------|--------|----------|
| Page title | 24px | 600 | -0.02em |
| Section title | 18px | 600 | -0.01em |
| Card title | 16px | 500 | normal |
| Body | 14px | 400 | normal |
| Label | 13px | 500 | 0.01em |
| Caption | 12px | 400 | 0.01em |
| Data (mono) | 13px | 400 | normal |

### Usage

- **All secret values, keys, IDs**: Monospace
- **All timestamps, versions**: Monospace
- **UI labels, descriptions**: Sans-serif
- **Data alignment**: Use `font-variant-numeric: tabular-nums`

---

## Spacing

### Base Unit: 4px

| Token | Value | Usage |
|-------|-------|-------|
| `--space-1` | 4px | Icon gaps, tight pairs |
| `--space-2` | 8px | Within buttons, compact |
| `--space-3` | 12px | Component internal |
| `--space-4` | 16px | Card padding, gaps |
| `--space-5` | 20px | Section gaps |
| `--space-6` | 24px | Major sections |
| `--space-8` | 32px | Page margins |
| `--space-10` | 40px | Large separation |

### Padding Rules

- Cards: `16px` all sides
- Inputs: `10px 12px`
- Buttons: `8px 16px`
- Modals: `24px`
- Page content: `32px` horizontal

---

## Depth Strategy: Borders Only

No shadows. This is a terminal-inspired interface.

### Border Application

```css
/* Card/panel separation */
.card {
  border: 1px solid var(--terminal-border);
}

/* Subtle internal division */
.divider {
  border-top: 1px solid var(--terminal-border-subtle);
}

/* Interactive hover */
.card:hover {
  border-color: var(--terminal-border-strong);
}

/* Focus state - amber ring */
.focusable:focus {
  outline: none;
  box-shadow: 0 0 0 2px var(--terminal-border-focus);
}
```

### No Shadows Exception

The only "shadow" is the amber focus ring, which is actually a box-shadow used as an outline alternative.

---

## Border Radius

### Scale

| Token | Value | Usage |
|-------|-------|-------|
| `--radius-sm` | 4px | Buttons, inputs |
| `--radius-md` | 6px | Cards, dropdowns |
| `--radius-lg` | 8px | Modals |
| `--radius-full` | 9999px | Pills, badges |

Technical feel = sharper corners. Don't exceed `8px` for containers.

---

## Components

### Buttons

**Primary (Amber)**
```css
.btn-primary {
  background: var(--amber);
  color: #fff;
  border: none;
  font-weight: 500;
  padding: 8px 16px;
  border-radius: var(--radius-sm);
  transition: background var(--transition-fast);
}
.btn-primary:hover {
  background: var(--amber-hover);
}
```

**Secondary (Ghost)**
```css
.btn-secondary {
  background: transparent;
  color: var(--cipher-text);
  border: 1px solid var(--terminal-border);
  padding: 8px 16px;
  border-radius: var(--radius-sm);
}
.btn-secondary:hover {
  border-color: var(--terminal-border-strong);
  background: var(--vault-surface-100);
}
```

**Destructive**
```css
.btn-destructive {
  background: transparent;
  color: var(--error);
  border: 1px solid var(--error-muted);
}
.btn-destructive:hover {
  background: var(--error-muted);
}
```

### Cards

```css
.card {
  background: var(--vault-surface-100);
  border: 1px solid var(--terminal-border);
  border-radius: var(--radius-md);
  padding: var(--space-4);
}
```

### Inputs

```css
.input {
  background: var(--control-bg);
  border: 1px solid var(--control-border);
  border-radius: var(--radius-sm);
  padding: 10px 12px;
  color: var(--cipher-text);
  font-family: var(--font-sans);
  transition: border-color var(--transition-fast), box-shadow var(--transition-fast);
}
.input:focus {
  border-color: var(--amber);
  box-shadow: 0 0 0 2px var(--control-focus);
  outline: none;
}

/* Monospace inputs for secrets/keys */
.input-mono {
  font-family: var(--font-mono);
  font-size: 13px;
}
```

### Secrets Display (Signature Element)

The secret value display is the signature — terminal-style, monospace, with reveal interaction.

```css
.secret-value {
  font-family: var(--font-mono);
  font-size: 13px;
  color: var(--cipher-text);
  background: var(--vault-inset);
  padding: 8px 12px;
  border: 1px solid var(--terminal-border-subtle);
  border-radius: var(--radius-sm);
}

.secret-value-hidden {
  color: var(--cipher-text-muted);
  letter-spacing: 0.1em;
}

.secret-key {
  font-family: var(--font-mono);
  font-weight: 500;
  color: var(--amber-text);
}
```

### Sidebar

Same background as content. Border separation only.

```css
.sidebar {
  background: var(--vault-base);
  border-right: 1px solid var(--terminal-border);
  width: 240px;
}

.sidebar-item {
  padding: 8px 16px;
  color: var(--cipher-text-secondary);
  border-radius: var(--radius-sm);
  transition: background var(--transition-fast), color var(--transition-fast);
}

.sidebar-item:hover {
  background: var(--vault-surface-100);
  color: var(--cipher-text);
}

.sidebar-item-active {
  background: var(--amber-muted);
  color: var(--amber-text);
}
```

### Tables (Secrets List)

```css
.table {
  width: 100%;
  border-collapse: collapse;
}

.table th {
  text-align: left;
  font-size: 12px;
  font-weight: 500;
  color: var(--cipher-text-muted);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  padding: 12px 16px;
  border-bottom: 1px solid var(--terminal-border);
}

.table td {
  padding: 12px 16px;
  border-bottom: 1px solid var(--terminal-border-subtle);
}

.table tr:hover {
  background: var(--vault-surface-100);
}
```

### Badges

```css
.badge {
  display: inline-flex;
  padding: 2px 8px;
  font-size: 11px;
  font-weight: 500;
  border-radius: var(--radius-full);
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.badge-amber {
  background: var(--amber-muted);
  color: var(--amber-text);
}

.badge-success {
  background: var(--success-muted);
  color: var(--success);
}

.badge-error {
  background: var(--error-muted);
  color: var(--error);
}
```

### Modals

```css
.modal-backdrop {
  background: rgba(0, 0, 0, 0.6);
}

.modal {
  background: var(--vault-surface-100);
  border: 1px solid var(--terminal-border);
  border-radius: var(--radius-lg);
  padding: var(--space-6);
  max-width: 480px;
  width: 100%;
}

.modal-title {
  font-size: 18px;
  font-weight: 600;
  color: var(--cipher-text);
  margin-bottom: var(--space-4);
}
```

---

## Animation

```css
--transition-fast: 150ms ease-out;
--transition-normal: 200ms ease-out;
```

Apply to:
- Hover states
- Focus states
- Border color changes
- Background color changes

No spring/bounce effects. This is a serious tool.

---

## Icon Style

- Use outlined icons (Heroicons outline style)
- 20px for inline icons
- 24px for standalone/action icons
- Color follows text hierarchy unless interactive

---

## States

### Interactive Elements

| State | Treatment |
|-------|-----------|
| Default | Base styling |
| Hover | Border-strong, surface-100 bg |
| Focus | Amber ring (2px) |
| Active | Slight bg shift |
| Disabled | 50% opacity, no pointer events |

### Data States

| State | Treatment |
|-------|-----------|
| Loading | Skeleton pulse or spinner |
| Empty | Muted text + action CTA |
| Error | Error color, alert component |

---

## Tailwind Integration

To implement in your existing Tailwind config, extend with custom colors:

```js
// tailwind.config.js
module.exports = {
  darkMode: 'media', // Respects prefers-color-scheme
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
        },
      },
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'SF Mono', 'monospace'],
      },
      borderRadius: {
        sm: '4px',
        md: '6px',
        lg: '8px',
      },
    },
  },
}
```

---

## What This Replaces

| DaisyUI Default | Zopp Pattern |
|-----------------|--------------|
| Warm orange base | Cold slate base |
| Card shadows | Border-only cards |
| Rounded buttons | Sharper 4px radius |
| Orange everywhere | Amber as signal only |
| Component library look | Custom terminal aesthetic |

---

## Checks Before Shipping

1. **Squint test**: Can you see hierarchy without reading?
2. **Amber check**: Is amber used only for actions/focus/key data?
3. **Border check**: Are borders subtle, not the first thing you see?
4. **Mono check**: Are all data values in monospace?
5. **State check**: Does every interactive element have hover/focus/disabled?
6. **Theme check**: Does it look correct in both light and dark system settings?
