// SPDX-License-Identifier: Apache-2.0
// Theme colors are CSS variables holding plain hex values. Wrapping them in
// color-mix with Tailwind's <alpha-value> placeholder makes opacity suffixes
// such as bg-primary/5 or bg-muted-foreground/30 work; without it Tailwind
// silently emits no rule for them.
const v = (name) => `color-mix(in srgb, var(--${name}) calc(<alpha-value> * 100%), transparent)`;

/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Geist", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["Geist Mono", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      colors: {
        border: v("border"),
        input: v("input"),
        ring: v("ring"),
        background: v("background"),
        foreground: v("foreground"),
        primary: {
          DEFAULT: v("primary"),
          foreground: v("primary-foreground"),
        },
        secondary: {
          DEFAULT: v("secondary"),
          foreground: v("secondary-foreground"),
        },
        destructive: {
          DEFAULT: v("destructive"),
          foreground: v("destructive-foreground"),
        },
        muted: {
          DEFAULT: v("muted"),
          foreground: v("muted-foreground"),
        },
        accent: {
          DEFAULT: v("accent"),
          foreground: v("accent-foreground"),
        },
        popover: {
          DEFAULT: v("popover"),
          foreground: v("popover-foreground"),
        },
        card: {
          DEFAULT: v("card"),
          foreground: v("card-foreground"),
        },
        teal: {
          DEFAULT: v("teal"),
          dark: v("teal-dark"),
          light: v("teal-light"),
        },
        event: {
          allow: v("event-allow"),
          "allow-bg": v("event-allow-bg"),
          "allow-text": v("event-allow-text"),
          pii: v("event-pii"),
          "pii-bg": v("event-pii-bg"),
          "pii-text": v("event-pii-text"),
          block: v("event-block"),
          "block-bg": v("event-block-bg"),
          "block-text": v("event-block-text"),
          injection: v("event-injection"),
          "injection-bg": v("event-injection-bg"),
          "injection-text": v("event-injection-text"),
          muted: v("event-muted"),
          "muted-bg": v("event-muted-bg"),
        },
      },
      borderRadius: {
        lg: v("radius"),
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },
    },
  },
  plugins: [],
};
