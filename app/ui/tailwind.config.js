// SPDX-License-Identifier: Apache-2.0
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
        border: "var(--border)",
        input: "var(--input)",
        ring: "var(--ring)",
        background: "var(--background)",
        foreground: "var(--foreground)",
        primary: {
          DEFAULT: "var(--primary)",
          foreground: "var(--primary-foreground)",
        },
        secondary: {
          DEFAULT: "var(--secondary)",
          foreground: "var(--secondary-foreground)",
        },
        destructive: {
          DEFAULT: "var(--destructive)",
          foreground: "var(--destructive-foreground)",
        },
        muted: {
          DEFAULT: "var(--muted)",
          foreground: "var(--muted-foreground)",
        },
        accent: {
          DEFAULT: "var(--accent)",
          foreground: "var(--accent-foreground)",
        },
        popover: {
          DEFAULT: "var(--popover)",
          foreground: "var(--popover-foreground)",
        },
        card: {
          DEFAULT: "var(--card)",
          foreground: "var(--card-foreground)",
        },
        teal: {
          DEFAULT: "var(--teal)",
          dark: "var(--teal-dark)",
          light: "var(--teal-light)",
        },
        event: {
          allow: "var(--event-allow)",
          "allow-bg": "var(--event-allow-bg)",
          "allow-text": "var(--event-allow-text)",
          pii: "var(--event-pii)",
          "pii-bg": "var(--event-pii-bg)",
          "pii-text": "var(--event-pii-text)",
          block: "var(--event-block)",
          "block-bg": "var(--event-block-bg)",
          "block-text": "var(--event-block-text)",
          injection: "var(--event-injection)",
          "injection-bg": "var(--event-injection-bg)",
          "injection-text": "var(--event-injection-text)",
          muted: "var(--event-muted)",
          "muted-bg": "var(--event-muted-bg)",
        },
      },
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },
    },
  },
  plugins: [],
};
