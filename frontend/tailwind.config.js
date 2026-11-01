export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#070B14", bg2: "#0B1220", panel: "#101827", raised: "#151F30", line: "#253247", line2: "#1A2536",
        cyan: { DEFAULT: "#26D9D0", dim: "#12B8A6" }, crit: "#EF4444", warn: "#F59E0B", ok: "#22C55E",
        ink: "#E5E7EB", sub: "#94A3B8", mute: "#64748B",
      },
      fontFamily: {
        sans: ['"Inter Variable"', "system-ui", "sans-serif"],
        mono: ['"JetBrains Mono Variable"', "ui-monospace", "Menlo", "monospace"],
      },
      fontSize: { "2xs": ["10.5px", "14px"], xs: ["11.5px", "16px"], sm: ["12.5px", "18px"], base: ["13.5px", "20px"] },
    },
  },
};
