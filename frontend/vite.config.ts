import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The built console replaces forgetrace/api/static, so `make serve` needs no Node at runtime.
export default defineConfig({
  plugins: [react()],
  base: "/static/",
  build: { assetsInlineLimit: 0, outDir: "../forgetrace/api/static", emptyOutDir: true, chunkSizeWarningLimit: 2500 },
  server: {
    proxy: Object.fromEntries(
      ["health", "incidents", "events", "alerts", "rules", "workspaces", "overview", "detections", "metrics", "inputs",
        "runs", "walkthrough", "graph", "stream", "explain", "live"].map((p) => [`/${p}`, "http://127.0.0.1:8000"])),
  },
});
