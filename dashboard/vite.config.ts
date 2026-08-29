import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The dashboard is served by the gw binary from an embedded filesystem, and its
// CSP allows scripts only from 'self'. Nothing may be inlined and nothing may
// come from a CDN, so the build emits plain hashed files under assets/ — which
// is also the prefix the server caches immutably.
export default defineConfig({
  plugins: [react()],
  resolve: {
    // Mirrors the paths mapping in tsconfig.app.json. tsc resolves it on its
    // own; the bundler needs telling separately, and a mismatch fails only at
    // build time.
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // Vite inlines small assets as data: URIs by default. img-src allows data:,
    // but keeping everything as real files means the asset cache rules apply
    // uniformly and nothing silently grows the entry chunk.
    assetsInlineLimit: 0,
    rollupOptions: {
      output: {
        // The editor is the single largest dependency and is only needed on the
        // Xray page. Splitting it keeps the first paint small on a thin client
        // serving over a LAN.
        manualChunks: {
          editor: ["@uiw/react-codemirror", "@codemirror/lang-json", "@codemirror/lint"],
        },
      },
    },
  },
  server: {
    proxy: {
      "/api": { target: "https://127.0.0.1:8088", changeOrigin: true, secure: false },
    },
  },
});
