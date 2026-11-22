import path from "node:path";
import { fileURLToPath } from "node:url";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const uiRoot = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  root: uiRoot,
  base: "./",
  publicDir: path.resolve(uiRoot, "public"),
  clearScreen: false,
  envPrefix: ["VITE_", "TAURI_ENV_"],
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(uiRoot, "src"),
    },
  },
  server: {
    port: 1420,
    strictPort: true,
    host: "localhost",
  },
  preview: {
    port: 1420,
    strictPort: true,
  },
  build: {
    outDir: path.resolve(uiRoot, "dist"),
    emptyOutDir: true,
    target: ["es2022", "chrome105", "safari15"],
    minify: "esbuild",
    cssMinify: true,
    sourcemap: false,
    reportCompressedSize: true,
    chunkSizeWarningLimit: 240,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes("node_modules/react/") || id.includes("node_modules/react-dom/") || id.includes("node_modules/scheduler/")) {
            return "vendor-react";
          }
          if (id.includes("node_modules/@tauri-apps/")) {
            return "vendor-tauri";
          }
          if (id.includes("node_modules/lucide-react/")) {
            return "vendor-icons";
          }
          return undefined;
        },
        entryFileNames: "assets/[name]-[hash].js",
        chunkFileNames: "assets/[name]-[hash].js",
        assetFileNames: "assets/[name]-[hash][extname]",
      },
    },
  },
});
