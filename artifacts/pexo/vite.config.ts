import path from "node:path";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vite";

const rawPort = process.env.PORT;
if (!rawPort) throw new Error("PORT environment variable is required but was not provided.");
const port = Number(rawPort);
if (Number.isNaN(port) || port <= 0) throw new Error(`Invalid PORT value: "${rawPort}"`);

const basePath = process.env.BASE_PATH;
if (!basePath) throw new Error("BASE_PATH environment variable is required but was not provided.");

export default defineConfig({
  base: basePath,
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "src"),
      "@assets": path.resolve(import.meta.dirname, "attached_assets"),
      "@noble/hashes/sha256": path.resolve(import.meta.dirname, "node_modules/@noble/hashes/sha2.js"),
      "@noble/hashes/sha512": path.resolve(import.meta.dirname, "node_modules/@noble/hashes/sha2.js"),
      "@noble/hashes/sha3": path.resolve(import.meta.dirname, "node_modules/@noble/hashes/sha3.js"),
      "@noble/hashes/ripemd160": path.resolve(import.meta.dirname, "node_modules/@noble/hashes/legacy.js"),
      "@noble/hashes/hmac": path.resolve(import.meta.dirname, "node_modules/@noble/hashes/hmac.js"),
      "@noble/hashes/utils": path.resolve(import.meta.dirname, "node_modules/@noble/hashes/utils.js"),
      "@noble/hashes/scrypt": path.resolve(import.meta.dirname, "node_modules/@noble/hashes/scrypt.js"),
      "@noble/hashes/pbkdf2": path.resolve(import.meta.dirname, "node_modules/@noble/hashes/pbkdf2.js"),
    },
    dedupe: ["react", "react-dom"],
  },
  define: { global: "globalThis" },
  worker: { format: "es" },
  root: path.resolve(import.meta.dirname),
  build: {
    outDir: path.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true,
  },
  server: {
    port,
    strictPort: true,
    host: "0.0.0.0",
    allowedHosts: true,
    fs: { strict: true },
  },
  preview: {
    port,
    host: "0.0.0.0",
    allowedHosts: true,
  },
});
