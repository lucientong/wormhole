import { defineConfig } from "vite";
import solid from "vite-plugin-solid";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [solid(), tailwindcss()],
  build: {
    outDir: "../pkg/web/dist",
    emptyOutDir: true,
    target: "esnext",
  },
  server: {
    proxy: {
      "/api": "http://localhost:4040",
    },
  },
});
