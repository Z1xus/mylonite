import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    alias: {
      obsidian: new URL("./test/obsidian-shim.ts", import.meta.url).pathname,
    },
  },
});
