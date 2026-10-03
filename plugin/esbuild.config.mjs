import esbuild from "esbuild";
import { readFile } from "fs/promises";
import { createRequire } from "module";
import process from "process";
import { constants, zstdCompressSync } from "zlib";

const production = process.argv[2] === "production";
// SecretStorage is missing on mobile, so secrets fall back to plugin data
const allowPluginDataSecrets =
  process.env.MYLONITE_DISABLE_PLUGIN_DATA_SECRETS !== "1";

await esbuild.build({
  banner: { js: "/* Mylonite Obsidian plugin */" },
  bundle: true,
  define: {
    __MYLONITE_ALLOW_PLUGIN_DATA_SECRETS__: JSON.stringify(
      allowPluginDataSecrets,
    ),
  },
  entryPoints: ["src/main.ts"],
  external: ["obsidian"],
  format: "cjs",
  logLevel: "info",
  minify: production,
  outfile: "main.js",
  plugins: [{
    name: "loro-wasm-zstd",
    setup(build) {
      build.onResolve({ filter: /^loro-wasm-zstd$/ }, () => ({
        path: createRequire(import.meta.url).resolve("loro-crdt/web/loro_wasm_bg.wasm"),
      }));
      build.onLoad({ filter: /\.wasm$/ }, async (args) => ({
        contents: zstdCompressSync(await readFile(args.path), { params: { [constants.ZSTD_c_compressionLevel]: 22 } }),
        loader: "binary",
      }));
    },
  }],
  sourcemap: production ? false : "inline",
  target: "es2021",
  treeShaking: true,
});
