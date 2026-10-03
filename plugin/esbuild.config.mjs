import esbuild from "esbuild";
import process from "process";

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
  sourcemap: production ? false : "inline",
  target: "es2021",
  treeShaking: true,
});
