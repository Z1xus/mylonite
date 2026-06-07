import { copyFile, mkdir, stat } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const source = resolve("plugin", "main.js");
const target = resolve("main.js");

try {
  const sourceStats = await stat(source);
  if (!sourceStats.isFile()) {
    throw new Error(`${source} is not a file`);
  }
} catch (error) {
  throw new Error("Plugin build did not produce plugin/main.js", { cause: error });
}

await mkdir(dirname(target), { recursive: true });
await copyFile(source, target);
