import { decompress } from "fzstd";
import loroWasmZstd from "loro-wasm-zstd";

export function loroWasm(): Uint8Array {
  return decompress(loroWasmZstd);
}
