import loroWasmGzip from "loro-wasm-gzip";

export function loroWasm(): Promise<ArrayBuffer> {
  const stream = new Blob([loroWasmGzip as BlobPart]).stream().pipeThrough(new DecompressionStream("gzip"));
  return new Response(stream).arrayBuffer();
}
