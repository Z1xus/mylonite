const QR_CONFIGS = [
  { version: 2, dataCodewords: 28, blockCount: 1, ecCodewordsPerBlock: 16, alignment: [6, 18], errorCorrectionLevel: 0b00 },
  { version: 3, dataCodewords: 44, blockCount: 1, ecCodewordsPerBlock: 26, alignment: [6, 22], errorCorrectionLevel: 0b00 },
  { version: 4, dataCodewords: 64, blockCount: 2, ecCodewordsPerBlock: 18, alignment: [6, 26], errorCorrectionLevel: 0b00 },
  { version: 8, dataCodewords: 194, blockCount: 2, ecCodewordsPerBlock: 24, alignment: [6, 24, 42], errorCorrectionLevel: 0b01 },
];
const ALPHANUMERIC_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

type QrConfig = typeof QR_CONFIGS[number];

type Module = 0 | 1 | -1;

export function qrSvgDataUrl(text: string, scale = 5): string {
  const modules = encodeQr(text);
  const quiet = 4;
  const size = modules.length + quiet * 2;
  const rects: string[] = [];
  for (let y = 0; y < modules.length; y += 1) {
    for (let x = 0; x < modules.length; x += 1) {
      if (modules[y][x]) {
        rects.push(`<rect x="${x + quiet}" y="${y + quiet}" width="1" height="1"/>`);
      }
    }
  }
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="${size * scale}" height="${size * scale}"><rect width="100%" height="100%" fill="#fff"/><g fill="#000">${rects.join("")}</g></svg>`;
  return `data:image/svg+xml,${encodeURIComponent(svg)}`;
}

function encodeQr(text: string): boolean[][] {
  const config = selectConfig(text);
  const data = makeDataCodewords(text);
  const codewords = addErrorCorrection(data, config);
  let bestModules: boolean[][] | null = null;
  let bestPenalty = Number.POSITIVE_INFINITY;
  for (let mask = 0; mask < 8; mask += 1) {
    const { modules, functionModules } = makeBaseMatrix(config);
    drawCodewords(modules, functionModules, codewords, mask);
    drawFormatBits(modules, config, mask);
    drawVersionBits(modules, config);
    const boolModules = modules.map((row) => row.map((value) => value === 1));
    const penalty = penaltyScore(boolModules);
    if (penalty < bestPenalty) {
      bestPenalty = penalty;
      bestModules = boolModules;
    }
  }
  if (!bestModules) {
    throw new Error("QR generation failed");
  }
  return bestModules;
}

function makeDataCodewords(text: string): number[] {
  if (isAlphanumericText(text)) {
    const config = selectConfigForBits(alphanumericBitLength(text));
    return makeDataCodewordsForBits(alphanumericBits(text), config);
  }
  const bytes = new TextEncoder().encode(text);
  const config = selectConfig(text);
  return makeDataCodewordsForBytes(bytes, config);
}

function selectConfig(text: string): QrConfig {
  const bytes = new TextEncoder().encode(text);
  const config = QR_CONFIGS.find((candidate) => bytes.length <= candidate.dataCodewords - 3);
  if (!config) {
    throw new Error("invite is too long for QR code");
  }
  return config;
}

function selectConfigForBits(bitLength: number): QrConfig {
  const config = QR_CONFIGS.find((candidate) => bitLength <= candidate.dataCodewords * 8);
  if (!config) {
    throw new Error("invite is too long for QR code");
  }
  return config;
}

function makeDataCodewordsForBytes(bytes: Uint8Array, config: QrConfig): number[] {
  const bits: number[] = [];
  appendBits(bits, 0b0100, 4);
  appendBits(bits, bytes.length, 8);
  for (const byte of bytes) {
    appendBits(bits, byte, 8);
  }
  return makeDataCodewordsForBits(bits, config);
}

function makeDataCodewordsForBits(bits: number[], config: QrConfig): number[] {
  appendBits(bits, 0, Math.min(4, config.dataCodewords * 8 - bits.length));
  while (bits.length % 8 !== 0) {
    bits.push(0);
  }
  const data: number[] = [];
  for (let index = 0; index < bits.length; index += 8) {
    let value = 0;
    for (let offset = 0; offset < 8; offset += 1) {
      value = (value << 1) | bits[index + offset];
    }
    data.push(value);
  }
  for (let pad = 0xec; data.length < config.dataCodewords; pad = pad === 0xec ? 0x11 : 0xec) {
    data.push(pad);
  }
  return data;
}

function alphanumericBits(text: string): number[] {
  const bits: number[] = [];
  appendBits(bits, 0b0010, 4);
  appendBits(bits, text.length, 9);
  for (let index = 0; index < text.length; index += 2) {
    const first = ALPHANUMERIC_CHARS.indexOf(text[index]);
    const second = index + 1 < text.length ? ALPHANUMERIC_CHARS.indexOf(text[index + 1]) : -1;
    if (second >= 0) {
      appendBits(bits, first * 45 + second, 11);
    } else {
      appendBits(bits, first, 6);
    }
  }
  return bits;
}

function alphanumericBitLength(text: string): number {
  return 4 + 9 + Math.floor(text.length / 2) * 11 + (text.length % 2 === 0 ? 0 : 6);
}

function isAlphanumericText(text: string): boolean {
  return Array.from(text).every((char) => ALPHANUMERIC_CHARS.includes(char));
}

function addErrorCorrection(data: number[], config: QrConfig): number[] {
  const generator = reedSolomonGenerator(config.ecCodewordsPerBlock);
  const blocks: number[][] = [];
  const ecc: number[][] = [];
  const dataCodewordsPerBlock = config.dataCodewords / config.blockCount;
  for (let block = 0; block < config.blockCount; block += 1) {
    const start = block * dataCodewordsPerBlock;
    const chunk = data.slice(start, start + dataCodewordsPerBlock);
    blocks.push(chunk);
    ecc.push(reedSolomonRemainder(chunk, generator));
  }
  const out: number[] = [];
  for (let index = 0; index < dataCodewordsPerBlock; index += 1) {
    for (const block of blocks) {
      out.push(block[index]);
    }
  }
  for (let index = 0; index < config.ecCodewordsPerBlock; index += 1) {
    for (const block of ecc) {
      out.push(block[index]);
    }
  }
  return out;
}

function makeBaseMatrix(config: QrConfig): { modules: Module[][]; functionModules: boolean[][] } {
  const size = sizeForVersion(config.version);
  const modules: Module[][] = Array.from({ length: size }, () => Array<Module>(size).fill(-1));
  const functionModules: boolean[][] = Array.from({ length: size }, () => Array<boolean>(size).fill(false));
  drawFinder(modules, functionModules, 3, 3);
  drawFinder(modules, functionModules, size - 4, 3);
  drawFinder(modules, functionModules, 3, size - 4);
  drawTiming(modules, functionModules);
  for (const y of config.alignment) {
    for (const x of config.alignment) {
      if ((x === 6 && y === 6) || (x === config.alignment.at(-1) && y === 6) || (x === 6 && y === config.alignment.at(-1))) {
        continue;
      }
      drawAlignment(modules, functionModules, x, y);
    }
  }
  setFunctionModule(modules, functionModules, 8, 4 * config.version + 9, 1);
  reserveFormatAreas(functionModules);
  reserveVersionAreas(functionModules, config);
  return { modules, functionModules };
}

function drawFinder(modules: Module[][], functionModules: boolean[][], cx: number, cy: number): void {
  const size = modules.length;
  for (let dy = -4; dy <= 4; dy += 1) {
    for (let dx = -4; dx <= 4; dx += 1) {
      const x = cx + dx;
      const y = cy + dy;
      if (x < 0 || y < 0 || x >= size || y >= size) {
        continue;
      }
      const dist = Math.max(Math.abs(dx), Math.abs(dy));
      setFunctionModule(modules, functionModules, x, y, dist !== 2 && dist !== 4 ? 1 : 0);
    }
  }
}

function drawAlignment(modules: Module[][], functionModules: boolean[][], cx: number, cy: number): void {
  for (let dy = -2; dy <= 2; dy += 1) {
    for (let dx = -2; dx <= 2; dx += 1) {
      const dist = Math.max(Math.abs(dx), Math.abs(dy));
      setFunctionModule(modules, functionModules, cx + dx, cy + dy, dist !== 1 ? 1 : 0);
    }
  }
}

function drawTiming(modules: Module[][], functionModules: boolean[][]): void {
  const size = modules.length;
  for (let i = 8; i < size - 8; i += 1) {
    const value: Module = i % 2 === 0 ? 1 : 0;
    setFunctionModule(modules, functionModules, 6, i, value);
    setFunctionModule(modules, functionModules, i, 6, value);
  }
}

function reserveFormatAreas(functionModules: boolean[][]): void {
  const size = functionModules.length;
  for (let i = 0; i < 9; i += 1) {
    functionModules[8][i] = true;
    functionModules[i][8] = true;
    functionModules[8][size - 1 - i] = true;
    functionModules[size - 1 - i][8] = true;
  }
}

function reserveVersionAreas(functionModules: boolean[][], config: QrConfig): void {
  if (config.version < 7) {
    return;
  }
  const size = functionModules.length;
  for (let i = 0; i < 6; i += 1) {
    for (let j = 0; j < 3; j += 1) {
      functionModules[i][size - 11 + j] = true;
      functionModules[size - 11 + j][i] = true;
    }
  }
}

function setFunctionModule(modules: Module[][], functionModules: boolean[][], x: number, y: number, value: Module): void {
  modules[y][x] = value;
  functionModules[y][x] = true;
}

function drawCodewords(modules: Module[][], functionModules: boolean[][], codewords: number[], mask: number): void {
  const size = modules.length;
  let bitIndex = 0;
  let upward = true;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) {
      right -= 1;
    }
    for (let vert = 0; vert < size; vert += 1) {
      const y = upward ? size - 1 - vert : vert;
      for (let col = 0; col < 2; col += 1) {
        const x = right - col;
        if (functionModules[y][x]) {
          continue;
        }
        let bit = 0;
        if (bitIndex < codewords.length * 8) {
          bit = (codewords[bitIndex >>> 3] >>> (7 - (bitIndex & 7))) & 1;
        }
        bitIndex += 1;
        if (maskBit(mask, x, y)) {
          bit ^= 1;
        }
        modules[y][x] = bit as Module;
      }
    }
    upward = !upward;
  }
}

function drawFormatBits(modules: Module[][], config: QrConfig, mask: number): void {
  const size = modules.length;
  const bits = formatBits(config, mask);
  for (let i = 0; i <= 5; i += 1) {
    modules[8][i] = ((bits >>> i) & 1) as Module;
  }
  modules[8][7] = ((bits >>> 6) & 1) as Module;
  modules[8][8] = ((bits >>> 7) & 1) as Module;
  modules[7][8] = ((bits >>> 8) & 1) as Module;
  for (let i = 9; i < 15; i += 1) {
    modules[14 - i][8] = ((bits >>> i) & 1) as Module;
  }
  for (let i = 0; i < 8; i += 1) {
    modules[size - 1 - i][8] = ((bits >>> i) & 1) as Module;
  }
  for (let i = 8; i < 15; i += 1) {
    modules[8][size - 15 + i] = ((bits >>> i) & 1) as Module;
  }
  modules[size - 8][8] = 1;
}

function drawVersionBits(modules: Module[][], config: QrConfig): void {
  if (config.version < 7) {
    return;
  }
  const size = modules.length;
  let bits = config.version;
  for (let i = 0; i < 12; i += 1) {
    bits = (bits << 1) ^ (((bits >>> 11) & 1) * 0x1f25);
  }
  bits = (config.version << 12) | bits;
  for (let i = 0; i < 18; i += 1) {
    const bit = ((bits >>> i) & 1) as Module;
    const a = size - 11 + (i % 3);
    const b = Math.floor(i / 3);
    modules[b][a] = bit;
    modules[a][b] = bit;
  }
}

function maskBit(mask: number, x: number, y: number): boolean {
  switch (mask) {
    case 0: return (x + y) % 2 === 0;
    case 1: return y % 2 === 0;
    case 2: return x % 3 === 0;
    case 3: return (x + y) % 3 === 0;
    case 4: return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0;
    case 5: return ((x * y) % 2) + ((x * y) % 3) === 0;
    case 6: return (((x * y) % 2) + ((x * y) % 3)) % 2 === 0;
    case 7: return (((x + y) % 2) + ((x * y) % 3)) % 2 === 0;
    default: throw new Error("invalid QR mask");
  }
}

function formatBits(config: QrConfig, mask: number): number {
  let data = (config.errorCorrectionLevel << 3) | mask;
  let bits = data << 10;
  for (let i = 14; i >= 10; i -= 1) {
    if (((bits >>> i) & 1) !== 0) {
      bits ^= 0x537 << (i - 10);
    }
  }
  return (((data << 10) | bits) ^ 0x5412) & 0x7fff;
}

function penaltyScore(modules: boolean[][]): number {
  const size = modules.length;
  let penalty = 0;
  for (let y = 0; y < size; y += 1) {
    penalty += linePenalty(modules[y]);
  }
  for (let x = 0; x < size; x += 1) {
    penalty += linePenalty(modules.map((row) => row[x]));
  }
  for (let y = 0; y < size - 1; y += 1) {
    for (let x = 0; x < size - 1; x += 1) {
      const color = modules[y][x];
      if (modules[y][x + 1] === color && modules[y + 1][x] === color && modules[y + 1][x + 1] === color) {
        penalty += 3;
      }
    }
  }
  const dark = modules.flat().filter(Boolean).length;
  const percent = (dark * 100) / (size * size);
  penalty += Math.floor(Math.abs(percent - 50) / 5) * 10;
  return penalty;
}

function linePenalty(line: boolean[]): number {
  let penalty = 0;
  let runColor = line[0];
  let runLength = 1;
  for (let i = 1; i < line.length; i += 1) {
    if (line[i] === runColor) {
      runLength += 1;
      if (runLength === 5) {
        penalty += 3;
      } else if (runLength > 5) {
        penalty += 1;
      }
    } else {
      runColor = line[i];
      runLength = 1;
    }
  }
  return penalty;
}

function appendBits(bits: number[], value: number, count: number): void {
  for (let i = count - 1; i >= 0; i -= 1) {
    bits.push((value >>> i) & 1);
  }
}

function sizeForVersion(version: number): number {
  return 17 + 4 * version;
}

function reedSolomonGenerator(degree: number): number[] {
  let result = [1];
  for (let i = 0; i < degree; i += 1) {
    const next = Array.from({ length: result.length + 1 }).fill(0) as number[];
    for (let j = 0; j < result.length; j += 1) {
      next[j] ^= gfMultiply(result[j], gfPow(2, i));
      next[j + 1] ^= result[j];
    }
    result = next;
  }
  return result;
}

function reedSolomonRemainder(data: number[], generator: number[]): number[] {
  const result = Array.from({ length: generator.length - 1 }).fill(0) as number[];
  for (const byte of data) {
    const factor = byte ^ result.shift()!;
    result.push(0);
    for (let i = 0; i < result.length; i += 1) {
      result[i] ^= gfMultiply(generator[i], factor);
    }
  }
  return result;
}

function gfPow(x: number, power: number): number {
  let result = 1;
  for (let i = 0; i < power; i += 1) {
    result = gfMultiply(result, x);
  }
  return result;
}

function gfMultiply(x: number, y: number): number {
  let z = 0;
  for (let i = 7; i >= 0; i -= 1) {
    z = (z << 1) ^ (((z >>> 7) & 1) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z & 0xff;
}
