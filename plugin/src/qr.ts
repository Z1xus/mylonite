import qrcode from "qrcode-generator";

export function qrSvgDataUrl(text: string, scale = 5): string {
  const qr = qrcode(0, "M");
  qr.addData(text);
  qr.make();

  const quiet = 4;
  const moduleCount = qr.getModuleCount();
  const size = moduleCount + quiet * 2;
  const rects: string[] = [];

  for (let y = 0; y < moduleCount; y += 1) {
    for (let x = 0; x < moduleCount; x += 1) {
      if (qr.isDark(y, x)) {
        rects.push(`<rect x="${x + quiet}" y="${y + quiet}" width="1" height="1"/>`);
      }
    }
  }

  const svg = [
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="${size * scale}" height="${size * scale}" shape-rendering="crispEdges">`,
    `<rect width="100%" height="100%" fill="#fff"/>`,
    `<g fill="#000">${rects.join("")}</g>`,
    `</svg>`,
  ].join("");
  return `data:image/svg+xml,${encodeURIComponent(svg)}`;
}
