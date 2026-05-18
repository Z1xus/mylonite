import { describe, expect, it } from "vitest";

import { qrSvgDataUrl } from "./qr";

describe("qrSvgDataUrl", () => {
  it("renders invite text as an SVG data URL", () => {
    const url = qrSvgDataUrl("MYLONITE:test");

    expect(url).toMatch(/^data:image\/svg\+xml,/);
    expect(decodeURIComponent(url.slice("data:image/svg+xml,".length))).toContain("<svg");
  });

  it("uses a compact QR version for uppercase invite URLs", () => {
    const url = qrSvgDataUrl("HTTPS://MYLONITE.Z1X.US/P/T42B65HMWYVV");

    expect(decodeURIComponent(url.slice("data:image/svg+xml,".length))).toContain("viewBox=\"0 0 37 37\"");
  });
});
