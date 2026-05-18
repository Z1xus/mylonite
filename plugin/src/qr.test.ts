import { describe, expect, it } from "vitest";

import { qrSvgDataUrl } from "./qr";

describe("qrSvgDataUrl", () => {
  it("renders invite text as an SVG data URL", () => {
    const url = qrSvgDataUrl("MYLONITE:test");

    expect(url).toMatch(/^data:image\/svg\+xml,/);
    expect(decodeURIComponent(url.slice("data:image/svg+xml,".length))).toContain("<svg");
  });
});
