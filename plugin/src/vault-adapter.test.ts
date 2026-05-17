import { describe, expect, it } from "vitest";

import { normalizeVaultPath } from "./vault-adapter";

describe("vault path validation", () => {
  it("normalizes safe relative paths", () => {
    expect(normalizeVaultPath("Notes\\a.md")).toBe("Notes/a.md");
  });

  it("rejects paths that cannot be safely addressed inside the vault", () => {
    expect(() => normalizeVaultPath("../outside.md")).toThrow("invalid vault path");
    expect(() => normalizeVaultPath("/absolute.md")).toThrow("invalid vault path");
    expect(() => normalizeVaultPath("Notes/../outside.md")).toThrow("invalid vault path");
    expect(() => normalizeVaultPath("bad\0name.md")).toThrow("invalid vault path");
  });
});
