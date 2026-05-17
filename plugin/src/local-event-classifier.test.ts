import { describe, expect, it, vi } from "vitest";

import { LocalEventClassifier } from "./local-event-classifier";
import { VaultStateIndex } from "./state-index";

let randomByte = 1;
vi.stubGlobal("crypto", {
  getRandomValues(bytes: Uint8Array) {
    bytes.fill(randomByte);
    randomByte = randomByte === 250 ? 1 : randomByte + 1;
    return bytes;
  },
});

describe("local event classifier", () => {
  it("classifies a new file as a create with a stable file id", () => {
    const index = new VaultStateIndex();
    const classifier = new LocalEventClassifier(index);

    const entry = classifier.classifyCreate({ path: "Notes\\a.md", kind: "markdown", content: "hello" }, 10);

    expect(entry.kind).toBe("file-create");
    expect(entry.path).toBe("Notes/a.md");
    expect(entry.fileId).toMatch(/^f[0-9a-f]{32}$/);
    expect(index.byPath("Notes/a.md")?.fileId).toBe(entry.fileId);
  });

  it("classifies same-content create as a copy with a new file id", () => {
    const index = new VaultStateIndex();
    const classifier = new LocalEventClassifier(index);
    const original = classifier.classifyCreate({ path: "a.md", kind: "markdown", content: "same" }, 10);

    const copy = classifier.classifyCreate({ path: "b.md", kind: "markdown", content: "same" }, 20);

    expect(copy.kind).toBe("file-copy");
    expect(copy.sourceFileId).toBe(original.fileId);
    expect(copy.fileId).not.toBe(original.fileId);
  });

  it("keeps the same file id across renames", () => {
    const index = new VaultStateIndex();
    const classifier = new LocalEventClassifier(index);
    const created = classifier.classifyCreate({ path: "a.md", kind: "markdown", content: "hello" }, 10);

    const renamed = classifier.classifyRename("a.md", { path: "folder/b.md", kind: "markdown", content: "hello" }, 20);

    expect(renamed.kind).toBe("file-rename");
    expect(renamed.fileId).toBe(created.fileId);
    expect(index.byPath("a.md")).toBeUndefined();
    expect(index.byPath("folder/b.md")?.fileId).toBe(created.fileId);
  });

  it("treats delete then recreate at the same path as a new file", () => {
    const index = new VaultStateIndex();
    const classifier = new LocalEventClassifier(index);
    const created = classifier.classifyCreate({ path: "a.md", kind: "markdown", content: "first" }, 10);
    const deleted = classifier.classifyDelete("a.md", "markdown", 20);

    const recreated = classifier.classifyCreate({ path: "a.md", kind: "markdown", content: "second" }, 30);

    expect(deleted.fileId).toBe(created.fileId);
    expect(recreated.fileId).not.toBe(created.fileId);
    expect(index.byPath("a.md")?.fileId).toBe(recreated.fileId);
  });
});
