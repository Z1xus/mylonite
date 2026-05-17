import { describe, expect, it } from "vitest";
import * as Y from "yjs";

import {
  applyMarkdownUpdate,
  encodeMarkdownDeleteUpdate,
  encodeMarkdownRenameUpdate,
  encodeMarkdownUpsertUpdate,
  getMarkdownText,
  MarkdownTree,
} from "./yjs-markdown";

function markdownDoc(): { doc: Y.Doc; tree: MarkdownTree } {
  const doc = new Y.Doc();
  return { doc, tree: doc.getMap<Y.Map<unknown>>("tree") };
}

describe("Yjs markdown tree updates", () => {
  it("applies markdown upsert updates to another document", () => {
    const local = markdownDoc();
    const remote = markdownDoc();

    const updateHex = encodeMarkdownUpsertUpdate(local.doc, local.tree, "note.md", "hello");
    applyMarkdownUpdate(remote.doc, updateHex);

    const entry = remote.tree.get("note.md");
    expect(entry?.get("kind")).toBe("markdown");
    expect(entry?.get("path")).toBe("note.md");
    expect(getMarkdownText(remote.tree, "note.md")?.toString()).toBe("hello");
  });

  it("applies markdown delete updates to another document", () => {
    const local = markdownDoc();
    const remote = markdownDoc();

    applyMarkdownUpdate(remote.doc, encodeMarkdownUpsertUpdate(local.doc, local.tree, "note.md", "hello"));
    applyMarkdownUpdate(remote.doc, encodeMarkdownDeleteUpdate(local.doc, local.tree, "note.md"));

    expect(remote.tree.has("note.md")).toBe(false);
  });

  it("applies markdown rename updates as old-path delete plus new-path content", () => {
    const local = markdownDoc();
    const remote = markdownDoc();

    applyMarkdownUpdate(remote.doc, encodeMarkdownUpsertUpdate(local.doc, local.tree, "old.md", "hello"));
    applyMarkdownUpdate(remote.doc, encodeMarkdownRenameUpdate(local.doc, local.tree, "old.md", "folder/new.md", "hello"));

    expect(remote.tree.has("old.md")).toBe(false);
    const entry = remote.tree.get("folder/new.md");
    expect(entry?.get("renamedFrom")).toBe("old.md");
    expect(getMarkdownText(remote.tree, "folder/new.md")?.toString()).toBe("hello");
  });
});
