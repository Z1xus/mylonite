import { describe, expect, it } from "vitest";

import { decideRemoteV2Apply } from "./conflict-policy";
import { VaultStateIndex } from "./state-index";
import { RemoteV2Payload } from "./sync-types";
import { VaultFileState } from "./sync-state";

const fileIdA = "f" + "a".repeat(32);
const fileIdB = "f" + "b".repeat(32);

function indexWith(...files: Partial<VaultFileState>[]): VaultStateIndex {
  const index = new VaultStateIndex();
  for (const file of files) {
    index.upsertFile({
      fileId: fileIdA,
      path: "Notes/a.md",
      kind: "markdown",
      contentHash: "aa",
      tombstone: false,
      lastLocalSeq: 0,
      lastRemoteSeq: 0,
      updatedAtMs: 1,
      ...file,
    });
  }
  return index;
}

function update(overrides: Record<string, unknown> = {}): RemoteV2Payload {
  return {
    version: 2,
    kind: "file-update",
    fileId: fileIdA,
    path: "Notes/a.md",
    fileKind: "markdown",
    updateHex: "00",
    contentHash: "bb",
    ...overrides,
  } as RemoteV2Payload;
}

describe("remote apply decisions", () => {
  it("redirects updates to the file's current local path after a rename", () => {
    const index = indexWith({ path: "Moved/a.md" });

    const decision = decideRemoteV2Apply(index, update(), new Set());

    expect(decision).toEqual({ action: "apply", path: "Moved/a.md" });
  });

  it("redirects deletes to the file's current local path after a rename", () => {
    const index = indexWith({ path: "Moved/a.md" });

    const decision = decideRemoteV2Apply(index, update({ kind: "file-delete", tombstoneId: "t" + "c".repeat(32) }), new Set());

    expect(decision).toEqual({ action: "apply", path: "Moved/a.md" });
  });

  it("keeps the local version when a remote delete overlaps queued local edits", () => {
    const index = indexWith({});

    const decision = decideRemoteV2Apply(index, update({ kind: "file-delete", tombstoneId: "t" + "c".repeat(32) }), new Set([fileIdA]));

    expect(decision.action).toBe("skip-local-wins");
  });

  it("keeps the local version when a remote binary update overlaps queued local edits", () => {
    const index = indexWith({ kind: "binary", path: "assets/a.png" });

    const decision = decideRemoteV2Apply(index, update({
      path: "assets/a.png",
      fileKind: "binary",
      blobId: "c".repeat(64),
      size: 3,
      updateHex: undefined,
    }), new Set([fileIdA]));

    expect(decision.action).toBe("skip-local-wins");
  });

  it("diverts a create to a conflict path when another file occupies it", () => {
    const index = indexWith({});

    const decision = decideRemoteV2Apply(index, update({ kind: "file-create", fileId: fileIdB }), new Set());

    expect(decision).toEqual({
      action: "conflict-path",
      path: "Notes/a conflict-fbbbbbbb.md",
      reason: "remote path is occupied by another file",
    });
  });

  it("adopts a remote file over an identical untouched local occupant instead of forking", () => {
    const index = indexWith({ contentHash: "bb" });

    const decision = decideRemoteV2Apply(index, update({ kind: "file-create", fileId: fileIdB }), new Set());

    expect(decision).toEqual({ action: "apply", path: "Notes/a.md" });
  });

  it("diverts an occupied rename to a conflict path only when local edits are at stake", () => {
    const index = indexWith({});
    const payload = update({ kind: "file-rename", fileId: fileIdB, oldPath: "Old/a.md", newPath: "Notes/a.md", contentHash: undefined });

    expect(decideRemoteV2Apply(index, payload, new Set()).action).toBe("apply");
    expect(decideRemoteV2Apply(index, payload, new Set([fileIdA]))).toEqual({
      action: "conflict-path",
      path: "Notes/a conflict-fbbbbbbb.md",
      reason: "remote rename target is occupied",
    });
  });
});
