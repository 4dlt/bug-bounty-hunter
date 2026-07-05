// Shared, pure path helpers for the checklist artifacts.
//
// These live OUTSIDE both role modules on purpose: the Author (author.ts) and
// the Reviewer (reviewer.ts) each need to know where the `checklists/` directory
// is, but neither should import the other to get it. A path function carries no
// mutable state and writes nothing, so sharing it here keeps the structural rule
// airtight — the two role modules never import each other.

import path from "node:path";

export function checklistsDir(workdir: string): string {
  return path.join(workdir, "checklists");
}

/** `checklists/<class>.md` — the Author's artifact. */
export function checklistPath(workdir: string, vulnClass: string): string {
  return path.join(checklistsDir(workdir), `${vulnClass}.md`);
}

/** `checklists/<class>.approval.json` — the Reviewer's artifact. */
export function approvalPath(workdir: string, vulnClass: string): string {
  return path.join(checklistsDir(workdir), `${vulnClass}.approval.json`);
}
