# Repository size and history: options

Measured on 2026-11-22, before the rewrite described under Status.

## Where the size comes from

| Item | Size in `.git` |
|---|---|
| Whole `.git` directory | 2.1 GiB |
| Committed `*.so` blobs (Rust-built plugin libraries, about 4.5 MiB each) | 2,118.7 MiB |
| Committed `*.o` files | 0.1 MiB |
| `almap/almap` and `almap/dist/*` | 0.4 MiB |
| Everything else (sources, docs, tests) | 1.7 MiB |

Almost all of it (over 99.9%) is the `.so` files. The objects are stored loose (4,608 loose objects, a pack of 537 KiB), so a `git gc` may shrink the directory somewhat. That has not been tried, because it rewrites `.git` and was not part of the task.

## Status (2026-11-22): Option 2 was carried out locally

- **Backup first:** a full mirror at `~/Almap-backup.git` (outside the repo). All refs and commit hashes were compared against the source, `git fsck --full` reported no errors, and the reachable object counts matched.
- **Rewrite:** `git filter-repo --force --path-glob '*.so' --path-glob 'almap/dist/*' --invert-paths` on all 7 local branches. No `.so` or `almap/dist/` path remains in any commit.
- **Result:** `.git` went from 2,226,706,716 bytes (2.1 GiB) to 1,819,837 bytes (1.8 MB). Every commit hash changed (for example `main` `7ec659f` is now `e5f84b4`); the tip tree of `v5.1.0-fixes` is byte-identical before and after. The old-to-new map is in `.git/filter-repo/commit-map` (local only).
- **Verification:** the scanner and unit tests build and pass, and all 623 plugins build under `-Werror`.
- **Not pushed.** The remote still has the old history until a force-push is approved. `filter-repo` removes the `origin` remote and the `refs/remotes/origin/*` tracking refs; only the URL was re-added.
- **Worktree gotcha:** git counts every linked worktree's index and reflog as GC roots. The old `.so` blobs stayed in the pack (120 MB) until the other worktrees' indexes were re-synced (`git read-tree HEAD`, which does not touch files) and their reflogs expired before `git gc --prune=now`.

## What Task 1 did

Task 1 stopped tracking every `*.so`, `*.o`, `almap/almap` and `almap/dist/*` and added ignore rules for them, so new commits carry no binaries.

## The options that were considered

### 1. Leave history as it is

- Steps: none.
- Resulting size: unchanged (2.1 GiB clone).
- Who it affects: nobody. Existing clones and commit hashes stay valid.
- Downside: every new clone is large, and the `.so` blobs stay in history forever.

### 2. Strip the binaries with `git filter-repo` (chosen and done locally; see Status)

- Steps:
  1. Install `git-filter-repo` (not installed here).
  2. In a fresh clone: `git filter-repo --path-glob '*.so' --path-glob '*.o' --path almap/almap --path almap/dist --invert-paths`
  3. Re-add the remote and force-push every branch and tag.
- Resulting size: about 2–3 MiB (measured afterwards: 1.8 MB).
- Who it affects: every commit hash changes. Everyone with a clone must re-clone, and open pull requests, tags and references to old hashes (for example `7ec659f` in notes) break.
- Downside: a force-push, which is irreversible on the remote unless a backup of the old repo is kept.

### 3. Start a fresh repository and archive the old one

- Steps:
  1. Create a new repository from the current tree (one initial commit, or a squashed history).
  2. Keep the old repository as a read-only archive.
- Resulting size: about 2–3 MiB.
- Who it affects: all history, blame and issue links stay only in the archive.
- Downside: loses the commit history in the new repository.
