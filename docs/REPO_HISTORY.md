# Repository size and history: options

Measured on 2026-11-22 (branch `v5.1.0-fixes`, 36 commits).

## Where the size comes from

| Item | Size in `.git` |
|---|---|
| Whole `.git` directory | 2.1 GiB |
| Committed `*.so` blobs (Rust-built plugin libraries, about 4.5 MiB each) | 2,118.7 MiB |
| Committed `*.o` files | 0.1 MiB |
| `almap/almap` and `almap/dist/*` | 0.4 MiB |
| Everything else (sources, docs, tests) | 1.7 MiB |

Almost all of it (over 99.9%) is the `.so` files. The objects are stored loose (4,608 loose objects, a pack of 537 KiB), so a `git gc` may shrink the directory somewhat. That has not been tried, because it rewrites `.git` and was not part of the task.

## What this branch did

Task 1 stopped tracking every `*.so`, `*.o`, `almap/almap` and `almap/dist/*` and added ignore rules for them. New commits no longer carry binaries. **History is unchanged**, so a fresh clone still downloads the 2.1 GiB.

## Options for the existing history (nothing here has been done)

### 1. Leave history as it is

- Steps: none.
- Resulting size: unchanged (2.1 GiB clone).
- Who it affects: nobody. Existing clones and commit hashes stay valid.
- Downside: every new clone is large, and the `.so` blobs stay in history forever.

### 2. Strip the binaries with `git filter-repo`

- Steps:
  1. Install `git-filter-repo` (not installed here).
  2. In a fresh clone: `git filter-repo --path-glob '*.so' --path-glob '*.o' --path almap/almap --path almap/dist --invert-paths`
  3. Re-add the remote and force-push every branch and tag.
- Resulting size: about 2–3 MiB (the "everything else" row above, plus packing overhead).
- Who it affects: every commit hash changes. Everyone with a clone must re-clone, and open pull requests, tags and references to old hashes (for example `7ec659f` in notes) break.
- Downside: a force-push, which is irreversible on the remote unless a backup of the old repo is kept.

### 3. Start a fresh repository and archive the old one

- Steps:
  1. Create a new repository from the current tree (one initial commit, or a squashed history).
  2. Keep the old repository as a read-only archive.
- Resulting size: about 2–3 MiB.
- Who it affects: all history, blame and issue links stay only in the archive.
- Downside: loses the commit history in the new repository.

## Recommendation (for you to decide)

Option 2 keeps the history of the source files and fixes the size, but needs a force-push and re-clone. If nobody else has cloned the repository yet (the plan says there are no users), it costs little. Option 1 is the right choice if you cannot take a force-push.
