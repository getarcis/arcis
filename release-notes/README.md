# Release notes

One file per release, named exactly after the git tag the publish
workflow creates: `vX.Y.Z.md` (for example `v1.7.0.md`).

When `publish.yml` runs on a push to `main`, the `create-release` job
looks for `release-notes/<tag>.md`. If it exists, GitHub renders it as
the release body verbatim. If it is missing, the job falls back to
`--generate-notes` (auto-filled from PR titles), which is noisy and
leaks internal detail, so always prefer a committed file.

## How to use

Write `release-notes/vX.Y.Z.md` as part of the release PR (the same PR
that bumps the version). Reviewers see the exact public text before it
ships, and it is versioned in git.

## What the file may contain

User-facing changes only, grouped under clear headings:

```
## Features
- ...

## Fixes
- ...

## Compatibility
- ...

## Install
- ...
```

## What the file must NOT contain

This text is public the moment the release publishes. Keep it like a
press release:

- No internal infrastructure moves (website, dashboard, control plane).
- No benchmark numbers or internal metrics.
- No internal file paths or repo-internal jargon.
- No em dashes. Use periods or commas.
- No mention of the tooling used to build the release.

A clean categorized changelog. Nothing a reader outside the project
would find confusing or that exposes internal work.
