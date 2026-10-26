# v0.1.0 local package candidate

This package unit builds the existing CLI as `chinwag 0.1.0`. Its version
output retains `(uncommitted candidate)`. The seed remains `0.0.1`.
The candidate has no accepted Genesis commit, tag, signature, peer
attestation, vault seal, hosted installation, or seed exec cutover.

The package contains one macOS arm64 `chinwag` executable, the Apache-2.0
license, a manifest, and relative aliases for `git-chinwag`, `git-emun`,
`gh-chinwag`, and `gh-emun`. All aliases resolve to the same bytes.
The manifest binds the candidate source record, native database archive,
toolchain, executable digest, file sizes, and alias targets. A digest
records integrity; it does not confer release approval.

Build and packaging run once in a new private operator namespace, using
the pinned toolchain and an isolated offline cache. A failed or uncertain
namespace stays frozen. Packaging does not publish, modify repository
history, register keys, change global installation, or contact a provider.
The package must be extracted and its actual aliases exercised before
local package acceptance. Prior component acceptance remains scoped to
its recorded source and tests.

The later release gates still require normal installation and onboarding,
actual cross-client shared context and latency, actual seed-to-binary
exec, both-Mac artifact verification, and pristine signed, co-signed,
decryptable vault evidence from Commit #1. Only their verified outcome
can authorize the `v0.1.0-genesis` tag.
