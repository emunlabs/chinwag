# GPUI macOS stable Rust compatibility patches

These local copies let the GPUI bus alpha build with the repository's declared
stable Rust 1.97.1. Root owns the workspace patch declarations and lockfile.
Neither the Rust toolchain nor the global Cargo registry is changed.

## Original packages

Both directories are complete copies of the downloaded crates.io registry
packages. Their package manifests, original manifests, lockfiles, license files,
and all other source files are preserved byte for byte. The sole modified file
in each package is `src/window.rs`.

| Local directory | Original package | Downloaded `.crate` SHA256 |
| --- | --- | --- |
| `gpui-pre-macos` | `gpui-pre-macos` 0.3.10 | `7e07a5e5c84f0b2160c194a1c852cc89d1942db66867938ceabcd7f763cb4386` |
| `gpui-fast-macos` | `gpui-fast-macos` 0.1.12 | `d8e8b377d6dcbc0007e68098cb3f40bc2591a1d29526301e9572a70bb674f171` |

The downloaded archive hashes were verified against the original workspace
Cargo.lock checksums before copying. `gpui-pre-macos` retains `LICENSE-APACHE`;
`gpui-fast-macos` retains `LICENSE`. Both manifests retain `license = "Apache-2.0"`.

## Six changed lines

`Option::map_or_default(f)` is unstable in Rust 1.97.1. Each occurrence is
replaced with the stable equivalent
`Option::map_or_else(Default::default, f)`. The selected value is mapped by the
same closure; an absent value produces the same default. Both forms compute the
default only when the option is absent.

| File | Line | Before | After |
| --- | --- | --- | --- |
| `gpui-pre-macos/src/window.rs` | 854 | `.map_or_default(\|screen\| screen.visibleFrame());` | `.map_or_else(Default::default, \|screen\| screen.visibleFrame());` |
| `gpui-pre-macos/src/window.rs` | 915 | `.map_or_default(\|view\| view.frame().size);` | `.map_or_else(Default::default, \|view\| view.frame().size);` |
| `gpui-pre-macos/src/window.rs` | 1021 | `.map_or_default(\|screen\| screen.frame());` | `.map_or_else(Default::default, \|screen\| screen.frame());` |
| `gpui-fast-macos/src/window.rs` | 858 | `.map_or_default(\|screen\| screen.visibleFrame());` | `.map_or_else(Default::default, \|screen\| screen.visibleFrame());` |
| `gpui-fast-macos/src/window.rs` | 919 | `.map_or_default(\|view\| view.frame().size);` | `.map_or_else(Default::default, \|view\| view.frame().size);` |
| `gpui-fast-macos/src/window.rs` | 1025 | `.map_or_default(\|screen\| screen.frame());` | `.map_or_else(Default::default, \|screen\| screen.frame());` |

## Verification

A recursive byte comparison against each downloaded registry directory confirms
that only `src/window.rs` changed and that exactly three substitutions occurred
per package. The native alpha build validates these packages after Root adds
their workspace patch declarations.

## Headless test-support dependency compatibility

The native alpha can build without test support, but `gpui-fast` 0.1.12's
optional property-test dependency requests `proptest = "1.12.0"`. The available
registry version is 1.11.0. The local `vendor/gpui-fast` copy changes only that
normalized manifest requirement to `proptest = "1.11.0"` (Cargo's caret
requirement `^1.11.0`). Features and optionality remain unchanged. The original
`Cargo.toml.orig` and package lockfile remain byte-identical.

| Local directory | Original package | Downloaded `.crate` SHA256 | Changed files |
| --- | --- | --- | --- |
| `gpui-fast` | `gpui-fast` 0.1.12 | `87b6d2f355531132e8f1ec357cb23901aba1d1b3e522260822ae199f02ec32da` | `Cargo.toml` only |

The archive digest matches the package checksum in the workspace Cargo.lock
before the path patch is applied. Every archived file was compared against the
downloaded registry source before copying. A recursive byte comparison confirms
that the optional dependency version in `Cargo.toml` is the sole changed file;
all source files and `LICENSE` remain unchanged. No global Cargo registry file
was edited.

`gpui-pre` 0.3.10 was also inspected. Its downloaded manifest already declares
optional `proptest = "1"`, which accepts 1.11.0; no copy or patch is needed.
Its downloaded archive SHA256 is `df4b5f8d0c278308df2f11e0bfe0212dd77d7848ce1bdc4b9d513334414396f6`,
matching its workspace Cargo.lock checksum. Its archived files were also
compared against the downloaded source; no files were changed.

API inspection found the requested `attr-macro` feature, `test_runner::Config`
with `rng_seed`, `RngSeed::Fixed`, and the property strategy APIs used by GPUI in
proptest 1.11.0. This establishes the targeted API compatibility rationale; it
is not a claim that the full headless build or UI tests have passed. Root owns
the workspace patch declarations, lockfile resolution and headless build.
