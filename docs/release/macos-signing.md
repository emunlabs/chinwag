# Prepare macOS signing and notarization

CHWG-011-1 provides scaffolding only. **Nothing has been signed or submitted
to Apple as part of this task. Nothing has been published.** The execution
path requires separate release authorization and has not been exercised.

## Prerequisites

Use a macOS release host with Xcode command-line tools providing `codesign`,
`xcrun notarytool`, `xcrun stapler`, `hdiutil`, `ditto`, `plutil`, and `spctl`.
Have an Apple Developer Program account and a valid Developer ID Application
certificate with its private key already provisioned in the release keychain.
Provisioning and keychain access are operator responsibilities. This script
does not import certificates, unlock keychains, or enumerate identities.

The current repository produces the `chinwag` CLI, not a desktop app bundle.
Build it with the pinned Rust 1.97.1 toolchain when a build is needed:

```bash
export CHINWAG_PRIVATE_CRSQL_INPUTS=/Users/brianspector/.chinwag-native-inputs
cargo build -p chinwag-cli --release --bin chinwag --locked
```

The native database build currently supports `aarch64-apple-darwin` and links
the private cr-sqlite archive statically. This task does not build or inspect
that private archive. See [the existing package candidate](../release-candidate-v0.1.md)
for the separate manifest, alias, and release acceptance requirements.

## Prepare a keychain profile manually

The following command is a description for a release operator. **It has not
been run for this task.** Replace the placeholders locally. Omit `--password`
so `notarytool` prompts for the app-specific password without putting it in
shell history or process arguments:

```bash
xcrun notarytool store-credentials '<profile-name>' \
    --apple-id '<apple-id>' \
    --team-id '<team-id>'
```

This operator step validates credentials over the network and stores them in
the keychain. Never paste the password, certificates, or key material into
this repository. Apple documents the interactive password prompt in
[TN3147](https://developer.apple.com/documentation/technotes/tn3147-migrating-to-the-latest-notarization-tool).

## Set environment references

| Variable | Purpose |
| --- | --- |
| `CHINWAG_SIGN_IDENTITY` | Required. Developer ID Application certificate common name or certificate hash supplied by the operator. Ad hoc identity `-` is rejected. |
| `CHINWAG_NOTARY_PROFILE` | Required. Name of an existing `notarytool` keychain profile. The script passes this name to `--keychain-profile`. |
| `CHINWAG_PRIVATE_CRSQL_INPUTS` | Build only. Native archive directory used by the existing Rust build, not by the signing script. |

There is no Apple ID, Team ID, password, API key, or credential-file fallback.
`APPLE_ID`, `TEAM_ID`, and app-specific password environment variables are
ignored. Profile authentication keeps raw notarization secrets out of argv.
The script redacts both environment references when it prints commands.

## Inspect the dry-run plan

From the repository root, use fake references to inspect a plan against an
existing executable. The parent directory of the output must already exist:

```bash
CHINWAG_SIGN_IDENTITY='FAKE_SIGN_IDENTITY' \
CHINWAG_NOTARY_PROFILE='FAKE_PROFILE' \
bash scripts/macos-sign.sh --dry-run \
    --artifact target/release/chinwag \
    --output /tmp/chinwag-review.dmg
```

Omitting `--dry-run` produces the same safe plan. Only `--execute` permits
mutation or network access. Multiple mode flags are rejected.

Dry-run validates required arguments, nonempty references, basic input layout,
the entitlements file's presence, and unused output paths. It prints exact,
shell-escaped commands with credential references replaced by `<redacted>`.
It invokes no Apple tools, creates no files, and makes no network requests.
It does not validate Mach-O contents, parse app metadata, inspect a keychain,
verify a certificate, or authenticate a profile. Those checks need an
authorized release environment. Run the regression test without credentials:

```bash
bash scripts/tests/macos-sign-dry-run.sh
```

The test clears the inherited environment and installs failing sentinels for
Apple and network tools. Every signing-script invocation stays in dry-run.

## Review the future execution flow

After separate release authorization, the same arguments with `--execute`
perform the printed plan. Never use that flag for this scaffolding task.

The script copies the input into `<output>.work/payload`, then signs the copy
with `--options runtime --timestamp` and the entitlements plist. It verifies
the signature, creates and signs a compressed DMG, and submits that DMG with
`notarytool submit --wait`. It requires an `Accepted` status from the plist
receipt before `stapler staple`, `stapler validate`, strict code verification,
and a Gatekeeper assessment of the DMG. App bundles also receive an execute
assessment. Standalone CLI code receives strict signature verification and a
`codesign -R=notarized --check-notarization` check rather than the app-oriented
execute assessment. Apple's [distribution test guidance](https://developer.apple.com/forums/thread/130560)
distinguishes apps, containers, and other code. The clean-Mac checklist below
still applies to the CLI itself.

Both the output and its adjacent `.work` directory must be absent. A failed
attempt retains partial artifacts and a private notarization receipt for
local review. Use a fresh output path for retries. Do not distribute a failed
or partly verified output. Tool diagnostics are suppressed because tools can
repeat credential references. The receipt is not printed. Review it locally,
and retrieve the submission log using the profile after an authorized run.
Keep release staging and receipts outside source control.

The DMG contains one `chinwag` executable or one simple `Chinwag.app`.
A future app input must contain `Contents/Info.plist` and
`Contents/MacOS/chinwag`. The operator must confirm that `CFBundleExecutable`
matches and that there is no nested code. Common nested-code directories are
rejected. Frameworks, helpers, plug-ins, extra executables, and arbitrary app
layouts require an explicit inside-out signing plan before extending this
script. Signing does not use `--deep`; verification does.

The staple target is the DMG. Standalone executables cannot carry a stapled
ticket, and ZIP archives cannot be stapled directly. Apple describes this
constraint and the accepted containers in
[Customizing the notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow).
If a later release distributes an app outside this DMG, that artifact needs
its own reviewed stapling and verification flow. This script does not replace
the candidate package's alias and manifest generation.

## Entitlements rationale

[`chinwag.entitlements.plist`](../../packaging/macos/chinwag.entitlements.plist)
contains an empty dictionary. Hardened runtime comes from `codesign --options
runtime`; an entitlement is not required to turn it on.

| Entitlement | Decision and reason |
| --- | --- |
| `com.apple.security.network.client` and `.network.server` | Omitted. These are App Sandbox permissions. This Developer ID CLI does not enable App Sandbox and uses outbound swarm connections and local listeners without these sandbox entitlements. |
| `com.apple.security.app-sandbox` | Omitted. Sandboxing the repository and process-management CLI needs a separate capability design and compatibility review. |
| `com.apple.security.cs.disable-library-validation` | Omitted. The native database archive links statically. No requirement for arbitrary third-party dynamic libraries has been established. Preserve library validation. |
| `com.apple.security.cs.allow-jit`, `.allow-unsigned-executable-memory`, and `.disable-executable-page-protection` | Omitted. No JIT or runtime-generated native code requirement has been established. |
| `com.apple.security.get-task-allow` | Omitted. Release software does not grant debugger attachment through this entitlement. |

Apple's [network-client entitlement documentation](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.network.client)
places it under App Sandbox. Apple's
[library-validation documentation](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.disable-library-validation)
explains the default trust restriction. Revisit entitlements only after a
specific signed build demonstrates a missing capability. A future webview or
desktop runtime needs its own review.

## CI notes

Run the shell test on pull requests. It needs Bash and standard Unix tools,
with no certificate, keychain, or Apple account. ShellCheck can lint both
scripts. Keep any future release job separate and explicitly authorized.

Provision release credentials only through the CI secret store and the
platform's protected keychain provisioning process. Never put secrets or
private keys in YAML, command-line arguments, artifacts, or debug logs.
Expose only the identity reference and keychain profile name to this script.
Disable shell tracing in the calling job too. The script disables its own
xtrace before reading references and suppresses tool diagnostics, but a parent
shell can expose values before the script starts. Retain receipts privately.
No CI publishing or automatic Apple submission is added by this task.

## Manual release checklist

- [ ] Obtain release authorization before any `--execute` invocation.
- [ ] Confirm source revision, pinned toolchain, architecture, and native input provenance.
- [ ] Review the staged artifact contents, entitlements, and Developer ID identity locally.
- [ ] Provision a valid notary profile without logging passwords or inspecting credential stores through this script.
- [ ] Run the shell test and review the default dry-run plan against the exact release input.
- [ ] Use a fresh output path outside source control for an authorized execution.
- [ ] Require `Accepted`, inspect the notarization log for warnings, and retain the submission receipt privately.
- [ ] Require successful stapler validation, code verification, the DMG Gatekeeper assessment, and the app assessment when applicable.
- [ ] Test the downloaded, quarantined DMG on a clean Mac, including offline opening and the actual CLI or app workflow.
- [ ] Complete separate alias, manifest, checksum, packaging, and publication gates. Hash the final stapled DMG, whose bytes differ from the submitted image.

These release checks remain pending. Dry-run success is not evidence of an
Apple signature, accepted notarization, or Gatekeeper approval.
