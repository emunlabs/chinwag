#!/bin/bash
set +x
set -euo pipefail

root=$(cd -- "${BASH_SOURCE[0]%/*}/../.." && pwd -P)
scratch=$(mktemp -d "$root/.macos-sign-test.XXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
mkdir -p "$scratch/tools" "$scratch/input app/Chinwag.app/Contents/MacOS"
marker="$scratch/apple-tool-invoked"
output="$scratch/release image.dmg"
log="$scratch/output.log"
identity='FAKE_SIGN_IDENTITY_DO_NOT_ECHO'
profile='FAKE_PROFILE_DO_NOT_ECHO'
password='FAKE_PASSWORD_DO_NOT_ECHO'

for tool in codesign xcrun notarytool stapler spctl hdiutil ditto plutil security curl; do
    cat >"$scratch/tools/$tool" <<'EOF'
#!/bin/bash
printf 'unexpected tool invocation\n' >> "$TOOL_MARKER"
exit 99
EOF
    chmod +x "$scratch/tools/$tool"
done
printf 'not a Mach-O; dry-run must not execute this fixture\n' >"$scratch/chinwag"
chmod +x "$scratch/chinwag"
cp "$scratch/chinwag" "$scratch/input app/Chinwag.app/Contents/MacOS/chinwag"
printf '<plist version="1.0"><dict/></plist>\n' >"$scratch/input app/Chinwag.app/Contents/Info.plist"

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

invoke() {
    env -i PATH="$scratch/tools:/usr/bin:/bin" TOOL_MARKER="$marker" \
        CHINWAG_SIGN_IDENTITY="$1" CHINWAG_NOTARY_PROFILE="$2" \
        APPLE_ID='FAKE_APPLE_ID_DO_NOT_ECHO' TEAM_ID='FAKE_TEAM_ID_DO_NOT_ECHO' \
        APPLE_APP_SPECIFIC_PASSWORD="$password" \
        /bin/bash "$root/scripts/macos-sign.sh" "${@:3}" >"$log" 2>&1
}

assert_safe() {
    [[ ! -e "$marker" ]] || fail 'Dry-run invoked an Apple or network tool.'
    [[ ! -e "$output" && ! -e "$output.work" ]] || fail 'Dry-run created an output artifact.'
    local contents secret
    contents=$(<"$log")
    for secret in "$identity" "$profile" "$password" FAKE_APPLE_ID_DO_NOT_ECHO FAKE_TEAM_ID_DO_NOT_ECHO; do
        [[ "$contents" != *"$secret"* ]] || fail 'Credential value appeared in output.'
    done
}

assert_plan() {
    local contents
    contents=$(<"$log")
    [[ "$contents" == *'DRY RUN: no files changed'* ]] || fail 'Missing dry-run banner.'
    [[ "$contents" == *'codesign --force --options runtime --timestamp --entitlements '* ]] || fail 'Missing hardened runtime signature.'
    [[ "$contents" == *'--sign \<redacted\>'* ]] || fail 'Missing redacted signing identity.'
    [[ "$contents" == *'xcrun notarytool submit '* ]] || fail 'Missing submission plan.'
    [[ "$contents" == *'--keychain-profile \<redacted\> --wait --output-format plist > '* ]] || fail 'Missing redacted profile or wait flag.'
    [[ "$contents" == *'require Accepted before stapling'* ]] || fail 'Missing acceptance gate.'
    [[ "$contents" == *'xcrun stapler staple '*'xcrun stapler validate '* ]] || fail 'Missing stapling or validation plan.'
    [[ "$contents" == *'codesign --verify --deep --strict '* ]] || fail 'Missing code verification.'
    [[ "$contents" == *'spctl --assess --type open --context context:primary-signature '* ]] || fail 'Missing DMG Gatekeeper check.'
}

invoke "$identity" "$profile" --artifact "$scratch/chinwag" --output "$output"
assert_safe
assert_plan
[[ "$(<"$log")" != *'spctl --assess --type execute '* ]] || fail 'Used app assessment for a standalone CLI.'
[[ "$(<"$log")" == *'codesign --verify --strict -R=notarized --check-notarization '* ]] || fail 'Missing standalone notarization check.'
cp "$log" "$scratch/default.log"
invoke "$identity" "$profile" --dry-run --artifact "$scratch/chinwag" --output "$output"
assert_safe
assert_plan
cmp -s "$log" "$scratch/default.log" || fail 'Explicit and default dry-run plans differ.'
invoke "$identity" "$profile" --dry-run --artifact "$scratch/input app/Chinwag.app" --output "$output"
assert_safe
assert_plan
[[ "$(<"$log")" == *'spctl --assess --type execute '* ]] || fail 'Missing app Gatekeeper check.'
env -i PATH="$scratch/tools:/usr/bin:/bin" TOOL_MARKER="$marker" \
    CHINWAG_SIGN_IDENTITY="$identity" CHINWAG_NOTARY_PROFILE="$profile" \
    APPLE_APP_SPECIFIC_PASSWORD="$password" \
    /bin/bash -x "$root/scripts/macos-sign.sh" --dry-run \
    --artifact "$scratch/chinwag" --output "$output" >"$log" 2>&1
assert_safe
assert_plan

if invoke '' "$profile" --dry-run --artifact "$scratch/chinwag" --output "$output"; then
    fail 'Accepted missing signing identity.'
fi
assert_safe
if invoke "$identity" '' --dry-run --artifact "$scratch/chinwag" --output "$output"; then
    fail 'Accepted missing profile.'
fi
assert_safe
if invoke "$identity" "$profile" --dry-run --artifact "$scratch/missing" --output "$output"; then
    fail 'Accepted missing artifact.'
fi
assert_safe
if invoke "$identity" "$profile" --dry-run --artifact "$scratch/chinwag" --output "$scratch/release.zip"; then
    fail 'Accepted an unstaplable output format.'
fi
assert_safe
if invoke "$identity" "$profile" --dry-run --artifact "$scratch/chinwag" --output; then
    fail 'Accepted a missing option value.'
fi
assert_safe
if invoke "$identity" "$profile" --dry-run "$password"; then
    fail 'Accepted an unknown argument.'
fi
assert_safe
printf 'already exists\n' >"$scratch/existing.dmg"
if invoke "$identity" "$profile" --dry-run --artifact "$scratch/chinwag" --output "$scratch/existing.dmg"; then
    fail 'Accepted an existing output.'
fi
assert_safe
mkdir "$scratch/existing-work.dmg.work"
if invoke "$identity" "$profile" --dry-run --artifact "$scratch/chinwag" --output "$scratch/existing-work.dmg"; then
    fail 'Accepted an existing work directory.'
fi
assert_safe

printf 'PASS: default and explicit dry-run, CLI and app plans, input guards, credential redaction, and zero Apple tool invocations.\n'
