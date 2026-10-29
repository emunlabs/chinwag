#!/bin/bash
set +x
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: bash scripts/macos-sign.sh [--dry-run | --execute] --artifact PATH --output PATH.dmg

Default: dry-run. Prints a redacted command plan without invoking Apple tools,
creating files, signing, or contacting Apple. --execute performs the plan.
Required environment: CHINWAG_SIGN_IDENTITY, CHINWAG_NOTARY_PROFILE.
Input: an executable CLI or a simple .app containing Contents/MacOS/chinwag.
Output and its adjacent .work directory must not already exist.
EOF
}

die() {
    printf 'macos-sign: %s\n' "$1" >&2
    exit 1
}

mode=dry-run
mode_seen=false
artifact=
output=
while (($#)); do
    case "$1" in
        --dry-run|--execute)
            [[ "$mode_seen" == false ]] || die 'Specify at most one mode flag.'
            mode=${1#--}
            mode_seen=true
            shift
            ;;
        --artifact|--output)
            (($# >= 2)) && [[ -n "$2" && "$2" != --* ]] || die 'A path option requires a value.'
            if [[ "$1" == --artifact ]]; then
                [[ -z "$artifact" ]] || die 'Duplicate artifact option.'
                artifact=$2
            else
                [[ -z "$output" ]] || die 'Duplicate output option.'
                output=$2
            fi
            shift 2
            ;;
        --help|-h) usage; exit 0 ;;
        *) die 'Unknown argument. Use --help.' ;;
    esac
done

[[ -n "$artifact" && -n "$output" ]] || die 'Both --artifact and --output are required.'
[[ ! "$artifact$output" =~ [[:cntrl:]] ]] || die 'Paths must not contain control characters.'
identity=${CHINWAG_SIGN_IDENTITY:-}
profile=${CHINWAG_NOTARY_PROFILE:-}
[[ -n "$identity" && "$identity" != - ]] || die 'Set CHINWAG_SIGN_IDENTITY to a Developer ID Application identity.'
[[ -n "$profile" ]] || die 'Set CHINWAG_NOTARY_PROFILE to a keychain profile name.'
[[ ! "$identity$profile" =~ [[:cntrl:]] ]] || die 'Credential references must not contain control characters.'

[[ "$artifact" == /* ]] || artifact="$PWD/$artifact"
[[ "$output" == /* ]] || output="$PWD/$output"
artifact_parent=$(cd -- "${artifact%/*}" 2>/dev/null && pwd -P) || die 'Artifact parent directory must exist.'
output_parent=$(cd -- "${output%/*}" 2>/dev/null && pwd -P) || die 'Output parent directory must exist.'
artifact="$artifact_parent/${artifact##*/}"
output="$output_parent/${output##*/}"
[[ "$output" == *.dmg ]] || die 'Output must end in .dmg.'
[[ ! -L "$artifact" ]] || die 'Artifact must not be a symbolic link.'

if [[ -d "$artifact" && "$artifact" == *.app ]]; then
    [[ -f "$artifact/Contents/Info.plist" && -x "$artifact/Contents/MacOS/chinwag" ]] || die 'App requires Info.plist and Contents/MacOS/chinwag.'
    for directory in Frameworks PlugIns XPCServices Helpers Library; do
        [[ ! -e "$artifact/Contents/$directory" ]] || die 'Nested app code requires a reviewed inside-out signing plan.'
    done
    [[ "$output" != "$artifact/"* ]] || die 'Output must be outside the input app.'
    payload_name=Chinwag.app
else
    [[ -f "$artifact" && -x "$artifact" ]] || die 'Artifact must be an executable file or a supported .app.'
    payload_name=chinwag
fi

script_path=${BASH_SOURCE[0]}
[[ "$script_path" == */* ]] || script_path="./$script_path"
script_dir=$(cd -- "${script_path%/*}" && pwd -P)
entitlements="$script_dir/../packaging/macos/chinwag.entitlements.plist"
[[ -r "$entitlements" ]] || die 'Entitlements file is missing or unreadable.'
work_dir="$output.work"
for path in "$output" "$work_dir"; do
    [[ ! -e "$path" && ! -L "$path" ]] || die 'Output or work directory already exists. Use a fresh output path.'
done
payload="$work_dir/payload/$payload_name"
receipt="$work_dir/notary-result.plist"

print_command() {
    printf '+'
    local argument
    for argument in "$@"; do
        if [[ "$argument" == "$identity" || "$argument" == "$profile" ]]; then
            argument='<redacted>'
        fi
        printf ' %q' "$argument"
    done
}

run() {
    print_command "$@"
    printf '\n'
    if [[ "$mode" == execute ]]; then
        # Tool diagnostics can repeat credential references. Keep them out of logs.
        "$@" >/dev/null 2>&1 || die 'A planned command failed. Stop and review the staged artifacts locally.'
    fi
}

if [[ "$mode" == execute ]]; then
    [[ "$(uname -s)" == Darwin ]] || die 'Execution requires macOS.'
    for tool in codesign xcrun spctl hdiutil ditto plutil mkdir; do
        command -v "$tool" >/dev/null || die 'A required release tool is unavailable. See the release guide.'
    done
    umask 077
    printf 'EXECUTE: signing and Apple submission enabled. Tool diagnostics are suppressed.\n'
else
    printf 'DRY RUN: no files changed, no Apple tools invoked, nothing submitted to Apple.\n'
fi

run plutil -lint "$entitlements"
run mkdir "$work_dir"
run mkdir "$work_dir/payload"
run ditto "$artifact" "$payload"
run codesign --force --options runtime --timestamp --entitlements "$entitlements" --sign "$identity" "$payload"
run codesign --verify --deep --strict "$payload"
run hdiutil create -format UDZO -volname Chinwag -srcfolder "$work_dir/payload" "$output"
run codesign --force --timestamp --sign "$identity" "$output"
run codesign --verify --strict "$output"

submission=(xcrun notarytool submit "$output" --keychain-profile "$profile" --wait --output-format plist)
print_command "${submission[@]}"
printf ' > %q\n' "$receipt"
if [[ "$mode" == execute ]]; then
    "${submission[@]}" >"$receipt" 2>/dev/null || die 'Notary submission failed. Review the private receipt locally.'
fi
print_command plutil -extract status raw -o - "$receipt"
printf ' # require Accepted before stapling\n'
if [[ "$mode" == execute ]]; then
    status=$(plutil -extract status raw -o - "$receipt" 2>/dev/null) || die 'Cannot read notarization status.'
    [[ "$status" == Accepted ]] || die 'Notarization was not Accepted. Stop and review the private receipt locally.'
fi

run xcrun stapler staple "$output"
run xcrun stapler validate "$output"
run codesign --verify --deep --strict "$payload"
run codesign --verify --strict "$output"
if [[ "$payload_name" == Chinwag.app ]]; then
    run spctl --assess --type execute "$payload"
else
    run codesign --verify --strict -R=notarized --check-notarization "$payload"
fi
run spctl --assess --type open --context context:primary-signature "$output"
if [[ "$mode" == execute ]]; then
    printf 'Completed signing, notarization, stapling, and verification. Retain the private work directory for review.\n'
fi
