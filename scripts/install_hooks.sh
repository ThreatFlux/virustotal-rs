#!/bin/sh
# Install repository hooks through Git's worktree-aware hooks path.
set -eu

script_dir="$(CDPATH='' cd "$(dirname "$0")" && pwd)"
repo_root="$(git -C "$script_dir/.." rev-parse --show-toplevel)"
hooks_path="$(git -C "$repo_root" rev-parse --git-path hooks)"
case "$hooks_path" in
    /* | [A-Za-z]:/* | [A-Za-z]:\\*) ;;
    *) hooks_path="$repo_root/$hooks_path" ;;
esac
mkdir -p "$hooks_path"

hook_source="$repo_root/.githooks/pre-commit"
hook_target="$hooks_path/pre-commit"
if [ -L "$hook_target" ]; then
    printf '%s\n' 'Existing pre-commit hook is a symlink; it was preserved.' >&2
    exit 1
fi
if [ -e "$hook_target" ]; then
    if [ ! -f "$hook_target" ]; then
        printf '%s\n' 'Existing unrelated pre-commit hook was preserved.' >&2
        exit 1
    fi
    if ! cmp -s "$hook_source" "$hook_target"; then
        owned_header="$(head -n 2 "$hook_source")"
        current_header="$(head -n 2 "$hook_target")"
        if [ "$current_header" != "$owned_header" ]; then
            printf '%s\n' 'Existing unrelated pre-commit hook was preserved.' >&2
            exit 1
        fi
    fi
fi
if ! cmp -s "$hook_source" "$hook_target"; then
    cp "$hook_source" "$hook_target"
fi
chmod 755 "$hook_target"
printf '%s\n' 'Installed the virustotal-rs pre-commit hook.'
