#!/usr/bin/env python3
"""Install repository hooks through Git's worktree-aware hooks path."""

import pathlib
import subprocess


def main() -> None:
    root = pathlib.Path(__file__).resolve().parents[1]
    hooks_path = subprocess.check_output(
        ["git", "rev-parse", "--git-path", "hooks"], cwd=root, text=True
    ).strip()
    hooks = pathlib.Path(hooks_path)
    if not hooks.is_absolute():
        hooks = root / hooks
    hooks.mkdir(parents=True, exist_ok=True)

    source = root / ".githooks" / "pre-commit"
    target = hooks / "pre-commit"
    hook = source.read_bytes()
    if target.is_symlink():
        raise SystemExit("Existing pre-commit hook is a symlink; it was preserved.")
    if target.exists():
        current = target.read_bytes()
        owned = current.startswith(b"#!/bin/sh\n# virustotal-rs repository hook\n")
        if current != hook and not owned:
            raise SystemExit("Existing unrelated pre-commit hook was preserved.")
    target.write_bytes(hook)
    target.chmod(0o755)
    print("Installed the virustotal-rs pre-commit hook.")


if __name__ == "__main__":
    main()
