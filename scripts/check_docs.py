#!/usr/bin/env python3
"""Validate the small set of documentation facts that must track source."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
QUICKSTART = ROOT / "examples/quickstart.rs"
CONFIGURATION = ROOT / "docs/configuration.md"
REQUIRED_FILES = (
    README,
    QUICKSTART,
    ROOT / "docs/api-coverage.md",
    CONFIGURATION,
    ROOT / "docs/README.md",
    ROOT / "CONTRIBUTING.md",
    ROOT / "SECURITY.md",
    ROOT / "LICENSE",
    ROOT / "LICENSE-APACHE",
)
MARKDOWN_FILES = (
    README,
    ROOT / "docs/api-coverage.md",
    CONFIGURATION,
    ROOT / "docs/README.md",
    ROOT / "CONTRIBUTING.md",
)
LINK_PATTERN = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")


def load_manifest() -> dict[str, Any]:
    return tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))


def marked_section(text: str, name: str) -> str | None:
    match = re.search(
        rf"<!-- {re.escape(name)}:start -->(.*?)<!-- {re.escape(name)}:end -->",
        text,
        flags=re.DOTALL,
    )
    return match.group(1) if match else None


def local_link_target(document: Path, raw_target: str) -> Path | None:
    target = raw_target.strip().strip("<>").split("#", 1)[0]
    if not target or re.match(r"^(?:https?://|mailto:)", target):
        return None
    return (document.parent / target).resolve()


def check_required_files() -> list[str]:
    return [
        f"missing required file: {path.relative_to(ROOT)}"
        for path in REQUIRED_FILES
        if not path.is_file()
    ]


def check_msrv(readme: str, msrv: str) -> list[str]:
    if f"<!-- docs-msrv:{msrv} -->" in readme:
        return []
    return [f"README MSRV must match Cargo.toml ({msrv})"]


def documented_features(readme: str) -> set[str] | None:
    section = marked_section(readme, "feature-flags")
    if section is None:
        return None
    return set(re.findall(r"^\| `([^`]+)` \|", section, flags=re.MULTILINE))


def check_features(readme: str, expected: set[str]) -> list[str]:
    documented = documented_features(readme)
    if documented is None:
        return ["README is missing feature-flags markers"]
    if documented == expected:
        return []
    return [
        "README features differ from Cargo.toml: "
        f"documented={sorted(documented)}, expected={sorted(expected)}"
    ]


def readme_quickstart(readme: str) -> str | None:
    section = marked_section(readme, "quickstart")
    if section is None:
        return None
    match = re.fullmatch(r"\s*```rust\n(.*?)\n```\s*", section, re.DOTALL)
    return match.group(1).strip() if match else None


def check_quickstart(readme: str) -> list[str]:
    mirrored = readme_quickstart(readme)
    if mirrored is None:
        return ["README quickstart must contain one marked Rust code block"]
    example = QUICKSTART.read_text(encoding="utf-8").strip()
    if mirrored == example:
        return []
    return ["README quickstart differs from examples/quickstart.rs"]


def check_disclosures(readme: str) -> list[str]:
    required = (
        "independent, community-maintained project",
        "are not retried automatically",
        "The `main` branch can be ahead",
    )
    return [
        f"README is missing required disclosure: {phrase!r}"
        for phrase in required
        if phrase not in readme
    ]


def check_installation(readme: str) -> list[str]:
    if not re.search(r"virustotal-rs\s*=\s*[\"{]", readme):
        return []
    return ["README must not pin a crates.io version that can drift from releases"]


def check_license_contract(readme: str, expression: str) -> list[str]:
    errors: list[str] = []
    if expression != "MIT OR Apache-2.0":
        errors.append("Cargo.toml package license must be 'MIT OR Apache-2.0'")
    for link in ("[MIT License](LICENSE)", "[Apache License 2.0](LICENSE-APACHE)"):
        if link not in readme:
            errors.append(f"README must link the declared license: {link}")
    return errors


def check_builder_disclosure() -> list[str]:
    text = CONFIGURATION.read_text(encoding="utf-8")
    if text.count("Stored, but not applied by `build()`") == 4:
        return []
    return ["configuration guide must disclose all four inactive builder settings"]


def check_document_links(document: Path) -> list[str]:
    text = document.read_text(encoding="utf-8")
    errors: list[str] = []
    for raw_target in LINK_PATTERN.findall(text):
        target = local_link_target(document, raw_target)
        if target is not None and not target.exists():
            errors.append(f"broken local link in {document.relative_to(ROOT)}: {raw_target}")
    return errors


def check_links() -> list[str]:
    return [error for document in MARKDOWN_FILES for error in check_document_links(document)]


def collect_errors(manifest: dict[str, Any], readme: str) -> list[str]:
    package = manifest["package"]
    features = set(manifest.get("features", {}))
    return [
        *check_required_files(),
        *check_msrv(readme, package["rust-version"]),
        *check_features(readme, features),
        *check_quickstart(readme),
        *check_disclosures(readme),
        *check_installation(readme),
        *check_license_contract(readme, package["license"]),
        *check_builder_disclosure(),
        *check_links(),
    ]


def report_errors(errors: list[str]) -> None:
    for error in errors:
        print(f"docs contract: {error}", file=sys.stderr)


def main() -> int:
    manifest = load_manifest()
    msrv = manifest["package"]["rust-version"]
    if sys.argv[1:] == ["--print-msrv"]:
        print(msrv)
        return 0
    if sys.argv[1:]:
        print("usage: scripts/check_docs.py [--print-msrv]", file=sys.stderr)
        return 2

    errors = collect_errors(manifest, README.read_text(encoding="utf-8"))
    if errors:
        report_errors(errors)
        return 1

    features = ", ".join(sorted(manifest["features"]))
    print(f"Documentation contract is consistent (MSRV {msrv}; features: {features}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
