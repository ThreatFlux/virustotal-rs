#!/usr/bin/env python3
"""Validate tag-triggered builds and choose immutable and current publication tags."""

import argparse
import os
import re
import tomllib
from pathlib import Path


def validate_release(ref_type, ref_name, version):
    """Require every tag publication to identify the checked-out package version."""
    if ref_type == "tag" and (not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", ref_name)
                              or ref_name != f"v{version}"):
        raise ValueError("release tag does not match the checked-out Cargo package version")


def publication_tags(image, sha, ref_type, ref_name):
    """Publish immutable SHA and version aliases independently of mutable latest updates."""
    tags = [f"{image}:{sha}"]
    if ref_type == "tag":
        tags.extend((f"{image}:{ref_name}", f"{image}:{ref_name[1:]}"))
    return tags


def latest_source(image, main_head):
    """Choose current main independently of the updater's possibly obsolete commit."""
    if not re.fullmatch(r"[a-f0-9]{40}", main_head):
        raise ValueError("expected the full current main commit SHA")
    return f"{image}:{main_head}"


def main():
    """Emit Docker CLI arguments without evaluating any tag text in a shell."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--latest", action="store_true")
    parser.add_argument("--main-head")
    args = parser.parse_args()
    if args.latest:
        if not args.main_head:
            parser.error("--main-head is required when updating latest")
        print(latest_source(os.environ["IMAGE"], args.main_head))
        return
    manifest = tomllib.loads(Path("Cargo.toml").read_text())
    ref_type, ref_name = os.environ["REF_TYPE"], os.environ["REF_NAME"]
    validate_release(ref_type, ref_name, manifest["package"]["version"])
    if not args.validate:
        for tag in publication_tags(os.environ["IMAGE"], os.environ["SHA"], ref_type, ref_name):
            print("--tag")
            print(tag)


if __name__ == "__main__":
    main()
