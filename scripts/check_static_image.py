#!/usr/bin/env python3
"""Verify the shipped image has static executables and no shared runtimes."""

import argparse
import json
from pathlib import PurePosixPath
import struct
# Required for shell-free Docker/OpenSSL test commands.
import subprocess  # nosec B404
import tarfile
import tempfile

from smoke_mcp_container import image_reference


BINARIES = {"usr/local/bin/app", "usr/bin/tini"}


def check_ca_trust(bundle):
    """Reject roots deliberately removed from the shipped trust bundle."""
    # Fixed executable and argument list; no shell interprets image names or fixture data.
    encoded = subprocess.check_output(  # nosec B603, B607 # nosemgrep
        ["openssl", "crl2pkcs7", "-nocrl", "-certfile", "/dev/stdin"], input=bundle
    )
    # Fixed executable and argument list; no shell interprets image names or fixture data.
    subjects = subprocess.check_output(  # nosec B603, B607 # nosemgrep
        ["openssl", "pkcs7", "-print_certs", "-noout"], input=encoded
    ).decode().lower()
    for distrusted in ("emsign ecc root ca - g3", "aaa certificate services"):
        if distrusted in subjects:
            raise ValueError(f"distrusted CA root returned to trust bundle: {distrusted}")


def check_dynamic_section(name, data, header):
    """Reject ELF dynamic entries that require shared libraries."""
    for entry in range(header[2], header[2] + header[5], 16):
        tag, _ = struct.unpack_from("<qQ", data, entry)
        if tag == 0:
            break
        if tag == 1:
            raise ValueError(f"{name}: has a shared-library dependency")


def check_elf(name, data, architecture):
    """Validate static ELF architecture, loader independence, and PIE hardening."""
    if data[:6] != b"\x7fELF\x02\x01":
        raise ValueError(f"{name}: expected a little-endian ELF64 executable")
    if name == "usr/local/bin/app" and struct.unpack_from("<H", data, 16)[0] != 3:
        raise ValueError(f"{name}: static executable must retain PIE address randomization")
    machine = struct.unpack_from("<H", data, 18)[0]
    if machine != {"amd64": 62, "arm64": 183}[architecture]:
        raise ValueError(f"{name}: wrong ELF architecture {machine}")
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    if not count or size < 56:
        raise ValueError(f"{name}: missing or invalid ELF program headers")
    for index in range(count):
        header = struct.unpack_from("<IIQQQQQQ", data, offset + index * size)
        if header[0] == 3:  # PT_INTERP: needs an external ELF loader.
            raise ValueError(f"{name}: has a dynamic interpreter")
        if header[0] == 2:  # Static PIE can have PT_DYNAMIC, but no NEEDED.
            check_dynamic_section(name, data, header)


def check_configuration(info):
    """Require the expected nonroot entrypoint and CA bundle configuration."""
    config = info["Config"]
    if config["User"] != "65532:65532":
        raise ValueError("runtime must use the nonroot 65532:65532 account")
    if config["Entrypoint"] != ["/usr/bin/tini", "--", "/usr/local/bin/app"]:
        raise ValueError("runtime must launch the CLI through its static init")
    if "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt" not in config["Env"]:
        raise ValueError("runtime must configure the shipped CA trust bundle")


def read_file(filesystem, files, name):
    """Read a regular file from the exported container archive without extracting it."""
    with filesystem.extractfile(files[name]) as source:
        return source.read()


def check_runtime_files(filesystem, files, architecture):
    """Check every runtime file for unexpected executables or unsafe permissions."""
    seen = set()
    for name, member in files.items():
        if member.mode & 0o6000:
            raise ValueError(f"privileged executable mode shipped: {name}")
        if ".so" in PurePosixPath(name).name:
            raise ValueError(f"shared runtime library shipped: {name}")
        with filesystem.extractfile(member) as source:
            if source.read(4) != b"\x7fELF":
                continue
            if name not in BINARIES:
                raise ValueError(f"unexpected runtime executable: {name}")
            source.seek(0)
            check_elf(name, source.read(), architecture)
        if member.uid != 0 or member.mode & 0o022:
            raise ValueError(f"{name}: executable must be root-owned and not writable by others")
        seen.add(name)
    if seen != BINARIES:
        raise ValueError(f"missing static executables: {BINARIES - seen}")


def check_ca_package(status):
    """Require current CA supplier package metadata for vulnerability scans."""
    if "Package: ca-certificates\n" not in status or "Status: install ok installed\n" not in status:
        raise ValueError("missing installed CA supplier package record")
    version = next(
        line.removeprefix("Version: ") for line in status.splitlines() if line.startswith("Version: ")
    )
    if version == "20250419":
        raise ValueError("stale CA supplier package record")


def check_support_files(filesystem, files, architecture):
    """Validate certificates, SBOM components, and native musl build provenance."""
    bundle = read_file(filesystem, files, "etc/ssl/certs/ca-certificates.crt")
    if b"-----BEGIN CERTIFICATE-----" not in bundle:
        raise ValueError("missing CA certificates")
    check_ca_trust(bundle)
    status = read_file(filesystem, files, "var/lib/dpkg/status.d/ca-certificates").decode()
    check_ca_package(status)
    sbom = json.loads(read_file(filesystem, files, "usr/share/doc/app/sbom.cdx.json"))
    if sbom.get("bomFormat") != "CycloneDX" or not sbom.get("components"):
        raise ValueError("missing application SBOM components")
    provenance = read_file(filesystem, files, "usr/share/doc/app/native-build.txt").decode()
    target = {"amd64": "x86_64", "arm64": "aarch64"}[architecture]
    if (f"host: {target}-unknown-linux-musl" not in provenance
        or "/usr/lib/libc.a" not in provenance
        or "self-contained/libc.a" in provenance):
        raise ValueError("missing system-musl linker provenance")


def check_filesystem(container, architecture):
    """Export the disposable container and inspect its filesystem in memory."""
    with tempfile.TemporaryFile() as archive:
        # Fixed executable and argument list; no shell interprets image names or fixture data.
        subprocess.run(["docker", "export", container], stdout=archive, check=True)  # nosec B603, B607 # nosemgrep
        archive.seek(0)
        with tarfile.open(fileobj=archive) as filesystem:
            files = {str(PurePosixPath(m.name)): m for m in filesystem if m.isfile()}
            check_runtime_files(filesystem, files, architecture)
            check_support_files(filesystem, files, architecture)


def main():
    """Parse the image and platform arguments and run all verification checks."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=image_reference)
    parser.add_argument("--platform", choices=("linux/amd64", "linux/arm64"))
    args = parser.parse_args()
    create = ["docker", "create"]
    if args.platform:
        create += ["--platform", args.platform]
    # Fixed executable and argument list; no shell interprets image names or fixture data.
    container = subprocess.check_output(create + ["--", args.image], text=True).strip()  # nosec B603, B607 # nosemgrep
    try:
        # Fixed executable and argument list; no shell interprets image names or fixture data.
        info = json.loads(subprocess.check_output(["docker", "inspect", container]))[0]  # nosec B603, B607 # nosemgrep
        # Fixed executable and argument list; no shell interprets image names or fixture data.
        image = json.loads(subprocess.check_output(["docker", "image", "inspect", info["Image"]]))[0]  # nosec B603, B607 # nosemgrep
        check_configuration(info)
        check_filesystem(container, image["Architecture"])
        print(f"Static runtime verified: {args.image} ({image['Architecture']})")
    finally:
        # Fixed executable and argument list; no shell interprets image names or fixture data.
        subprocess.run(["docker", "rm", container], stdout=subprocess.DEVNULL, check=True)  # nosec B603, B607 # nosemgrep


if __name__ == "__main__":
    main()
