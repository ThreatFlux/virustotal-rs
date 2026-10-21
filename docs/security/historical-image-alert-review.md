# Historical published MCP image: all 89 alert dispositions

Reviewed 2026-10-21. These alerts refer to main commit
`7188aab71d2201d88671425663130e5a36282c22` (2026-01-12), category
`.github/workflows/auto-release.yml:docker-scan`, image
`ghcr.io/threatflux/virustotal-rs-mcp`. The old workflow generated its Dockerfile
inline and shipped Debian bookworm, OpenSSL and account-management utilities.
Current main still supports the MCP server, but replacing the release workflow
removed container publication/scanning. That did not remove its public image.

## Artifact evidence and scope

The inspected published index is
`sha256:325f3eb5cae586e6af34217591936b865f7326ecc541b5aaf28dacc379ed8027`:

- amd64: `sha256:37605a797fc04845842182af72d505b1af995074962338463dd40ad671963b86`
- arm64: `sha256:664833a4542228f17950f232968876ba0a7f247365f0df2e8cee41ce135c7053`

Both immutable manifests were pulled and their filesystems exported without
executing the old application. Neither filesystem contains MiniZip. Both
`passwd.list` records own `/usr/bin/chfn` and `/usr/bin/chsh`, while the
`util-linux.list` records do not. The manifests publish no PowerPC target.
Privileged account-management executables are present in the old image;
nonroot application execution alone is not grounds to call its packages safe.

## Confirmed scoped false positives

- **16 util-linux mappings**, eight each for
  [CVE-2025-14104](https://security-tracker.debian.org/tracker/CVE-2025-14104)
  and [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563):
  affected util-linux chfn/chsh implementations are disabled in Debian builds.
  The same-named tools actually present belong to shadow/passwd; they do not
  make these util-linux-specific findings applicable. Other shadow defects
  remain separately reviewed and are not dismissed by this decision.
- **One MiniZip mapping**,
  [CVE-2023-45853](https://security-tracker.debian.org/tracker/CVE-2023-45853):
  affected ZIP creation code is not supplied by the installed zlib1g binary;
  MiniZip files are absent from both complete runtime exports.
- **Two architecture mappings**,
  [CVE-2025-27587](https://security-tracker.debian.org/tracker/CVE-2025-27587):
  the reported implementation is PowerPC-specific. This exact published index
  contains only amd64 and arm64 application manifests. This decision does not
  assert that every OpenSSL signing operation or every later platform is safe.

These 19 decisions permit individual evidence-backed FP dismissals. They do
not permit a blanket image exception, nor dismissal of the other 70 alerts.

## Retained findings and remediation

Three GCC runtime/source mappings for
[CVE-2022-27943](https://security-tracker.debian.org/tracker/CVE-2022-27943)
refer to libiberty's Rust demangler. No standalone libiberty archive is in the
export, but that fact alone does not prove whether affected implementation
code is embedded in every shipped binary. Retain these three as component
uncertainties rather than asserting an unverified false positive.

The other 67 records are retained package/version detections for remediation;
this is not proof that an MCP request reaches each defect. Some vendor records
are disputed or have no stable fix. Each row links its vendor evidence and
keeps this distinction explicit. Removing the broad Debian userspace from a
maintained replacement is the common remediation for all retained records,
including uncertain component mappings. Deleting alert analyses, ignoring
CVEs, or labeling the old public image obsolete is not a runtime fix.

Implementation plan:

1. Add a checked-in, maintained minimal runtime for the supported MCP binary;
   preserve `mcp-jwt` and `mcp-oauth`, with no fallback dropping authentication
   features. Use current stable toolchain, locked crates and maintained native
   code; prove actual linkage and native provenance.
2. Validate actual MCP startup, health/authentication behavior and shutdown
   with generated test credentials on both published architectures. Exercise
   TLS/DNS through an isolated fixture, never production VirusTotal requests.
3. Build and scan replacement images at all severities, including unfixed
   findings and the Rust graph. Publish only through the reviewed normal
   workflow after merge. PR builds do not publish a production replacement.
4. Record replacement digests and preserve the previous analysis category so
   GitHub can recognize closure. Until publication and a replacement main scan,
   valid old-image alerts stay open; do not dismiss them as accepted risk.
5. Keep old immutable tag retention/deprecation explicit. A fixed latest tag
   does not change previously pulled or pinned historical digests.

## Complete alert coverage

| Alert | Rule | Package and reported version | Disposition / action |
| --- | --- | --- | --- |
| [170](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/170) | [CVE-2025-14104](https://security-tracker.debian.org/tracker/CVE-2025-14104) | util-linux-extra `2.38.1-5+deb12u3` | FP: component/target absent; dismiss with evidence above |
| [169](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/169) | [CVE-2025-14104](https://security-tracker.debian.org/tracker/CVE-2025-14104) | util-linux `2.38.1-5+deb12u3` | FP: component/target absent; dismiss with evidence above |
| [168](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/168) | [CVE-2025-14104](https://security-tracker.debian.org/tracker/CVE-2025-14104) | mount `2.38.1-5+deb12u3` | FP: component/target absent; dismiss with evidence above |
| [167](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/167) | [CVE-2025-14104](https://security-tracker.debian.org/tracker/CVE-2025-14104) | libuuid1 `2.38.1-5+deb12u3` | FP: component/target absent; dismiss with evidence above |
| [166](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/166) | [CVE-2025-13151](https://security-tracker.debian.org/tracker/CVE-2025-13151) | libtasn1-6 `4.19.0-2+deb12u1` | Retain package detection; replace runtime and verify closure |
| [165](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/165) | [CVE-2025-14104](https://security-tracker.debian.org/tracker/CVE-2025-14104) | libsmartcols1 `2.38.1-5+deb12u3` | FP: component/target absent; dismiss with evidence above |
| [164](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/164) | [CVE-2025-14104](https://security-tracker.debian.org/tracker/CVE-2025-14104) | libmount1 `2.38.1-5+deb12u3` | FP: component/target absent; dismiss with evidence above |
| [163](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/163) | [CVE-2025-9820](https://security-tracker.debian.org/tracker/CVE-2025-9820) | libgnutls30 `3.7.9-2+deb12u5` | Retain package detection; replace runtime and verify closure |
| [162](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/162) | [CVE-2025-14104](https://security-tracker.debian.org/tracker/CVE-2025-14104) | libblkid1 `2.38.1-5+deb12u3` | FP: component/target absent; dismiss with evidence above |
| [161](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/161) | [CVE-2025-68972](https://security-tracker.debian.org/tracker/CVE-2025-68972) | gpgv `2.2.40-1.1+deb12u1` | Retain package detection; replace runtime and verify closure |
| [160](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/160) | [CVE-2025-68973](https://security-tracker.debian.org/tracker/CVE-2025-68973) | gpgv `2.2.40-1.1+deb12u1` | Retain package detection; replace runtime and verify closure |
| [159](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/159) | [CVE-2025-14104](https://security-tracker.debian.org/tracker/CVE-2025-14104) | bsdutils `1:2.38.1-5+deb12u3` | FP: component/target absent; dismiss with evidence above |
| [134](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/134) | [CVE-2023-45853](https://security-tracker.debian.org/tracker/CVE-2023-45853) | zlib1g `1:1.2.13.dfsg-1` | FP: component/target absent; dismiss with evidence above |
| [133](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/133) | [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563) | util-linux-extra `2.38.1-5+deb12u3` | FP: component/target absent; dismiss with evidence above |
| [132](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/132) | [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563) | util-linux `2.38.1-5+deb12u3` | FP: component/target absent; dismiss with evidence above |
| [131](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/131) | [TEMP-0290435-0B57B5](https://security-tracker.debian.org/tracker/TEMP-0290435-0B57B5) | tar `1.34+dfsg-1.2+deb12u1` | Retain package detection; replace runtime and verify closure |
| [130](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/130) | [CVE-2005-2541](https://security-tracker.debian.org/tracker/CVE-2005-2541) | tar `1.34+dfsg-1.2+deb12u1` | Retain package detection; replace runtime and verify closure |
| [129](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/129) | [TEMP-0517018-A83CE6](https://security-tracker.debian.org/tracker/TEMP-0517018-A83CE6) | sysvinit-utils `3.06-4` | Retain package detection; replace runtime and verify closure |
| [128](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/128) | [CVE-2023-31486](https://security-tracker.debian.org/tracker/CVE-2023-31486) | perl-base `5.36.0-7+deb12u3` | Retain package detection; replace runtime and verify closure |
| [127](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/127) | [CVE-2011-4116](https://security-tracker.debian.org/tracker/CVE-2011-4116) | perl-base `5.36.0-7+deb12u3` | Retain package detection; replace runtime and verify closure |
| [124](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/124) | [TEMP-0628843-DBAD28](https://security-tracker.debian.org/tracker/TEMP-0628843-DBAD28) | passwd `1:4.13+dfsg1-1+deb12u1` | Retain package detection; replace runtime and verify closure |
| [123](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/123) | [CVE-2024-56433](https://security-tracker.debian.org/tracker/CVE-2024-56433) | passwd `1:4.13+dfsg1-1+deb12u1` | Retain package detection; replace runtime and verify closure |
| [122](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/122) | [CVE-2007-5686](https://security-tracker.debian.org/tracker/CVE-2007-5686) | passwd `1:4.13+dfsg1-1+deb12u1` | Retain package detection; replace runtime and verify closure |
| [121](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/121) | [CVE-2025-27587](https://security-tracker.debian.org/tracker/CVE-2025-27587) | openssl `3.0.18-1~deb12u1` | FP: component/target absent; dismiss with evidence above |
| [120](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/120) | [CVE-2025-6141](https://security-tracker.debian.org/tracker/CVE-2025-6141) | ncurses-bin `6.4-4` | Retain package detection; replace runtime and verify closure |
| [119](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/119) | [CVE-2023-50495](https://security-tracker.debian.org/tracker/CVE-2023-50495) | ncurses-bin `6.4-4` | Retain package detection; replace runtime and verify closure |
| [118](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/118) | [CVE-2025-6141](https://security-tracker.debian.org/tracker/CVE-2025-6141) | ncurses-base `6.4-4` | Retain package detection; replace runtime and verify closure |
| [117](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/117) | [CVE-2023-50495](https://security-tracker.debian.org/tracker/CVE-2023-50495) | ncurses-base `6.4-4` | Retain package detection; replace runtime and verify closure |
| [116](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/116) | [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563) | mount `2.38.1-5+deb12u3` | FP: component/target absent; dismiss with evidence above |
| [115](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/115) | [TEMP-0628843-DBAD28](https://security-tracker.debian.org/tracker/TEMP-0628843-DBAD28) | login `1:4.13+dfsg1-1+deb12u1` | Retain package detection; replace runtime and verify closure |
| [114](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/114) | [CVE-2024-56433](https://security-tracker.debian.org/tracker/CVE-2024-56433) | login `1:4.13+dfsg1-1+deb12u1` | Retain package detection; replace runtime and verify closure |
| [113](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/113) | [CVE-2007-5686](https://security-tracker.debian.org/tracker/CVE-2007-5686) | login `1:4.13+dfsg1-1+deb12u1` | Retain package detection; replace runtime and verify closure |
| [112](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/112) | [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563) | libuuid1 `2.38.1-5+deb12u3` | FP: component/target absent; dismiss with evidence above |
| [111](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/111) | [CVE-2023-31439](https://security-tracker.debian.org/tracker/CVE-2023-31439) | libudev1 `252.39-1~deb12u1` | Retain package detection; replace runtime and verify closure |
| [110](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/110) | [CVE-2023-31438](https://security-tracker.debian.org/tracker/CVE-2023-31438) | libudev1 `252.39-1~deb12u1` | Retain package detection; replace runtime and verify closure |
| [109](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/109) | [CVE-2023-31437](https://security-tracker.debian.org/tracker/CVE-2023-31437) | libudev1 `252.39-1~deb12u1` | Retain package detection; replace runtime and verify closure |
| [108](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/108) | [CVE-2013-4392](https://security-tracker.debian.org/tracker/CVE-2013-4392) | libudev1 `252.39-1~deb12u1` | Retain package detection; replace runtime and verify closure |
| [107](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/107) | [CVE-2025-6141](https://security-tracker.debian.org/tracker/CVE-2025-6141) | libtinfo6 `6.4-4` | Retain package detection; replace runtime and verify closure |
| [106](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/106) | [CVE-2023-50495](https://security-tracker.debian.org/tracker/CVE-2023-50495) | libtinfo6 `6.4-4` | Retain package detection; replace runtime and verify closure |
| [105](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/105) | [CVE-2023-31439](https://security-tracker.debian.org/tracker/CVE-2023-31439) | libsystemd0 `252.39-1~deb12u1` | Retain package detection; replace runtime and verify closure |
| [104](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/104) | [CVE-2023-31438](https://security-tracker.debian.org/tracker/CVE-2023-31438) | libsystemd0 `252.39-1~deb12u1` | Retain package detection; replace runtime and verify closure |
| [103](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/103) | [CVE-2023-31437](https://security-tracker.debian.org/tracker/CVE-2023-31437) | libsystemd0 `252.39-1~deb12u1` | Retain package detection; replace runtime and verify closure |
| [102](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/102) | [CVE-2013-4392](https://security-tracker.debian.org/tracker/CVE-2013-4392) | libsystemd0 `252.39-1~deb12u1` | Retain package detection; replace runtime and verify closure |
| [101](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/101) | [CVE-2022-27943](https://security-tracker.debian.org/tracker/CVE-2022-27943) | libstdc++6 `12.2.0-14+deb12u1` | Undetermined component; replace runtime, retain until scanned |
| [100](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/100) | [CVE-2025-27587](https://security-tracker.debian.org/tracker/CVE-2025-27587) | libssl3 `3.0.18-1~deb12u1` | FP: component/target absent; dismiss with evidence above |
| [99](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/99) | [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563) | libsmartcols1 `2.38.1-5+deb12u3` | FP: component/target absent; dismiss with evidence above |
| [98](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/98) | [CVE-2024-22365](https://security-tracker.debian.org/tracker/CVE-2024-22365) | libpam0g `1.5.2-6+deb12u1` | Retain package detection; replace runtime and verify closure |
| [97](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/97) | [CVE-2024-10041](https://security-tracker.debian.org/tracker/CVE-2024-10041) | libpam0g `1.5.2-6+deb12u1` | Retain package detection; replace runtime and verify closure |
| [96](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/96) | [CVE-2025-6020](https://security-tracker.debian.org/tracker/CVE-2025-6020) | libpam0g `1.5.2-6+deb12u1` | Retain package detection; replace runtime and verify closure |
| [95](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/95) | [CVE-2024-22365](https://security-tracker.debian.org/tracker/CVE-2024-22365) | libpam-runtime `1.5.2-6+deb12u1` | Retain package detection; replace runtime and verify closure |
| [94](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/94) | [CVE-2024-10041](https://security-tracker.debian.org/tracker/CVE-2024-10041) | libpam-runtime `1.5.2-6+deb12u1` | Retain package detection; replace runtime and verify closure |
| [93](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/93) | [CVE-2025-6020](https://security-tracker.debian.org/tracker/CVE-2025-6020) | libpam-runtime `1.5.2-6+deb12u1` | Retain package detection; replace runtime and verify closure |
| [92](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/92) | [CVE-2024-22365](https://security-tracker.debian.org/tracker/CVE-2024-22365) | libpam-modules-bin `1.5.2-6+deb12u1` | Retain package detection; replace runtime and verify closure |
| [91](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/91) | [CVE-2024-10041](https://security-tracker.debian.org/tracker/CVE-2024-10041) | libpam-modules-bin `1.5.2-6+deb12u1` | Retain package detection; replace runtime and verify closure |
| [90](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/90) | [CVE-2025-6020](https://security-tracker.debian.org/tracker/CVE-2025-6020) | libpam-modules-bin `1.5.2-6+deb12u1` | Retain package detection; replace runtime and verify closure |
| [89](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/89) | [CVE-2024-22365](https://security-tracker.debian.org/tracker/CVE-2024-22365) | libpam-modules `1.5.2-6+deb12u1` | Retain package detection; replace runtime and verify closure |
| [88](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/88) | [CVE-2024-10041](https://security-tracker.debian.org/tracker/CVE-2024-10041) | libpam-modules `1.5.2-6+deb12u1` | Retain package detection; replace runtime and verify closure |
| [87](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/87) | [CVE-2025-6020](https://security-tracker.debian.org/tracker/CVE-2025-6020) | libpam-modules `1.5.2-6+deb12u1` | Retain package detection; replace runtime and verify closure |
| [86](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/86) | [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563) | libmount1 `2.38.1-5+deb12u3` | FP: component/target absent; dismiss with evidence above |
| [85](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/85) | [CVE-2011-3389](https://security-tracker.debian.org/tracker/CVE-2011-3389) | libgnutls30 `3.7.9-2+deb12u5` | Retain package detection; replace runtime and verify closure |
| [84](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/84) | [CVE-2024-2236](https://security-tracker.debian.org/tracker/CVE-2024-2236) | libgcrypt20 `1.10.1-3` | Retain package detection; replace runtime and verify closure |
| [83](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/83) | [CVE-2018-6829](https://security-tracker.debian.org/tracker/CVE-2018-6829) | libgcrypt20 `1.10.1-3` | Retain package detection; replace runtime and verify closure |
| [82](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/82) | [CVE-2022-27943](https://security-tracker.debian.org/tracker/CVE-2022-27943) | libgcc-s1 `12.2.0-14+deb12u1` | Undetermined component; replace runtime, retain until scanned |
| [81](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/81) | [CVE-2019-9192](https://security-tracker.debian.org/tracker/CVE-2019-9192) | libc6 `2.36-9+deb12u13` | Retain package detection; replace runtime and verify closure |
| [80](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/80) | [CVE-2019-1010025](https://security-tracker.debian.org/tracker/CVE-2019-1010025) | libc6 `2.36-9+deb12u13` | Retain package detection; replace runtime and verify closure |
| [79](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/79) | [CVE-2019-1010024](https://security-tracker.debian.org/tracker/CVE-2019-1010024) | libc6 `2.36-9+deb12u13` | Retain package detection; replace runtime and verify closure |
| [78](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/78) | [CVE-2019-1010023](https://security-tracker.debian.org/tracker/CVE-2019-1010023) | libc6 `2.36-9+deb12u13` | Retain package detection; replace runtime and verify closure |
| [77](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/77) | [CVE-2019-1010022](https://security-tracker.debian.org/tracker/CVE-2019-1010022) | libc6 `2.36-9+deb12u13` | Retain package detection; replace runtime and verify closure |
| [76](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/76) | [CVE-2018-20796](https://security-tracker.debian.org/tracker/CVE-2018-20796) | libc6 `2.36-9+deb12u13` | Retain package detection; replace runtime and verify closure |
| [75](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/75) | [CVE-2010-4756](https://security-tracker.debian.org/tracker/CVE-2010-4756) | libc6 `2.36-9+deb12u13` | Retain package detection; replace runtime and verify closure |
| [72](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/72) | [CVE-2019-9192](https://security-tracker.debian.org/tracker/CVE-2019-9192) | libc-bin `2.36-9+deb12u13` | Retain package detection; replace runtime and verify closure |
| [71](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/71) | [CVE-2019-1010025](https://security-tracker.debian.org/tracker/CVE-2019-1010025) | libc-bin `2.36-9+deb12u13` | Retain package detection; replace runtime and verify closure |
| [70](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/70) | [CVE-2019-1010024](https://security-tracker.debian.org/tracker/CVE-2019-1010024) | libc-bin `2.36-9+deb12u13` | Retain package detection; replace runtime and verify closure |
| [69](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/69) | [CVE-2019-1010023](https://security-tracker.debian.org/tracker/CVE-2019-1010023) | libc-bin `2.36-9+deb12u13` | Retain package detection; replace runtime and verify closure |
| [68](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/68) | [CVE-2019-1010022](https://security-tracker.debian.org/tracker/CVE-2019-1010022) | libc-bin `2.36-9+deb12u13` | Retain package detection; replace runtime and verify closure |
| [67](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/67) | [CVE-2018-20796](https://security-tracker.debian.org/tracker/CVE-2018-20796) | libc-bin `2.36-9+deb12u13` | Retain package detection; replace runtime and verify closure |
| [66](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/66) | [CVE-2010-4756](https://security-tracker.debian.org/tracker/CVE-2010-4756) | libc-bin `2.36-9+deb12u13` | Retain package detection; replace runtime and verify closure |
| [63](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/63) | [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563) | libblkid1 `2.38.1-5+deb12u3` | FP: component/target absent; dismiss with evidence above |
| [62](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/62) | [CVE-2011-3374](https://security-tracker.debian.org/tracker/CVE-2011-3374) | libapt-pkg6.0 `2.6.1` | Retain package detection; replace runtime and verify closure |
| [61](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/61) | [CVE-2025-30258](https://security-tracker.debian.org/tracker/CVE-2025-30258) | gpgv `2.2.40-1.1+deb12u1` | Retain package detection; replace runtime and verify closure |
| [60](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/60) | [CVE-2022-3219](https://security-tracker.debian.org/tracker/CVE-2022-3219) | gpgv `2.2.40-1.1+deb12u1` | Retain package detection; replace runtime and verify closure |
| [59](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/59) | [CVE-2022-27943](https://security-tracker.debian.org/tracker/CVE-2022-27943) | gcc-12-base `12.2.0-14+deb12u1` | Undetermined component; replace runtime, retain until scanned |
| [58](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/58) | [CVE-2025-6297](https://security-tracker.debian.org/tracker/CVE-2025-6297) | dpkg `1.21.22` | Retain package detection; replace runtime and verify closure |
| [57](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/57) | [CVE-2025-5278](https://security-tracker.debian.org/tracker/CVE-2025-5278) | coreutils `9.1-1` | Retain package detection; replace runtime and verify closure |
| [56](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/56) | [CVE-2017-18018](https://security-tracker.debian.org/tracker/CVE-2017-18018) | coreutils `9.1-1` | Retain package detection; replace runtime and verify closure |
| [55](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/55) | [CVE-2016-2781](https://security-tracker.debian.org/tracker/CVE-2016-2781) | coreutils `9.1-1` | Retain package detection; replace runtime and verify closure |
| [54](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/54) | [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563) | bsdutils `1:2.38.1-5+deb12u3` | FP: component/target absent; dismiss with evidence above |
| [53](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/53) | [TEMP-0841856-B18BAF](https://security-tracker.debian.org/tracker/TEMP-0841856-B18BAF) | bash `5.2.15-2+b9` | Retain package detection; replace runtime and verify closure |
| [52](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/52) | [CVE-2011-3374](https://security-tracker.debian.org/tracker/CVE-2011-3374) | apt `2.6.1` | Retain package detection; replace runtime and verify closure |


## Maintained replacement and analysis continuity

The checked-in Dockerfile builds the actual MCP server with all authentication features. The new MCP Container workflow builds, tests and scans each native architecture independently, and only publishes the exact tested artifacts after a clean all-severity OS/Cargo scan on a normal push. A PR does not publish. Old immutable vulnerable digests remain historical artifacts; merging this PR alone does not change them. A subsequent reviewed normal publication replaces the maintained latest tag.

The AMD64 upload intentionally retains the old analysis key and category `.github/workflows/auto-release.yml:docker-scan` and the original empty matrix/environment (`{}`). ARM64 uses a distinct category and matrix so that one platform cannot overwrite the other. This uses CodeQL's documented manual `CODEQL_ACTION_ANALYSIS_KEY` support ([environment documentation](https://github.com/github/codeql-action/blob/v4.39.0/src/environment.ts), [getAnalysisKey implementation](https://github.com/github/codeql-action/blob/v4.39.0/src/api-client.ts)) and the official upload-sarif `matrix` input. Verify the resulting analysis key, category and environment in GitHub after the first hosted upload. No historical analysis is deleted.
