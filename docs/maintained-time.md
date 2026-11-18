# Maintained timestamps and nested OAuth source

The SDK uses Jiff1.0.1 for its own clocks, UTC formatting and feed calendars.
Numeric VirusTotal timestamps and whole-second UTC displays remain compatible;
RFC3339 clock strings now use the equivalent UTC `Z` representation. Checked
feed iteration stops at the last representable civil minute.

The optional MCP OAuth flow retains authorization code, PKCE, refresh, scope,
client authentication and TLS behavior. The published oauth2 5.0.0 crate still
requires Chrono. Its public source is adapted as a private module using time
0.3.55 for numeric instants and checked timeout arithmetic, with the current
reqwest/RNG dependencies. There is no private registry dependency or new
advisory exception. The original public archive, authors/licenses, per-file
hashes and removal plan are retained in `third_party/oauth2`.

The upstream standalone library's documentation remains in that archive;
native protocol tests and the SDK HTTP tests run on GitHub. New hosted
regressions cover negative/null/out-of-range instants, UTC displays, maximum
feed boundaries, empty JWT secrets and nested source custody. All previous
feature flags, including the now-empty `oauth2` and `serde_with` compatibility
flags and their implication from MCP features, remain available.

Codacy's23 imported Lizard measurements are upstream size/complexity findings,
including long protocol fixtures and a trait declaration mistaken for an
`active` method body. These do not describe new SDK runtime defects. Only
Lizard metrics for the ten identified upstream files are scoped out in
`.codacy.yml`; SDK-owned code and the new time regressions stay measured.
Clippy, CodeQL, dependency audit, native tests and source custody still inspect
the complete compiled nested component. Functional and security findings in
this component require fixes; the metric scope is not an advisory exception.
