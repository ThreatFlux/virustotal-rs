# API coverage

`virustotal-rs` exposes VirusTotal API v3 resources as typed clients on [`Client`](https://docs.rs/virustotal-rs/latest/virustotal_rs/struct.Client.html). This inventory is derived from the `Client` accessor implementations in `src/`; it describes SDK resource coverage, not a guarantee that every operation, response field, or VirusTotal account can use every endpoint.

## Resource clients

| Area | `Client` accessor(s) | SDK surface | Typical access |
| --- | --- | --- | --- |
| Core intelligence | `files()`, `urls()`, `domains()`, `ip_addresses()` | Reports, scans, relationships, analyses, downloads, and iterators | Public operations plus privilege-dependent operations |
| Community | `comments()` | Comment retrieval, creation, and votes | API key; writes mutate remote state |
| Search and collections | `search()`, `collections()` | Intelligence search and collection lifecycle | Some queries and writes require privileges |
| Graphs | `graphs()` | Graph lifecycle, relationships, comments, permissions, and ownership | Privilege-dependent |
| Behaviors and feeds | `file_behaviours()`, `feeds()` | Sandbox behavior artifacts and intelligence feeds | Premium/privileged |
| Hunting | `livehunt()`, `retrohunt()` | Rulesets, notifications, jobs, matches, and permissions | Premium/privileged |
| Rules and threat context | `sigma_rules()`, `yara_rulesets()`, `crowdsourced_yara_rules()`, `ioc_stream()` | Sigma and YARA resources, crowdsourced rules, and IoC stream | Privilege-dependent |
| ATT&CK and actors | `attack_tactics()`, `attack_techniques()`, `threat_actors()` | MITRE ATT&CK context and threat-actor intelligence | Privilege-dependent |
| Private analysis | `private_files()`, `private_urls()` | Private uploads/scans, analyses, behaviors, and lifecycle operations | Separate private-scanning entitlement |
| Administration | `users()`, `groups()` | User, group, quota, membership, and permission operations | Account/admin privileges |
| Supporting resources | `references()`, `zip_files()` | Reference lifecycle and server-side ZIP creation/download | Privilege-dependent |

The crate also exports typed analysis objects, metadata, votes, display helpers, URL builders, pagination adapters, and retry utilities. Browse the [API reference](https://docs.rs/virustotal-rs) for method-level signatures.

## Access model

The SDK's `ApiTier` value configures local request throttling only:

- `ApiTier::Public` applies an in-process 4-requests-per-minute limiter and a 500-request client-day counter.
- `ApiTier::Premium` disables those local limits.

It does not inspect or change the privileges attached to an API key. VirusTotal remains the source of truth for endpoint access and [consumption quotas](https://docs.virustotal.com/docs/consumption-quotas-handled). An unavailable operation can therefore return authentication, forbidden, quota, or rate-limit errors even when the client is configured as `Premium`.

Prefer an explicit tier. `EnhancedClientBuilder::with_tier_detection()` only uses a local key-format/length heuristic; it does not query VirusTotal or verify the account plan.

## Coverage boundaries

- VirusTotal may add endpoints or response fields before this SDK models them.
- `FileAttributes` preserves unknown top-level attributes in `additional_attributes`; other response models may be stricter.
- Private APIs, feeds, hunting, administrative operations, downloads, and some relationships require account-specific access.
- Mutating methods can create scans, comments, votes, collections, graphs, rulesets, jobs, or other remote objects.
- Examples are compile-checked, but live behavior depends on API availability, account permissions, and fixture freshness.

When reporting a coverage gap, include the VirusTotal API v3 reference URL, the desired operation, a redacted response shape, and whether it requires a special account privilege. Never include an API key or sensitive sample.

## Upstream references

- [VirusTotal API v3 overview](https://docs.virustotal.com/reference/overview)
- [Authentication](https://docs.virustotal.com/reference/authentication)
- [Getting started and API access](https://docs.virustotal.com/reference/getting-started)
- [Quota handling](https://docs.virustotal.com/docs/consumption-quotas-handled)
- [Private Scanning](https://docs.virustotal.com/docs/private-scanning)
