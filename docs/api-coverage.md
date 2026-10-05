# API coverage

`virustotal-rs` exposes VirusTotal API v3 resources as typed clients on [`Client`](https://docs.rs/virustotal-rs/latest/virustotal_rs/struct.Client.html). This inventory is derived from the `Client` accessor implementations in `src/`; it describes SDK resource coverage, not a guarantee that every operation, response field, or VirusTotal account can use every endpoint.

Reviewed **2026-10-04** against fetched upstream source. The dated [feature plan](sdk-feature-plan.md) records verified gaps, implemented slices, compatibility limits, and deferred surfaces.

## Resource clients

| Area | `Client` accessor(s) | SDK surface | Typical access |
| --- | --- | --- | --- |
| Core intelligence | `files()`, `urls()`, `domains()`, `ip_addresses()` | Reports, scans, relationships, analyses, downloads, and iterators | Public operations plus privilege-dependent operations |
| Analysis resources | `analyses()` | Current and legacy retrieval, single analysed item/descriptor, and finite completion polling | Public file/URL analyses; private scanning uses separate endpoints |
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

## Current protocol additions

- `analyses().get_report(id)` and `wait_for_completion(id, options)` use `AnalysisReport`, which accepts null engine verdicts and preserves object/attribute/engine extensions and future status strings. Polling succeeds only on `completed`; request failures, time limits, and exhausted attempts return errors. The default policy uses a 15-second interval, a 300-second total deadline, and at most 20 reads. Caller-selected item typing and descriptor retrieval use the documented single-object envelopes.
- `search().search_objects(...)` and `intelligence_search_objects(...)` return extensible objects with their context and page metadata. Object iterators share the SDK's bounded cursor behavior; page metadata is available through the page methods. Intelligence search requires premium privileges, and its new page method validates `1..=300` limits.
- Legacy `SearchResult` now chooses its variant from the response's `type`, preserving its existing enum layout. Unknown types are supported through the extensible object APIs. Ascending sort directions, cursors, and snippet IDs are encoded correctly.
- `urls().get_last_serving_ip_address_object(id)` returns one typed IP object. `get_network_location::<T>(id)` reads one domain or IP object; use `serde_json::Value` to retain either shape.

These additions have offline mock/fixture tests; they were not exercised against a live account. [The model example](../examples/current_api_models.rs) runs without credentials or network access.

## Access model

The SDK's `ApiTier` value configures local request throttling only:

- `ApiTier::Public` applies an in-process 4-requests-per-minute limiter and a 500-request client-day counter.
- `ApiTier::Premium` disables those local limits.

It does not inspect or change the privileges attached to an API key. VirusTotal remains the source of truth for endpoint access and [consumption quotas](https://docs.virustotal.com/docs/consumption-quotas-handled). An unavailable operation can therefore return authentication, forbidden, quota, or rate-limit errors even when the client is configured as `Premium`.

Prefer an explicit tier. `EnhancedClientBuilder::with_tier_detection()` only uses a local key-format/length heuristic; it does not query VirusTotal or verify the account plan.

## Coverage boundaries

- VirusTotal may add endpoints or response fields before this SDK models them.
- `FileAttributes` preserves unknown top-level attributes in `additional_attributes`; other response models may be stricter.
- Legacy `analysis::EngineResult.result` and `urls::UrlAnalysisResult.result` remain `String` for source compatibility and cannot decode null verdicts. Prefer `AnalysisReport` for analysis retrieval and generic/extensible payloads where a legacy resource model is insufficient.
- The legacy `get_last_serving_ip_address` method retains its collection-shaped signature; use the additive object method for VirusTotal's current single-object response.
- VirusTotal Monitor is not exposed. The API catalog also includes fields and operations outside the selected audit; existing clients are partial coverage, not a declaration that every current or preview API is implemented.
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
