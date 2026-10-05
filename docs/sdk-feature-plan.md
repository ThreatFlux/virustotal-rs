# SDK modernization and feature plan

Audit date: **2026-10-04**. Baseline: fetched `main` at
`02ab78db31f2c54ef8e8d3b27b4c7b88017c598f`.

This review compares repository source with the official API v3 reference pages
listed below. The provider's advertised Markdown/OpenAPI index returned HTTP 403
in this environment; the readable official endpoint and object documentation was
used instead. No authenticated VirusTotal requests were made. This is a scoped
implementation plan, not certification of the entire endpoint catalog.

| Evidence and baseline gap | Implementation | Compatibility and verification |
| --- | --- | --- |
| [Analysis objects](https://docs.virustotal.com/reference/analyses-object) document `in-progress`, nullable engine verdicts, and empty queued statistics. The legacy enum used `inprogress`; required counters and string verdicts rejected valid payloads. | Correct the enum's wire spelling, accept its old spelling when reading, default absent legacy counters, and add `AnalysisReport` with nullable engine results and extension maps. | Existing public field types and enum variants remain. Legacy string-verdict models still require strings; use the additive report API for null verdicts. Fixtures cover current/legacy spellings, queued results, extensions, future statuses, and malformed recognized fields. |
| [Analysis retrieval](https://docs.virustotal.com/reference/analysis), [related items](https://docs.virustotal.com/reference/analyses-get-objects), and [item descriptors](https://docs.virustotal.com/reference/analyses-get-descriptors) exist, but there was no `Client::analyses()` resource client. | Add `AnalysisClient::{get,get_report,get_item,get_item_descriptor,wait_for_completion}`. Encode opaque IDs. Bound polling by a positive read count and total deadline; only explicit completion succeeds. | Additive accessors. Mock tests cover authenticated routes, a single related object, progress/completion, unknown statuses, attempt exhaustion, an in-flight deadline, API errors, and cancellation. Public and private analysis endpoints remain distinct. |
| [General search](https://docs.virustotal.com/reference/api-search) returns multiple object types. The untagged legacy enum always selected its first matching file shape. | Dispatch legacy deserialization by `type`; add extensible `SearchObject`, `SearchPage`, and object-search methods/iterators. | Existing enum layout is unchanged. Unknown types fail in the legacy enum and remain available through the additive object API. Malformed known comments cannot fall through to another variant. |
| [Intelligence search](https://docs.virustotal.com/reference/intelligence-search) supports heterogeneous results, context, page metadata, cursors, and directional sorting. Existing APIs presented heterogeneous results as `FileSearchResult` and discarded context/page extension fields; raw ascending `+` sorts became spaces in query decoding. | Add `intelligence_search_objects` and its iterator; preserve object/context extensions and page metadata, validate page limits, encode queries/sorts/cursors, and encode snippet IDs. | Premium privileges remain necessary. Legacy search APIs retain their signatures and limit clamping. New page APIs reject invalid limits. Wire mocks prove decoded query values and metadata retention. Iterators return objects, so use page APIs when page metadata matters. |
| [Last serving IP](https://docs.virustotal.com/reference/url-object-last-serving-ip-address) and [network location](https://docs.virustotal.com/reference/url-object-network-location) return one object. The legacy IP helper expected a collection. | Add `get_last_serving_ip_address_object` and generic `get_network_location`. | Preserve the old helper's signature and document its shape limitation. Test encoded identifiers, single envelopes, wrong discriminators, and missing relationships. |
| [Collection pagination](https://docs.virustotal.com/reference/collections) specifies opaque cursor query values. Existing iterators appended a second `?`, failed to encode cursors, could loop on repeated cursors, and stopped early on empty continuing pages. | Share encoded query construction and finite pagination state between core and enhanced iterators; expose positive bounds and return errors for cycles or exceeded bounds. | Keep existing iterator and `IteratorConfig` construction usable. Mock regressions cover query preservation, cursor injection, empty continuing pages, cycles, and limit errors. Root integrator owns this slice. |
| [Authentication](https://docs.virustotal.com/reference/authentication) requires `x-apikey`. `ApiKey` derived Debug exposed the credential, and enhanced headers/user-agent options were stored without effect. | Redact credential Debug, mark authentication headers sensitive, and apply validated custom headers and user agents through the shared client's default headers while rejecting credential conflicts. | Extra headers/user agents become effective for shared JSON, form, multipart, raw, and DELETE requests. Retry configuration and custom limiters remain explicitly standalone. Existing custom-base-URL semantics remain. Transport/configuration mocks verify these changes. |

## Stable tooling evidence

On the audit date, the official [Rust stable distribution manifest](https://static.rust-lang.org/dist/channel-rust-stable.toml) identifies Rust 1.99.0. Development, stable CI checks, and release builds now use it; the independent consumer MSRV check remains 1.97.1. Crate releases were verified against crates.io metadata, and action SHAs against their upstream release tags. Sixteen existing direct/development crates were upgraded, 96 locked package versions refreshed, and every remaining registry version was checked for yanks and prereleases.

[Elasticsearch's crate releases](https://crates.io/crates/elasticsearch/versions) only publish alpha versions. Its limited optional example operations now use stable reqwest REST calls. The former implicit `elasticsearch` feature remains an empty compatibility alias. Optional CLI/MCP dependencies remain outside the default SDK feature set.

Dependency policy checks now include all features. MPL-2.0 acceptance is limited to the existing `colored` 3.1.1 and `option-ext` 0.2.0 packages; it is not a blanket license allowance. The dependency audit has no advisory exemptions. Release versions remain owned by the existing maintainer automation; this implementation does not publish or tag a release.

## Implementation sequence

1. **Modernization agent:** verify the latest stable compiler and crates, keep the
   consumer MSRV when actual compilation permits, refresh the lockfile, pin action
   updates to immutable commits, review release ownership, and adapt dependency
   changes without weakening quality/security gates.
2. **API agent:** implement the documented analysis/search/URL slices above and
   add the offline suite entry point in `tests/current_api_tests.rs`, its analysis
   and search/URL modules in `tests/current_api/`, and
   `examples/current_api_models.rs`.
3. **Integrator:** implement transport and bounded iterator changes, review each
   agent's work, run repository gates with API keys unset, verify the consumer
   feature/MSRV matrix and Cargo package contents, and inspect hosted checks on the
   exact PR commit. No release, publication, or live endpoint mutations are part
   of this plan.

The focused suite's [analysis tests](../tests/current_api/analyses.rs) and
[search/URL tests](../tests/current_api/search_urls.rs) record protocol and failure
regressions. Local and hosted
validation receipts belong in the resulting PR so this document does not present
an unrun check as passed.

## Deferred and partially verified surfaces

- **VirusTotal Monitor:** no resource client exists. Official [item listing](https://docs.virustotal.com/reference/monitor-items-filter), [item retrieval](https://docs.virustotal.com/reference/monitor-items-stat), and [statistics](https://docs.virustotal.com/reference/monitor-statistics) prove a missing product surface. A later plan should establish Monitor entitlement, model file/folder differences, and implement a coherent lifecycle rather than guessed endpoints.
- **Legacy response models:** nullable results in old analysis and URL verdict fields remain a compatibility limit. Use current analysis reports or raw/extensible search results. An intentional breaking model migration should cover all affected resources together. Only changed endpoints were independently compared with upstream payloads.
- **Private large-file upload:** `PrivateFilesClient::upload_large_file` remains a placeholder that panics. It needs a separately verified private-upload wire contract; this refresh does not claim that method works.
- **Premium/private/admin catalog:** current resource clients exist but this audit does not establish complete method/schema coverage or live correctness for feeds, private scanning, hunting, graphs, and administration. Account-specific privileges and quotas still apply.
- **Future and preview APIs:** no speculative endpoint or preview schema was added. Unknown analysis status and generic search payloads are retained, but do not imply endpoint support.
- **Dormant CLI commands:** scanning, search, report, configuration, and indexing command modules are commented out in `src/cli/commands/mod.rs`; compiling their source files is not evidence that these command paths are available. This SDK refresh does not reactivate them.
- **Automatic retries/custom limiters:** the enhanced builder still does not apply these settings. The standalone utilities remain available; automatically retrying writes needs a separate operation-specific policy.

See [API coverage](api-coverage.md) and [configuration](configuration.md) for the
user-facing support and privilege boundaries.
