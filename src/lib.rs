pub mod analysis;
pub mod attack_tactics;
pub mod attack_techniques;
pub mod auth;
pub mod client;
pub mod client_utils;
pub mod collections;
pub mod comments;
pub mod common;
pub mod crowdsourced_yara_rules;
pub mod display;
pub mod domains;
pub mod error;
pub mod feeds;
pub mod file_behaviours;
pub mod files;
pub mod graphs;
pub mod groups;
pub mod ioc_stream;
pub mod ip_addresses;
pub mod iterator_utils;
pub mod livehunt;
pub mod macros;
pub mod metadata;
pub mod objects;
pub mod popular_threat_categories;
pub mod private_files;
pub mod private_files_client;
pub mod private_urls;
pub mod rate_limit;
pub mod references;
pub mod retrohunt;
pub mod search;
pub mod sigma_rules;
pub mod threat_actors;
pub mod url_utils;
pub mod urls;
pub mod users;
pub mod votes;
pub mod yara_rulesets;
pub mod zip_files;

#[cfg(feature = "mcp")]
pub mod mcp;

#[cfg(test)]
mod tests;

#[cfg(feature = "cli")]
pub mod cli;

#[cfg(test)]
pub mod test_utils;

pub use analysis::{Analysis, AnalysisResponse};
pub use attack_tactics::{AttackTactic, AttackTacticClient};
pub use attack_techniques::{AttackTechnique, AttackTechniqueClient};
pub use auth::{ApiKey, ApiTier};
pub use client::{Client, ClientBuilder};
pub use client_utils::{
    detect_api_tier, ClientUtils, EnhancedClientBuilder, HeaderUtils, RateLimitStatus, RateLimiter,
    RetryConfig, TokenBucketLimiter, COMMON_API_KEY_VARS, DEFAULT_RETRY_ATTEMPTS,
    DEFAULT_RETRY_DELAY, DEFAULT_TIMEOUT, PRIVATE_API_KEY_VARS,
};
pub use collections::{
    Collection as IocCollection, CollectionAttributes, CollectionItemsRequest, CollectionOrder,
    CollectionsClient, CreateCollectionRequest, DomainDescriptor, ExportFormat, FileDescriptor,
    IpAddressDescriptor, UpdateCollectionRequest, UrlDescriptor,
};
pub use comments::{
    Comment, CommentIterator, CommentVoteType, CommentsClient, VoteCommentResponse,
};
pub use crowdsourced_yara_rules::{
    CrowdsourcedYaraRule, CrowdsourcedYaraRulesClient, YaraRuleMeta, YaraRuleOrder,
};
pub use display::{
    display_options, format_file_size, format_list, format_reputation, format_table,
    format_timestamp, format_timestamp_relative, pretty_print_json, truncate_hash, truncate_text,
    DisplayDetails, DisplayOptions, DisplayStats, DisplayVotes, ThreatLevel, VoteConsensus,
};
pub use domains::{Domain, DomainClient};
pub use error::{Error, Result};
pub use feeds::{
    BehaviorContextAttributes, BehaviorFeedItem, DomainFeedItem, FeedConfig, FeedItem,
    FeedSubmitter, FeedsClient, IpFeedItem, UrlFeedItem,
};
pub use file_behaviours::{FileBehaviour, FileBehaviourClient};
pub use files::{
    File, FileBehavior, FileBehaviorSummary, FileBehaviorSummaryResponse, FileClient, MitreTactic,
    MitreTechnique, MitreTrees,
};
pub use graphs::{
    AddGraphCommentRequest, CreateGraphRequest, GrantPermissionRequest, Graph, GraphClient,
    GraphOrder, GraphOwner, GraphPermissionCheckResponse, GraphRelationshipDescriptor,
    GraphVisibility, PermissionDescriptor, UpdateGraphRequest,
};
pub use groups::{
    AdminsResponse, Group, GroupApiQuota, GroupAttributes, GroupQuotas, GroupResponse, GroupUpdate,
    GroupUpdateAttributes, GroupUpdateRequest, GroupsClient, UserDescriptor, UserListRequest,
    UsersResponse as GroupUsersResponse,
};
pub use ioc_stream::{
    EntityType, HuntingInfo, IocStreamClient, IocStreamContext, IocStreamNotification,
    IocStreamObject, IocStreamOrder, NotificationSource, SourceType,
};
pub use ip_addresses::{IpAddress, IpAddressClient};
pub use iterator_utils::{
    BatchIterator, CachedIterator, Collectable, CollectionIteratorAdapter,
    EnhancedCollectionIterator, FilteredIterator, IteratorExt, MappedIterator, Pageable,
    PaginatedIterator, ProgressIterator, ProgressStats, ProgressTracker, RetryIterator,
    SkippedIterator, TakeUntilIterator, ThrottledIterator,
};
pub use livehunt::{
    AddEditorsRequest, CreateLivehuntRulesetRequest, EditorDescriptor, LivehuntClient,
    LivehuntNotification, LivehuntRuleset, LivehuntRulesetOrder, MatchObjectType, NotificationFile,
    NotificationFileContext, NotificationOrder, OperationResponse, PermissionCheckResponse,
    TransferOwnershipRequest, UpdateLivehuntRulesetRequest,
};
pub use metadata::{EngineInfo, Metadata, MetadataResponse, RelationshipInfo};
pub use objects::{Collection, CollectionIterator, Object, ObjectResponse};
pub use popular_threat_categories::{PopularThreatCategoriesResponse, ThreatCategory};
pub use private_files::{
    AnalysisStats, CreatePrivateZipData, CreatePrivateZipRequest, DroppedFile, EngineResult,
    FileInfo, PrivateAnalysis, PrivateAnalysisMeta, PrivateAnalysisResponse, PrivateFile,
    PrivateFileBehavior, PrivateFileBehaviorAttributes, PrivateFileUploadParams,
    PrivateFileUploadResponse, PrivateFilesClient, PrivateZipDownloadUrlResponse, PrivateZipFile,
    PrivateZipFileAttributes, PrivateZipFileData, ProcessInfo, ReanalyzeParams, UploadUrlResponse,
};
pub use private_urls::{
    PrivateUrl, PrivateUrlAttributes, PrivateUrlResponse, PrivateUrlScanData, PrivateUrlScanParams,
    PrivateUrlScanResponse, PrivateUrlsClient, Votes,
};
pub use references::{CreateReferenceRequest, Reference, ReferencesClient};
pub use retrohunt::{
    Corpus, CreateRetrohuntJobRequest, JobStatus, MatchingFileContext, RetrohuntClient,
    RetrohuntJob, RetrohuntMatchingFile, TimeRange,
};
pub use search::{FileSearchResult, SearchClient, SearchOrder, SearchResult, SnippetResponse};
pub use sigma_rules::{SigmaRule, SigmaRuleResponse, SigmaRulesClient};
pub use threat_actors::{RelationshipOrder, ThreatActor, ThreatActorOrder, ThreatActorsClient};
pub use url_utils::{
    build_query_string, encode_path_segment, validate_domain, validate_hash, validate_ip,
    EndpointBuilder, Endpoints, QueryBuilder, VirusTotalUrlBuilder, VT_API_BASE,
};
pub use urls::{Url, UrlClient};
pub use users::{
    ApiQuota, User, UserAttributes, UserPrivileges, UserQuotas, UserResponse, UserUpdate,
    UserUpdateAttributes, UserUpdateRequest, UsersClient,
};
pub use votes::{Vote, VoteVerdict};
pub use yara_rulesets::{YaraRuleset, YaraRulesetResponse, YaraRulesetsClient};
pub use zip_files::{CreateZipFileRequest, ZipFile, ZipFileStatus, ZipFilesClient};

#[cfg(feature = "mcp")]
pub use mcp::{
    detect_indicator_type, run_http_server, run_stdio_server, vti_search, DetectionSummary,
    IndicatorType, McpResult, ThreatContext, ThreatIntelligence, VtMcpServer,
};

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_library_exports() {
        let _key = ApiKey::new("test");
        let _tier = ApiTier::Public;
        assert!(ClientBuilder::new().api_key("test").build().is_ok());
    }

    #[test]
    fn test_public_tier_configuration() {
        let tier = ApiTier::Public;
        assert_eq!(tier.daily_limit(), Some(500));
        assert_eq!(tier.requests_per_minute(), 4);
    }

    #[test]
    fn test_premium_tier_configuration() {
        let tier = ApiTier::Premium;
        assert_eq!(tier.daily_limit(), None);
        assert_eq!(tier.requests_per_minute(), u32::MAX);
    }
}
