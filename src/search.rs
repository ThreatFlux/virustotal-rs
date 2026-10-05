use crate::objects::{Collection, CollectionIterator};
use crate::url_utils::EndpointBuilder;
use crate::{Client, Result, impl_enum_to_string};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Search result that can contain different types of objects
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum SearchResult {
    File(FileSearchResult),
    Url(UrlSearchResult),
    Domain(DomainSearchResult),
    IpAddress(IpAddressSearchResult),
    Comment(CommentSearchResult),
}

impl<'de> Deserialize<'de> for SearchResult {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        let kind = value
            .get("type")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| serde::de::Error::custom("Search object requires a string type"))?;
        match kind {
            "file" => serde_json::from_value(value).map(Self::File),
            "url" => serde_json::from_value(value).map(Self::Url),
            "domain" => serde_json::from_value(value).map(Self::Domain),
            "ip_address" => serde_json::from_value(value).map(Self::IpAddress),
            "comment" => serde_json::from_value(value).map(Self::Comment),
            _ => {
                return Err(serde::de::Error::custom(
                    "Unsupported legacy search object type; use search_objects",
                ));
            }
        }
        .map_err(serde::de::Error::custom)
    }
}

/// An extensible search object, including future object types and context fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchObject {
    #[serde(rename = "type")]
    pub object_type: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_attributes: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<HashMap<String, String>>,
    #[serde(flatten)]
    pub additional_fields: HashMap<String, serde_json::Value>,
}

/// One search page, retaining provider metadata such as `days_back`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchPage {
    pub data: Vec<SearchObject>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<HashMap<String, String>>,
    #[serde(flatten)]
    pub additional_fields: HashMap<String, serde_json::Value>,
}

/// File search result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSearchResult {
    #[serde(rename = "type")]
    pub object_type: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_attributes: Option<FileContextAttributes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<HashMap<String, String>>,
}

/// URL search result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlSearchResult {
    #[serde(rename = "type")]
    pub object_type: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<HashMap<String, String>>,
}

/// Domain search result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainSearchResult {
    #[serde(rename = "type")]
    pub object_type: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<HashMap<String, String>>,
}

/// IP Address search result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpAddressSearchResult {
    #[serde(rename = "type")]
    pub object_type: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<HashMap<String, String>>,
}

/// Comment search result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommentSearchResult {
    #[serde(rename = "type")]
    pub object_type: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<CommentSearchAttributes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<HashMap<String, String>>,
}

/// Attributes for comment search results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommentSearchAttributes {
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub html: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub votes: Option<CommentVotesInfo>,
}

/// Comment votes information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommentVotesInfo {
    pub positive: u32,
    pub negative: u32,
    pub abuse: u32,
}

/// Context attributes for file content searches
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileContextAttributes {
    /// Match confidence (0.0 to 1.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,

    /// Whether the content match was found in a subfile
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_in_subfile: Option<bool>,

    /// Snippet ID for retrieving the matched content
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,

    /// Similarity score for fuzzy hash searches (0.0 to 1.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub similarity_score: Option<f64>,
}

/// Options for sorting search results
#[derive(Debug, Clone, Copy)]
pub enum SearchOrder {
    FirstSubmissionDateAsc,
    FirstSubmissionDateDesc,
    LastSubmissionDateAsc,
    LastSubmissionDateDesc,
    PositivesAsc,
    PositivesDesc,
    TimesSubmittedAsc,
    TimesSubmittedDesc,
    SizeAsc,
    SizeDesc,
    CreationDateAsc,
    CreationDateDesc,
    LastModificationDateAsc,
    LastModificationDateDesc,
    LastUpdateDateAsc,
    LastUpdateDateDesc,
}

impl_enum_to_string! {
    SearchOrder {
        FirstSubmissionDateAsc => "first_submission_date+",
        FirstSubmissionDateDesc => "first_submission_date-",
        LastSubmissionDateAsc => "last_submission_date+",
        LastSubmissionDateDesc => "last_submission_date-",
        PositivesAsc => "positives+",
        PositivesDesc => "positives-",
        TimesSubmittedAsc => "times_submitted+",
        TimesSubmittedDesc => "times_submitted-",
        SizeAsc => "size+",
        SizeDesc => "size-",
        CreationDateAsc => "creation_date+",
        CreationDateDesc => "creation_date-",
        LastModificationDateAsc => "last_modification_date+",
        LastModificationDateDesc => "last_modification_date-",
        LastUpdateDateAsc => "last_update_date+",
        LastUpdateDateDesc => "last_update_date-",
    }
}

/// Response for content search snippets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnippetResponse {
    pub data: Vec<String>,
}

/// Client for search operations
pub struct SearchClient<'a> {
    pub(crate) client: &'a Client,
}

impl<'a> SearchClient<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// General search for files, URLs, domains, IPs and comments
    ///
    /// This endpoint searches any of the following:
    /// - A file hash - Returns a File object
    /// - A URL - Returns a URL object
    /// - A domain - Returns Domain object
    /// - An IP address - Returns an IP address object
    /// - Comments by tags - Returns a list of Comment objects
    pub async fn search(&self, query: &str) -> Result<Collection<SearchResult>> {
        let endpoint = EndpointBuilder::new()
            .raw_segment("search")
            .query("query", query)
            .build();
        self.client.get(&endpoint).await
    }

    /// Search without discarding unknown object types, extensions, or page metadata.
    pub async fn search_objects(&self, query: &str) -> Result<SearchPage> {
        let endpoint = EndpointBuilder::new()
            .raw_segment("search")
            .query("query", query)
            .build();
        self.client.get(&endpoint).await
    }

    /// Lazily page extensible search objects using the shared bounded iterator.
    /// Page metadata is available from [`Self::search_objects`].
    pub fn search_objects_iterator(&self, query: &str) -> CollectionIterator<'_, SearchObject> {
        let endpoint = EndpointBuilder::new()
            .raw_segment("search")
            .query("query", query)
            .build();
        CollectionIterator::new(self.client, endpoint)
    }

    /// Search the premium intelligence corpus for current heterogeneous objects.
    ///
    /// A provided page limit must be in `1..=300`. The cursor and sort direction
    /// are encoded as query values; the `+` in ascending order remains literal.
    pub async fn intelligence_search_objects(
        &self,
        query: &str,
        order: Option<SearchOrder>,
        limit: Option<u32>,
        cursor: Option<&str>,
        descriptors_only: bool,
    ) -> Result<SearchPage> {
        if limit.is_some_and(|value| !(1..=300).contains(&value)) {
            return Err(crate::Error::invalid_argument(
                "Search page limit must be in 1..=300",
            ));
        }
        let endpoint = Self::intelligence_endpoint(query, order, descriptors_only)
            .query_opt("limit", limit)
            .query_opt("cursor", cursor)
            .build();
        self.client.get(&endpoint).await
    }

    /// Lazily page heterogeneous premium intelligence results.
    pub fn intelligence_search_objects_iterator(
        &self,
        query: &str,
        order: Option<SearchOrder>,
        descriptors_only: bool,
    ) -> CollectionIterator<'_, SearchObject> {
        let endpoint = Self::intelligence_endpoint(query, order, descriptors_only).build();
        CollectionIterator::new(self.client, endpoint)
    }

    fn intelligence_endpoint(
        query: &str,
        order: Option<SearchOrder>,
        descriptors_only: bool,
    ) -> EndpointBuilder {
        EndpointBuilder::new()
            .raw_segment("intelligence")
            .raw_segment("search")
            .query("query", query)
            .query_opt("order", order.map(|value| value.to_string()))
            .query("descriptors_only", descriptors_only)
    }

    /// Search with pagination support
    pub fn search_iterator(&self, query: &str) -> CollectionIterator<'_, SearchResult> {
        let url = EndpointBuilder::new()
            .raw_segment("search")
            .query("query", query)
            .build();
        CollectionIterator::new(self.client, url)
    }

    /// Advanced corpus search (Intelligence API)
    ///
    /// This endpoint allows searching for files in `VirusTotal`'s dataset using
    /// the same query syntax as the `VirusTotal` Intelligence user interface.
    ///
    /// Requires premium privileges.
    pub async fn intelligence_search(
        &self,
        query: &str,
        order: Option<SearchOrder>,
        limit: Option<u32>,
        descriptors_only: bool,
    ) -> Result<Collection<FileSearchResult>> {
        let endpoint = Self::intelligence_endpoint(query, order, descriptors_only)
            .query_opt("limit", limit.map(|value| value.min(300)))
            .build();
        self.client.get(&endpoint).await
    }

    /// Intelligence search with pagination support
    pub fn intelligence_search_iterator(
        &self,
        query: &str,
        order: Option<SearchOrder>,
        descriptors_only: bool,
    ) -> CollectionIterator<'_, FileSearchResult> {
        let url = Self::intelligence_endpoint(query, order, descriptors_only).build();
        CollectionIterator::new(self.client, url)
    }

    /// Get file content search snippets
    ///
    /// Returns file content snippets that matched a query in the search endpoint.
    /// The snippet ID is obtained from the context_attributes of content search results.
    pub async fn get_snippet(&self, snippet_id: &str) -> Result<SnippetResponse> {
        let endpoint = EndpointBuilder::new()
            .raw_segment("intelligence")
            .raw_segment("search")
            .raw_segment("snippets")
            .segment(snippet_id)
            .build();
        self.client.get(&endpoint).await
    }
}

impl Client {
    /// Get the Search client for search operations
    pub fn search(&self) -> SearchClient<'_> {
        SearchClient::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_order_strings() {
        assert_eq!(
            SearchOrder::FirstSubmissionDateAsc.to_string(),
            "first_submission_date+"
        );
        assert_eq!(
            SearchOrder::FirstSubmissionDateDesc.to_string(),
            "first_submission_date-"
        );
        assert_eq!(
            SearchOrder::LastSubmissionDateAsc.to_string(),
            "last_submission_date+"
        );
        assert_eq!(
            SearchOrder::LastSubmissionDateDesc.to_string(),
            "last_submission_date-"
        );
        assert_eq!(SearchOrder::PositivesAsc.to_string(), "positives+");
        assert_eq!(SearchOrder::PositivesDesc.to_string(), "positives-");
        assert_eq!(SearchOrder::SizeAsc.to_string(), "size+");
        assert_eq!(SearchOrder::SizeDesc.to_string(), "size-");
    }

    #[test]
    fn test_file_context_attributes() {
        let attrs = FileContextAttributes {
            confidence: Some(0.95),
            match_in_subfile: Some(false),
            snippet: Some("snippet_id_123".to_string()),
            similarity_score: Some(0.85),
        };

        assert_eq!(attrs.confidence.unwrap(), 0.95);
        assert!(!attrs.match_in_subfile.unwrap());
        assert_eq!(attrs.snippet.unwrap(), "snippet_id_123");
        assert_eq!(attrs.similarity_score.unwrap(), 0.85);
    }

    #[test]
    fn test_comment_search_attributes() {
        let attrs = CommentSearchAttributes {
            text: "Test comment #malware".to_string(),
            html: Some("<p>Test comment #malware</p>".to_string()),
            date: Some(1234567890),
            tags: Some(vec!["malware".to_string()]),
            votes: Some(CommentVotesInfo {
                positive: 5,
                negative: 1,
                abuse: 0,
            }),
        };

        assert_eq!(attrs.text, "Test comment #malware");
        assert!(attrs.tags.unwrap().contains(&"malware".to_string()));
        assert_eq!(attrs.votes.unwrap().positive, 5);
    }

    #[test]
    fn test_file_search_result() {
        let result = FileSearchResult {
            object_type: "file".to_string(),
            id: "abc123".to_string(),
            context_attributes: Some(FileContextAttributes {
                confidence: Some(1.0),
                match_in_subfile: Some(false),
                snippet: None,
                similarity_score: None,
            }),
            attributes: None,
            links: None,
        };

        assert_eq!(result.object_type, "file");
        assert_eq!(result.id, "abc123");
        assert_eq!(result.context_attributes.unwrap().confidence.unwrap(), 1.0);
    }

    #[test]
    fn test_snippet_response() {
        let response = SnippetResponse {
            data: vec![
                "00000000: 48 65 6C 6C 6F 20 *57 6F 72 6C 64* 21  Hello *World*!".to_string(),
                "00000010: 54 68 69 73 20 69 73 20 61 20 74 65  This is a te".to_string(),
            ],
        };

        assert_eq!(response.data.len(), 2);
        assert!(response.data[0].contains("*World*"));
    }
}
