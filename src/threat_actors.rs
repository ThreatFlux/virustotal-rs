use crate::objects::{Collection, CollectionIterator, Object};
use crate::{Client, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Represents a Threat Actor in `VirusTotal`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActor {
    #[serde(flatten)]
    pub object: Object<ThreatActorAttributes>,
}

/// Attributes for a Threat Actor
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThreatActorAttributes {
    /// Alternative names by which the threat actor is known
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aliases: Option<Vec<String>>,

    /// Description/context about the threat actor
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Estimated first seen date of activity (UTC timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen_date: Option<i64>,

    /// Estimated last seen date of activity (UTC timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_date: Option<i64>,

    /// Last time when the threat actor was updated (UTC timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modification_date: Option<i64>,

    /// Threat actor's name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Ratio of change between the last two "recent activity" periods
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recent_activity_relative_change: Option<f64>,

    /// Time series representing activity (2 weeks)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recent_activity_summary: Option<Vec<i32>>,

    /// Estimated number of related IOCs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_entities_count: Option<i32>,

    /// Threat actor's source region
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_region: Option<String>,

    /// Region sponsoring the threat actor
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sponsor_region: Option<String>,

    /// List of industries the threat actor has targeted
    #[serde(skip_serializing_if = "Option::is_none")]
    pub targeted_industries: Option<Vec<String>>,

    /// List of regions the threat actor has targeted
    #[serde(skip_serializing_if = "Option::is_none")]
    pub targeted_regions: Option<Vec<String>>,

    /// Additional attributes
    #[serde(flatten)]
    pub additional_attributes: HashMap<String, serde_json::Value>,
}

/// Options for threat actor ordering
#[derive(Debug, Clone, Copy)]
pub enum ThreatActorOrder {
    FirstSeenDateAsc,
    FirstSeenDateDesc,
    LastModificationDateAsc,
    LastModificationDateDesc,
    LastSeenDateAsc,
    LastSeenDateDesc,
    RelatedEntitiesCountAsc,
    RelatedEntitiesCountDesc,
}

impl fmt::Display for ThreatActorOrder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ThreatActorOrder::FirstSeenDateAsc => "first_seen_date+",
            ThreatActorOrder::FirstSeenDateDesc => "first_seen_date-",
            ThreatActorOrder::LastModificationDateAsc => "last_modification_date+",
            ThreatActorOrder::LastModificationDateDesc => "last_modification_date-",
            ThreatActorOrder::LastSeenDateAsc => "last_seen_date+",
            ThreatActorOrder::LastSeenDateDesc => "last_seen_date-",
            ThreatActorOrder::RelatedEntitiesCountAsc => "related_entities_count+",
            ThreatActorOrder::RelatedEntitiesCountDesc => "related_entities_count-",
        };
        write!(f, "{}", s)
    }
}

/// Options for relationship ordering
#[derive(Debug, Clone, Copy)]
pub enum RelationshipOrder {
    // For collections
    CreationDateAsc,
    CreationDateDesc,
    LastModificationDateAsc,
    LastModificationDateDesc,
    OwnerAsc,
    OwnerDesc,
    NameAsc,
    NameDesc,
    // For domains
    LastUpdateDateAsc,
    LastUpdateDateDesc,
    PositivesAsc,
    PositivesDesc,
    // For files
    FirstSubmissionDateAsc,
    FirstSubmissionDateDesc,
    LastSubmissionDateAsc,
    LastSubmissionDateDesc,
    TimesSubmittedAsc,
    TimesSubmittedDesc,
    SizeAsc,
    SizeDesc,
    // For IP addresses
    IpAsc,
    IpDesc,
    // For URLs
    StatusAsc,
    StatusDesc,
}

impl fmt::Display for RelationshipOrder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            RelationshipOrder::CreationDateAsc => "creation_date+",
            RelationshipOrder::CreationDateDesc => "creation_date-",
            RelationshipOrder::LastModificationDateAsc => "last_modification_date+",
            RelationshipOrder::LastModificationDateDesc => "last_modification_date-",
            RelationshipOrder::OwnerAsc => "owner+",
            RelationshipOrder::OwnerDesc => "owner-",
            RelationshipOrder::NameAsc => "name+",
            RelationshipOrder::NameDesc => "name-",
            RelationshipOrder::LastUpdateDateAsc => "last_update_date+",
            RelationshipOrder::LastUpdateDateDesc => "last_update_date-",
            RelationshipOrder::PositivesAsc => "positives+",
            RelationshipOrder::PositivesDesc => "positives-",
            RelationshipOrder::FirstSubmissionDateAsc => "first_submission_date+",
            RelationshipOrder::FirstSubmissionDateDesc => "first_submission_date-",
            RelationshipOrder::LastSubmissionDateAsc => "last_submission_date+",
            RelationshipOrder::LastSubmissionDateDesc => "last_submission_date-",
            RelationshipOrder::TimesSubmittedAsc => "times_submitted+",
            RelationshipOrder::TimesSubmittedDesc => "times_submitted-",
            RelationshipOrder::SizeAsc => "size+",
            RelationshipOrder::SizeDesc => "size-",
            RelationshipOrder::IpAsc => "ip+",
            RelationshipOrder::IpDesc => "ip-",
            RelationshipOrder::StatusAsc => "status+",
            RelationshipOrder::StatusDesc => "status-",
        };
        write!(f, "{}", s)
    }
}

/// Client for Threat Actors operations
pub struct ThreatActorsClient<'a> {
    pub(crate) client: &'a Client,
}

impl<'a> ThreatActorsClient<'a> {
    /// Helper function to build query URL with common parameters
    fn build_query_url(
        base: &str,
        filter: Option<&str>,
        order: Option<&dyn ToString>,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> String {
        let mut url = String::from(base);
        url.push('?');

        if let Some(f) = filter {
            url.push_str(&format!("filter={}&", urlencoding::encode(f)));
        }

        if let Some(o) = order {
            url.push_str(&format!("order={}&", o.to_string()));
        }

        if let Some(l) = limit {
            url.push_str(&format!("limit={}&", l));
        }

        if let Some(c) = cursor {
            url.push_str(&format!("cursor={}&", c));
        }

        // Remove trailing '&' or '?'
        url.pop();
        url
    }

    /// Helper function to build iterator URL
    fn build_iterator_url(
        base: &str,
        filter: Option<&str>,
        order: Option<&dyn ToString>,
    ) -> String {
        let mut url = String::from(base);
        url.push('?');

        if let Some(f) = filter {
            url.push_str(&format!("filter={}&", urlencoding::encode(f)));
        }

        if let Some(o) = order {
            url.push_str(&format!("order={}&", o.to_string()));
        }

        // Remove trailing '&' or '?'
        url.pop();
        url
    }

    pub fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// List threat actors (requires special privileges)
    ///
    /// Allowed filters:
    /// - Text without modifiers: name or description
    /// - description: threat actor's description
    /// - name: threat actor's name (including aliases)
    /// - source_region: source region (ISO 3166-1 alpha-2)
    /// - sponsor_region: sponsor region
    /// - targeted_industry: targeted industry
    /// - targeted_region: targeted region
    pub async fn list(
        &self,
        filter: Option<&str>,
        order: Option<ThreatActorOrder>,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<ThreatActor>> {
        let url = Self::build_query_url(
            "threat_actors",
            filter,
            order.as_ref().map(|o| o as &dyn ToString),
            limit.map(|l| l.min(40)), // Max 40
            cursor,
        );
        self.client.get(&url).await
    }

    /// List threat actors with pagination support
    pub fn list_iterator(
        &self,
        filter: Option<&str>,
        order: Option<ThreatActorOrder>,
    ) -> CollectionIterator<'_, ThreatActor> {
        let url = Self::build_iterator_url(
            "threat_actors",
            filter,
            order.as_ref().map(|o| o as &dyn ToString),
        );
        CollectionIterator::new(self.client, url)
    }

    /// Get a threat actor by ID (requires special privileges)
    ///
    /// The ID can be:
    /// - A UUID (e.g., "1cb7e1cc-d695-42b1-92f4-fd0112a3c9be")
    /// - A threat actor name (e.g., "APT1")
    /// - An alias (e.g., "Comment Crew")
    pub async fn get(&self, threat_actor_id: &str) -> Result<ThreatActor> {
        let url = format!("threat_actors/{}", urlencoding::encode(threat_actor_id));
        self.client.get(&url).await
    }

    /// Get objects related to a threat actor
    ///
    /// Available relationships:
    /// - collections: List of Collections
    /// - comments: List of Comments
    /// - references: List of References
    /// - related_domains: List of Domains
    /// - related_files: List of Files
    /// - related_ip_addresses: List of IP addresses
    /// - related_references: List of References
    /// - related_urls: List of URLs
    pub async fn get_relationship<T>(
        &self,
        threat_actor_id: &str,
        relationship: &str,
        order: Option<RelationshipOrder>,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        let base = format!(
            "threat_actors/{}/{}",
            urlencoding::encode(threat_actor_id),
            relationship
        );
        let url = Self::build_query_url(
            &base,
            None,
            order.as_ref().map(|o| o as &dyn ToString),
            limit,
            cursor,
        );
        self.client.get(&url).await
    }

    /// Get relationship with pagination support
    pub fn get_relationship_iterator<T>(
        &self,
        threat_actor_id: &str,
        relationship: &str,
        order: Option<RelationshipOrder>,
    ) -> CollectionIterator<'_, T>
    where
        T: serde::de::DeserializeOwned + Clone + Send + 'static,
    {
        let base = format!(
            "threat_actors/{}/{}",
            urlencoding::encode(threat_actor_id),
            relationship
        );
        let url = Self::build_iterator_url(&base, None, order.as_ref().map(|o| o as &dyn ToString));
        CollectionIterator::new(self.client, url)
    }

    /// Get object descriptors related to a threat actor
    pub async fn get_relationship_descriptors<T>(
        &self,
        threat_actor_id: &str,
        relationship: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        let base = format!(
            "threat_actors/{}/relationships/{}",
            urlencoding::encode(threat_actor_id),
            relationship
        );
        let url = Self::build_query_url(&base, None, None as Option<&dyn ToString>, limit, cursor);
        self.client.get(&url).await
    }
}

impl Client {
    /// Get the Threat Actors client for threat actor operations
    pub fn threat_actors(&self) -> ThreatActorsClient<'_> {
        ThreatActorsClient::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_actor_attributes() {
        let attrs = ThreatActorAttributes {
            name: Some("APT1".to_string()),
            aliases: Some(vec![
                "Comment Crew".to_string(),
                "Advanced Persistent Threat 1".to_string(),
            ]),
            description: Some("Chinese cyber espionage group".to_string()),
            source_region: Some("CN".to_string()),
            targeted_regions: Some(vec!["US".to_string(), "EU".to_string()]),
            targeted_industries: Some(vec!["government".to_string(), "defense".to_string()]),
            related_entities_count: Some(150),
            ..Default::default()
        };

        assert_eq!(attrs.name.unwrap(), "APT1");
        assert_eq!(attrs.aliases.unwrap().len(), 2);
        assert_eq!(attrs.source_region.unwrap(), "CN");
        assert_eq!(attrs.related_entities_count.unwrap(), 150);
    }

    #[test]
    fn test_threat_actor_order_strings() {
        assert_eq!(
            ThreatActorOrder::FirstSeenDateAsc.to_string(),
            "first_seen_date+"
        );
        assert_eq!(
            ThreatActorOrder::FirstSeenDateDesc.to_string(),
            "first_seen_date-"
        );
        assert_eq!(
            ThreatActorOrder::LastModificationDateAsc.to_string(),
            "last_modification_date+"
        );
        assert_eq!(
            ThreatActorOrder::LastModificationDateDesc.to_string(),
            "last_modification_date-"
        );
        assert_eq!(
            ThreatActorOrder::RelatedEntitiesCountDesc.to_string(),
            "related_entities_count-"
        );
    }

    #[test]
    fn test_relationship_order_strings() {
        assert_eq!(
            RelationshipOrder::CreationDateAsc.to_string(),
            "creation_date+"
        );
        assert_eq!(
            RelationshipOrder::LastSubmissionDateDesc.to_string(),
            "last_submission_date-"
        );
        assert_eq!(RelationshipOrder::PositivesDesc.to_string(), "positives-");
        assert_eq!(RelationshipOrder::SizeAsc.to_string(), "size+");
        assert_eq!(RelationshipOrder::IpDesc.to_string(), "ip-");
    }

    #[test]
    fn test_threat_actor_recent_activity() {
        let attrs = ThreatActorAttributes {
            recent_activity_relative_change: Some(1.5),
            recent_activity_summary: Some(vec![10, 15, 20, 25, 30, 35, 40]),
            ..Default::default()
        };

        assert_eq!(attrs.recent_activity_relative_change.unwrap(), 1.5);
        assert_eq!(attrs.recent_activity_summary.unwrap().len(), 7);
    }

    #[test]
    fn test_threat_actor_dates() {
        let attrs = ThreatActorAttributes {
            first_seen_date: Some(1609459200),        // 2021-01-01
            last_seen_date: Some(1640995200),         // 2022-01-01
            last_modification_date: Some(1641081600), // 2022-01-02
            ..Default::default()
        };

        assert_eq!(attrs.first_seen_date.unwrap(), 1609459200);
        assert_eq!(attrs.last_seen_date.unwrap(), 1640995200);
        assert_eq!(attrs.last_modification_date.unwrap(), 1641081600);
    }
}
