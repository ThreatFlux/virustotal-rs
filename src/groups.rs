use crate::client::Client;
use crate::error::Result;
use crate::objects::{Collection, CollectionIterator};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Client for managing `VirusTotal` groups
pub struct GroupsClient {
    client: Client,
}

impl GroupsClient {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Get a group object by ID
    ///
    /// Retrieves information about a group.
    ///
    /// # Arguments
    /// * `id` - Group ID
    ///
    /// # Example
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = virustotal_rs::Client::new("your_api_key".into(), virustotal_rs::ApiTier::Public)?;
    /// # let groups_client = client.groups();
    /// let group = groups_client.get_group("group123").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_group(&self, id: &str) -> Result<GroupResponse> {
        let endpoint = format!("groups/{}", id);
        self.client.get(&endpoint).await
    }

    /// Update a group object
    ///
    /// Updates group attributes. Attributes not present in the request remain unchanged.
    ///
    /// # Arguments
    /// * `id` - Group ID
    /// * `updates` - Partial group object with attributes to update
    ///
    /// # Example
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = virustotal_rs::Client::new("your_api_key".into(), virustotal_rs::ApiTier::Public)?;
    /// # let groups_client = client.groups();
    /// use virustotal_rs::groups::{GroupUpdateRequest, GroupUpdate, GroupUpdateAttributes};
    /// let updates = GroupUpdateRequest {
    ///     data: GroupUpdate::new(GroupUpdateAttributes {
    ///             name: Some("New Group Name".to_string()),
    ///             description: Some("Updated description".to_string()),
    ///             ..Default::default()
    ///         })
    /// };
    /// let updated_group = groups_client.update_group("group123", &updates).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn update_group(
        &self,
        id: &str,
        updates: &GroupUpdateRequest,
    ) -> Result<GroupResponse> {
        let endpoint = format!("groups/{}", id);
        self.client.patch(&endpoint, updates).await
    }

    /// Get administrators for a group
    ///
    /// Returns a list of User objects who are administrators of the group.
    ///
    /// # Arguments
    /// * `id` - Group ID
    ///
    /// # Example
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = virustotal_rs::Client::new("your_api_key".into(), virustotal_rs::ApiTier::Public)?;
    /// # let groups_client = client.groups();
    /// let admins = groups_client.get_administrators("group123").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_administrators(&self, id: &str) -> Result<AdminsResponse> {
        let endpoint = format!("groups/{}/relationships/administrators", id);
        self.client.get(&endpoint).await
    }

    /// Grant group admin permissions to users
    ///
    /// Adds users as administrators. User emails must be used.
    /// No admins are removed by using this endpoint.
    ///
    /// # Arguments
    /// * `id` - Group ID
    /// * `user_emails` - List of user email addresses
    ///
    /// # Example
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = virustotal_rs::Client::new("your_api_key".into(), virustotal_rs::ApiTier::Public)?;
    /// # let groups_client = client.groups();
    /// let emails = vec!["admin1@example.com", "admin2@example.com"];
    /// groups_client.add_administrators("group123", emails).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn add_administrators(&self, id: &str, user_emails: Vec<&str>) -> Result<()> {
        let endpoint = format!("groups/{}/relationships/administrators", id);

        let users: Vec<UserDescriptor> = user_emails
            .into_iter()
            .map(|email| UserDescriptor {
                id: email.to_string(),
                object_type: "user".to_string(),
            })
            .collect();

        let request = UserListRequest { data: users };

        self.client.post(&endpoint, &request).await
    }

    /// Check if a user is a group admin
    ///
    /// # Arguments
    /// * `id` - Group ID
    /// * `user_id` - User ID to check
    ///
    /// # Example
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = virustotal_rs::Client::new("your_api_key".into(), virustotal_rs::ApiTier::Public)?;
    /// # let groups_client = client.groups();
    /// let is_admin = groups_client.is_administrator("group123", "user456").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn is_administrator(&self, id: &str, user_id: &str) -> Result<bool> {
        let endpoint = format!("groups/{}/relationships/administrators/{}", id, user_id);
        match self.client.get::<serde_json::Value>(&endpoint).await {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Revoke group admin permissions from a user
    ///
    /// # Arguments
    /// * `id` - Group ID
    /// * `user_id` - User ID to remove admin privileges from
    ///
    /// # Example
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = virustotal_rs::Client::new("your_api_key".into(), virustotal_rs::ApiTier::Public)?;
    /// # let groups_client = client.groups();
    /// groups_client.remove_administrator("group123", "user456").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn remove_administrator(&self, id: &str, user_id: &str) -> Result<()> {
        let endpoint = format!("groups/{}/relationships/administrators/{}", id, user_id);
        self.client.delete(&endpoint).await
    }

    /// Get group users
    ///
    /// Returns a list of users who are members of the group.
    ///
    /// # Arguments
    /// * `id` - Group ID
    ///
    /// # Example
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = virustotal_rs::Client::new("your_api_key".into(), virustotal_rs::ApiTier::Public)?;
    /// # let groups_client = client.groups();
    /// let users = groups_client.get_users("group123").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_users(&self, id: &str) -> Result<UsersResponse> {
        let endpoint = format!("groups/{}/relationships/users", id);
        self.client.get(&endpoint).await
    }

    /// Check if a user is a group member
    ///
    /// # Arguments
    /// * `id` - Group ID
    /// * `user_id` - User ID to check
    ///
    /// # Example
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = virustotal_rs::Client::new("your_api_key".into(), virustotal_rs::ApiTier::Public)?;
    /// # let groups_client = client.groups();
    /// let is_member = groups_client.is_member("group123", "user456").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn is_member(&self, id: &str, user_id: &str) -> Result<bool> {
        let endpoint = format!("groups/{}/relationships/users/{}", id, user_id);
        match self.client.get::<MembershipCheck>(&endpoint).await {
            Ok(response) => Ok(response.data),
            Err(_) => Ok(false),
        }
    }

    /// Remove a user from a group
    ///
    /// # Arguments
    /// * `id` - Group ID
    /// * `user_id` - User ID to remove from the group
    ///
    /// # Example
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = virustotal_rs::Client::new("your_api_key".into(), virustotal_rs::ApiTier::Public)?;
    /// # let groups_client = client.groups();
    /// groups_client.remove_user("group123", "user456").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn remove_user(&self, id: &str, user_id: &str) -> Result<()> {
        let endpoint = format!("groups/{}/relationships/users/{}", id, user_id);
        self.client.delete(&endpoint).await
    }

    /// Add users to a group
    ///
    /// Adds users as members. User emails must be used.
    /// No users are removed by using this endpoint.
    ///
    /// # Arguments
    /// * `id` - Group ID
    /// * `user_emails` - List of user email addresses
    ///
    /// # Example
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = virustotal_rs::Client::new("your_api_key".into(), virustotal_rs::ApiTier::Public)?;
    /// # let groups_client = client.groups();
    /// let emails = vec!["user1@example.com", "user2@example.com"];
    /// groups_client.add_users("group123", emails).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn add_users(&self, id: &str, user_emails: Vec<&str>) -> Result<()> {
        let endpoint = format!("groups/{}/relationships/users", id);

        let users: Vec<UserDescriptor> = user_emails
            .into_iter()
            .map(|email| UserDescriptor {
                id: email.to_string(),
                object_type: "user".to_string(),
            })
            .collect();

        let request = UserListRequest { data: users };

        self.client.post(&endpoint, &request).await
    }

    /// Get objects related to a group
    ///
    /// Retrieves related objects for a group.
    ///
    /// # Arguments
    /// * `id` - Group ID
    /// * `relationship` - Relationship name (e.g., "users", "administrators", "graphs")
    /// * `limit` - Maximum number of related objects to retrieve
    /// * `cursor` - Continuation cursor for pagination
    ///
    /// # Example
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = virustotal_rs::Client::new("your_api_key".into(), virustotal_rs::ApiTier::Public)?;
    /// # let groups_client = client.groups();
    /// let graphs: virustotal_rs::objects::Collection<serde_json::Value> = groups_client.get_relationship("group123", "graphs", Some(20), None).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_relationship<T: for<'de> Deserialize<'de>>(
        &self,
        id: &str,
        relationship: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<T>> {
        let mut endpoint = format!("groups/{}/{}", id, relationship);

        let mut params = Vec::new();
        if let Some(l) = limit {
            params.push(format!("limit={}", l));
        }
        if let Some(c) = cursor {
            params.push(format!("cursor={}", c));
        }

        if !params.is_empty() {
            endpoint.push('?');
            endpoint.push_str(&params.join("&"));
        }

        self.client.get(&endpoint).await
    }

    /// Get object descriptors related to a group
    ///
    /// Same as get_relationship but returns only descriptors and context attributes
    /// instead of full objects.
    ///
    /// # Arguments
    /// * `id` - Group ID
    /// * `relationship` - Relationship name
    /// * `limit` - Maximum number of related objects
    /// * `cursor` - Continuation cursor
    pub async fn get_relationship_descriptors<T: for<'de> Deserialize<'de>>(
        &self,
        id: &str,
        relationship: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<T>> {
        let mut endpoint = format!("groups/{}/relationships/{}", id, relationship);

        let mut params = Vec::new();
        if let Some(l) = limit {
            params.push(format!("limit={}", l));
        }
        if let Some(c) = cursor {
            params.push(format!("cursor={}", c));
        }

        if !params.is_empty() {
            endpoint.push('?');
            endpoint.push_str(&params.join("&"));
        }

        self.client.get(&endpoint).await
    }

    /// Get an iterator for group relationships
    pub fn iter_relationship<T: for<'de> Deserialize<'de> + Clone + 'static>(
        &self,
        id: &str,
        relationship: &str,
    ) -> CollectionIterator<'_, T> {
        CollectionIterator::new(&self.client, format!("groups/{}/{}", id, relationship))
    }
}

/// Group response from the API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupResponse {
    pub data: Group,
}

/// Group object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    /// Group ID
    pub id: String,

    /// Object type (always "group")
    #[serde(rename = "type")]
    pub object_type: String,

    /// Group attributes
    pub attributes: GroupAttributes,

    /// Group relationships
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationships: Option<HashMap<String, serde_json::Value>>,

    /// Links
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<GroupLinks>,
}

/// Group attributes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupAttributes {
    /// Group name
    pub name: String,

    /// Group description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Creation timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creation_date: Option<i64>,

    /// Modification timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modification_date: Option<i64>,

    /// Group owner ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<String>,

    /// Group quotas
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quotas: Option<GroupQuotas>,

    /// Additional attributes
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

/// Group quotas
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupQuotas {
    /// API requests per month
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_requests_monthly: Option<GroupApiQuota>,

    /// Intelligence searches per month
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intelligence_searches_monthly: Option<GroupApiQuota>,

    /// Intelligence downloads per month
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intelligence_downloads_monthly: Option<GroupApiQuota>,

    /// Monitor storage bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monitor_storage_bytes: Option<GroupApiQuota>,

    /// Additional quotas
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

/// Group API quota information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupApiQuota {
    /// Number of allowed requests/items for the group
    pub allowed: u64,

    /// Number of used requests/items by the group
    pub used: u64,
}

/// Group links
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupLinks {
    /// Link to self
    #[serde(rename = "self")]
    pub self_link: String,
}

/// Group update request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupUpdateRequest {
    pub data: GroupUpdate,
}

/// Group update data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupUpdate {
    #[serde(rename = "type")]
    pub object_type: String,

    pub attributes: GroupUpdateAttributes,
}

impl GroupUpdate {
    pub fn new(attributes: GroupUpdateAttributes) -> Self {
        Self {
            object_type: "group".to_string(),
            attributes,
        }
    }
}

/// Group attributes that can be updated
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GroupUpdateAttributes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// User descriptor for adding to groups
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDescriptor {
    pub id: String,

    #[serde(rename = "type")]
    pub object_type: String,
}

/// Request for adding users to a group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserListRequest {
    pub data: Vec<UserDescriptor>,
}

/// Response for administrator list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminsResponse {
    pub data: Vec<crate::users::User>,
}

/// Response for user list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsersResponse {
    pub data: Vec<crate::users::User>,
}

/// Response for membership check
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MembershipCheck {
    pub data: bool,
}

impl crate::Client {
    /// Get the Groups client
    pub fn groups(&self) -> GroupsClient {
        GroupsClient::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_update_creation() {
        let attributes = GroupUpdateAttributes {
            name: Some("New Group Name".to_string()),
            description: Some("New description".to_string()),
        };

        let update = GroupUpdate::new(attributes);
        assert_eq!(update.object_type, "group");
        assert_eq!(update.attributes.name, Some("New Group Name".to_string()));
    }

    #[test]
    fn test_user_descriptor_creation() {
        let descriptor = UserDescriptor {
            id: "user@example.com".to_string(),
            object_type: "user".to_string(),
        };

        assert_eq!(descriptor.id, "user@example.com");
        assert_eq!(descriptor.object_type, "user");
    }

    #[test]
    fn test_group_quota_deserialization() {
        let json = r#"{
            "allowed": 10000,
            "used": 2500
        }"#;

        let quota: GroupApiQuota = serde_json::from_str(json).unwrap();
        assert_eq!(quota.allowed, 10000);
        assert_eq!(quota.used, 2500);
    }

    #[tokio::test]
    async fn test_groups_client_creation() {
        use crate::{ApiTier, ClientBuilder};

        let client = ClientBuilder::new()
            .api_key("test_key")
            .tier(ApiTier::Premium)
            .build()
            .unwrap();

        let groups = client.groups();

        // Test that methods exist and return errors without valid API key
        let result = groups.get_group("test_group").await;
        assert!(result.is_err());
    }
}
