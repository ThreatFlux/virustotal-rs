use crate::client::Client;
use crate::error::Result;
use crate::objects::{Collection, CollectionIterator};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Client for managing `VirusTotal` users
pub struct UsersClient {
    client: Client,
}

impl UsersClient {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Get a user object by ID or API key
    ///
    /// Retrieves information about a user, including privileges and quotas.
    /// Can be retrieved by user ID or API key, but using user ID only works
    /// if the requester is the user himself or an administrator of a group
    /// the user belongs to.
    ///
    /// # Arguments
    /// * `id` - User ID or API key
    ///
    /// # Example
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = virustotal_rs::Client::new("your_api_key".into(), virustotal_rs::ApiTier::Public)?;
    /// # let users_client = client.users();
    /// let user = users_client.get_user("user123").await?;
    /// // Or using API key:
    /// let user = users_client.get_user("api_key_here").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_user(&self, id: &str) -> Result<UserResponse> {
        let endpoint = format!("users/{}", id);
        self.client.get(&endpoint).await
    }

    /// Update a user object
    ///
    /// Updates user attributes. Attributes not present in the request remain unchanged.
    ///
    /// # Arguments
    /// * `id` - User ID or API key
    /// * `updates` - Partial user object with attributes to update
    ///
    /// # Example
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = virustotal_rs::Client::new("your_api_key".into(), virustotal_rs::ApiTier::Public)?;
    /// # let users_client = client.users();
    /// use virustotal_rs::users::{UserUpdateRequest, UserUpdate, UserUpdateAttributes};
    /// let updates = UserUpdateRequest {
    ///     data: UserUpdate::new(UserUpdateAttributes {
    ///             first_name: Some("John".to_string()),
    ///             last_name: Some("Doe".to_string()),
    ///             ..Default::default()
    ///         })
    /// };
    /// let updated_user = users_client.update_user("user123", &updates).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn update_user(&self, id: &str, updates: &UserUpdateRequest) -> Result<UserResponse> {
        let endpoint = format!("users/{}", id);
        self.client.patch(&endpoint, updates).await
    }

    /// Delete a user
    ///
    /// Deletes a given user. A user account can only be deleted by its owner.
    /// Requires the user's password as confirmation via the x-user-password header.
    ///
    /// # Arguments
    /// * `id` - User ID or API key
    /// * `password` - User password for confirmation
    ///
    /// # Example
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = virustotal_rs::Client::new("your_api_key".into(), virustotal_rs::ApiTier::Public)?;
    /// # let users_client = client.users();
    /// users_client.delete_user("user123", "user_password").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn delete_user(&self, id: &str, password: &str) -> Result<()> {
        let endpoint = format!("users/{}", id);
        self.client
            .delete_with_header(&endpoint, "x-user-password", password)
            .await
    }

    /// Get objects related to a user
    ///
    /// Retrieves related objects IDs for a user. Some relationships are only
    /// accessible to account owners and group admins.
    ///
    /// # Arguments
    /// * `id` - Username or API key
    /// * `relationship` - Relationship name (e.g., "api_keys", "groups", "submissions")
    /// * `limit` - Maximum number of related objects to retrieve
    /// * `cursor` - Continuation cursor for pagination
    ///
    /// # Example
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = virustotal_rs::Client::new("your_api_key".into(), virustotal_rs::ApiTier::Public)?;
    /// # let users_client = client.users();
    /// let submissions: virustotal_rs::objects::Collection<serde_json::Value> = users_client.get_relationship("user123", "submissions", Some(20), None).await?;
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
        let mut endpoint = format!("users/{}/{}", id, relationship);

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

    /// Get object descriptors related to a user
    ///
    /// Same as get_relationship but returns only IDs and context attributes
    /// instead of full objects.
    ///
    /// # Arguments
    /// * `id` - Username or API key
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
        let mut endpoint = format!("users/{}/relationships/{}", id, relationship);

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

    /// Get an iterator for user relationships
    pub fn iter_relationship<T: for<'de> Deserialize<'de> + Clone + 'static>(
        &self,
        id: &str,
        relationship: &str,
    ) -> CollectionIterator<'_, T> {
        CollectionIterator::new(&self.client, format!("users/{}/{}", id, relationship))
    }
}

/// User response from the API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResponse {
    pub data: User,
}

/// User object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// User ID
    pub id: String,

    /// Object type (always "user")
    #[serde(rename = "type")]
    pub object_type: String,

    /// User attributes
    pub attributes: UserAttributes,

    /// User relationships
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationships: Option<HashMap<String, serde_json::Value>>,

    /// Links
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<UserLinks>,
}

/// User attributes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAttributes {
    /// User's first name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,

    /// User's last name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,

    /// User's email address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    /// User's country
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,

    /// User's privileges
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privileges: Option<UserPrivileges>,

    /// User's quotas
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quotas: Option<UserQuotas>,

    /// User's preferences
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferences: Option<HashMap<String, serde_json::Value>>,

    /// User status
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,

    /// Email verified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,

    /// User biography/description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bio: Option<String>,

    /// Additional attributes
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

/// User privileges
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPrivileges {
    /// Can the user download files
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_file: Option<bool>,

    /// Can the user access intelligence data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intelligence: Option<bool>,

    /// Can the user access private scanning
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_scanning: Option<bool>,

    /// Can the user access retrohunt
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retrohunt: Option<bool>,

    /// Can the user access livehunt
    #[serde(skip_serializing_if = "Option::is_none")]
    pub livehunt: Option<bool>,

    /// Additional privileges
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

/// User quotas
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserQuotas {
    /// API requests per day
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_requests_daily: Option<ApiQuota>,

    /// API requests per month
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_requests_monthly: Option<ApiQuota>,

    /// Intelligence searches per month
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intelligence_searches_monthly: Option<ApiQuota>,

    /// Downloads per month
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intelligence_downloads_monthly: Option<ApiQuota>,

    /// Monitor quota
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monitor_storage_bytes: Option<ApiQuota>,

    /// Additional quotas
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

/// API quota information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiQuota {
    /// Number of allowed requests/items
    pub allowed: u64,

    /// Number of used requests/items
    pub used: u64,
}

/// User links
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserLinks {
    /// Link to self
    #[serde(rename = "self")]
    pub self_link: String,
}

/// User update request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserUpdateRequest {
    pub data: UserUpdate,
}

/// User update data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserUpdate {
    #[serde(rename = "type")]
    pub object_type: String,

    pub attributes: UserUpdateAttributes,
}

impl UserUpdate {
    pub fn new(attributes: UserUpdateAttributes) -> Self {
        Self {
            object_type: "user".to_string(),
            attributes,
        }
    }
}

/// User attributes that can be updated
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserUpdateAttributes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub bio: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferences: Option<HashMap<String, serde_json::Value>>,
}

impl crate::Client {
    /// Get the Users client
    pub fn users(&self) -> UsersClient {
        UsersClient::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_update_creation() {
        let attributes = UserUpdateAttributes {
            first_name: Some("John".to_string()),
            last_name: Some("Doe".to_string()),
            ..Default::default()
        };

        let update = UserUpdate::new(attributes);
        assert_eq!(update.object_type, "user");
        assert_eq!(update.attributes.first_name, Some("John".to_string()));
    }

    #[test]
    fn test_api_quota_deserialization() {
        let json = r#"{
            "allowed": 1000,
            "used": 250
        }"#;

        let quota: ApiQuota = serde_json::from_str(json).unwrap();
        assert_eq!(quota.allowed, 1000);
        assert_eq!(quota.used, 250);
    }

    #[tokio::test]
    async fn test_users_client_creation() {
        use crate::{ApiTier, ClientBuilder};

        let client = ClientBuilder::new()
            .api_key("test_key")
            .tier(ApiTier::Premium)
            .build()
            .unwrap();

        let users = client.users();

        // Test that methods exist and return errors without valid API key
        let result = users.get_user("test_user").await;
        assert!(result.is_err());
    }
}
