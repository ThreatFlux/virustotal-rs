use super::{types::*, LivehuntClient};
use crate::objects::{Collection, CollectionIterator};
use crate::Result;

/// Helper function to build query URL with common parameters
fn build_query_url(base: &str, params: &[(Option<&str>, &str)]) -> String {
    let mut url = String::from(base);
    let mut has_query = false;
    
    for (value, key) in params {
        if let Some(v) = value {
            if !has_query {
                url.push('?');
                has_query = true;
            } else {
                url.push('&');
            }
            url.push_str(&format!("{}={}", key, urlencoding::encode(v)));
        }
    }
    
    url
}

/// Helper function to build query URL with numeric parameters
fn build_query_url_with_numeric(base: &str, filter: Option<&str>, limit: Option<u32>, count_limit: Option<u32>, cursor: Option<&str>) -> String {
    let mut url = String::from(base);
    let mut has_query = false;
    
    let add_param = |url: &mut String, has_query: &mut bool, key: &str, value: &str| {
        if !*has_query {
            url.push('?');
            *has_query = true;
        } else {
            url.push('&');
        }
        url.push_str(&format!("{}={}", key, value));
    };
    
    if let Some(f) = filter {
        add_param(&mut url, &mut has_query, "filter", &urlencoding::encode(f));
    }
    
    if let Some(l) = limit {
        add_param(&mut url, &mut has_query, "limit", &l.to_string());
    }
    
    if let Some(cl) = count_limit {
        add_param(&mut url, &mut has_query, "count_limit", &cl.min(10000).to_string());
    }
    
    if let Some(c) = cursor {
        add_param(&mut url, &mut has_query, "cursor", &urlencoding::encode(c));
    }
    
    url
}

impl<'a> LivehuntClient<'a> {
    /// Get Livehunt notifications
    pub async fn list_notifications(
        &self,
        filter: Option<&str>,
        order: Option<NotificationOrder>,
        limit: Option<u32>,
        count_limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<LivehuntNotification>> {
        let mut url = build_query_url_with_numeric(
            "intelligence/hunting_notifications", 
            filter, 
            limit, 
            count_limit, 
            cursor
        );
        
        if let Some(o) = order {
            let separator = if url.contains('?') { "&" } else { "?" };
            url.push_str(&format!("{}order={}", separator, o.to_string()));
        }
        
        self.client.get(&url).await
    }

    /// List notifications with pagination support
    pub fn list_notifications_iterator(
        &self,
        filter: Option<&str>,
        order: Option<NotificationOrder>,
        count_limit: Option<u32>,
    ) -> CollectionIterator<'_, LivehuntNotification> {
        let mut url = build_query_url_with_numeric(
            "intelligence/hunting_notifications", 
            filter, 
            None, 
            count_limit, 
            None
        );
        
        if let Some(o) = order {
            let separator = if url.contains('?') { "&" } else { "?" };
            url.push_str(&format!("{}order={}", separator, o.to_string()));
        }
        
        CollectionIterator::new(self.client, url)
    }

    /// Helper to build notification URL with ID
    fn build_notification_id_url(&self, notification_id: &str) -> String {
        format!(
            "intelligence/hunting_notifications/{}",
            urlencoding::encode(notification_id)
        )
    }
    
    /// Get a specific notification
    pub async fn get_notification(&self, notification_id: &str) -> Result<LivehuntNotification> {
        let url = self.build_notification_id_url(notification_id);
        self.client.get(&url).await
    }

    /// Delete a specific notification
    pub async fn delete_notification(&self, notification_id: &str) -> Result<()> {
        let url = self.build_notification_id_url(notification_id);
        self.client.delete(&url).await
    }

    /// Delete notifications in bulk
    pub async fn delete_notifications(&self, tag: Option<&str>) -> Result<()> {
        let url = build_query_url("intelligence/hunting_notifications", &[(tag, "tag")]);
        self.client.delete(&url).await
    }

    /// Retrieve file objects for notifications
    pub async fn list_notification_files(
        &self,
        filter: Option<&str>,
        limit: Option<u32>,
        count_limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<NotificationFile>> {
        let url = build_query_url_with_numeric(
            "intelligence/hunting_notification_files", 
            filter, 
            limit, 
            count_limit, 
            cursor
        );
        self.client.get(&url).await
    }
}
