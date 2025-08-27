use super::{types::*, LivehuntClient};
use crate::objects::{Collection, CollectionIterator};
use crate::Result;

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
        let mut url = String::from("intelligence/hunting_notifications?");

        if let Some(f) = filter {
            url.push_str(&format!("filter={}&", urlencoding::encode(f)));
        }

        if let Some(o) = order {
            url.push_str(&format!("order={}&", o.to_string()));
        }

        if let Some(l) = limit {
            url.push_str(&format!("limit={}&", l));
        }

        if let Some(cl) = count_limit {
            url.push_str(&format!("count_limit={}&", cl.min(10000)));
        }

        if let Some(c) = cursor {
            url.push_str(&format!("cursor={}&", urlencoding::encode(c)));
        }

        // Remove trailing '&' or '?'
        url.pop();

        self.client.get(&url).await
    }

    /// List notifications with pagination support
    pub fn list_notifications_iterator(
        &self,
        filter: Option<&str>,
        order: Option<NotificationOrder>,
        count_limit: Option<u32>,
    ) -> CollectionIterator<'_, LivehuntNotification> {
        let mut url = String::from("intelligence/hunting_notifications?");

        if let Some(f) = filter {
            url.push_str(&format!("filter={}&", urlencoding::encode(f)));
        }

        if let Some(o) = order {
            url.push_str(&format!("order={}&", o.to_string()));
        }

        if let Some(cl) = count_limit {
            url.push_str(&format!("count_limit={}&", cl.min(10000)));
        }

        // Remove trailing '&' or '?'
        url.pop();

        CollectionIterator::new(self.client, url)
    }

    /// Get a specific notification
    pub async fn get_notification(&self, notification_id: &str) -> Result<LivehuntNotification> {
        let url = format!(
            "intelligence/hunting_notifications/{}",
            urlencoding::encode(notification_id)
        );
        self.client.get(&url).await
    }

    /// Delete a specific notification
    pub async fn delete_notification(&self, notification_id: &str) -> Result<()> {
        let url = format!(
            "intelligence/hunting_notifications/{}",
            urlencoding::encode(notification_id)
        );
        self.client.delete(&url).await
    }

    /// Delete notifications in bulk
    pub async fn delete_notifications(&self, tag: Option<&str>) -> Result<()> {
        let mut url = String::from("intelligence/hunting_notifications");

        if let Some(t) = tag {
            url.push_str(&format!("?tag={}", urlencoding::encode(t)));
        }

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
        let mut url = String::from("intelligence/hunting_notification_files?");

        if let Some(f) = filter {
            url.push_str(&format!("filter={}&", urlencoding::encode(f)));
        }

        if let Some(l) = limit {
            url.push_str(&format!("limit={}&", l));
        }

        if let Some(cl) = count_limit {
            url.push_str(&format!("count_limit={}&", cl.min(10000)));
        }

        if let Some(c) = cursor {
            url.push_str(&format!("cursor={}&", urlencoding::encode(c)));
        }

        // Remove trailing '&' or '?'
        url.pop();

        self.client.get(&url).await
    }
}
