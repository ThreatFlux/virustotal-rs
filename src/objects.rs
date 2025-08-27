use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::marker::PhantomData;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Object<T> {
    #[serde(rename = "type")]
    pub object_type: String,
    pub id: String,
    pub links: Option<Links>,
    pub attributes: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationships: Option<HashMap<String, Relationship>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Links {
    #[serde(rename = "self")]
    pub self_link: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Relationship {
    OneToOne(OneToOneRelationship),
    OneToMany(OneToManyRelationship),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneToOneRelationship {
    pub data: ObjectDescriptor,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Links>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneToManyRelationship {
    pub data: Vec<ObjectDescriptorOrError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<CollectionMeta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Links>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectDescriptor {
    #[serde(rename = "type")]
    pub object_type: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ObjectDescriptorOrError {
    Descriptor(ObjectDescriptor),
    Error {
        error: RelationshipError,
        id: String,
        #[serde(rename = "type")]
        object_type: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectResponse<T> {
    pub data: Object<T>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchRequest<T> {
    pub data: PatchData<T>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchData<T> {
    #[serde(rename = "type")]
    pub object_type: String,
    pub id: String,
    pub attributes: T,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collection<T> {
    pub data: Vec<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<CollectionMeta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Links>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
}

pub struct CollectionIterator<'a, T> {
    client: &'a crate::Client,
    url: String,
    cursor: Option<String>,
    finished: bool,
    limit: Option<u32>,
    _phantom: PhantomData<T>,
}

impl<'a, T> CollectionIterator<'a, T>
where
    T: for<'de> Deserialize<'de> + Clone,
{
    pub fn new(client: &'a crate::Client, url: impl Into<String>) -> Self {
        Self {
            client,
            url: url.into(),
            cursor: None,
            finished: false,
            limit: None,
            _phantom: PhantomData,
        }
    }

    pub fn with_limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    pub async fn next_batch(&mut self) -> crate::Result<Vec<T>> {
        if self.finished {
            return Ok(Vec::new());
        }

        let mut url = self.url.clone();
        let mut query_params = Vec::new();

        if let Some(cursor) = &self.cursor {
            query_params.push(format!("cursor={}", cursor));
        }

        if let Some(limit) = self.limit {
            query_params.push(format!("limit={}", limit));
        }

        if !query_params.is_empty() {
            url = format!("{}?{}", url, query_params.join("&"));
        }

        let response: Collection<T> = self.client.get(&url).await?;

        let items = response.data;

        if let Some(meta) = response.meta {
            self.cursor = meta.cursor;
            if self.cursor.is_none() {
                self.finished = true;
            }
        } else {
            self.finished = true;
        }

        Ok(items)
    }

    pub async fn collect_all(mut self) -> crate::Result<Vec<T>> {
        let mut all_items = Vec::new();

        while !self.finished {
            let batch = self.next_batch().await?;
            if batch.is_empty() {
                break;
            }
            all_items.extend(batch);
        }

        Ok(all_items)
    }

    /// Check if iteration has finished
    pub fn is_finished(&self) -> bool {
        self.finished
    }
}

pub trait ObjectOperations {
    type Attributes: Serialize + for<'de> Deserialize<'de>;

    fn collection_name() -> &'static str;

    fn object_url(id: &str) -> String {
        format!("{}/{}", Self::collection_name(), id)
    }

    fn relationships_url(id: &str, relationship: &str) -> String {
        format!(
            "{}/{}/relationships/{}",
            Self::collection_name(),
            id,
            relationship
        )
    }

    fn relationship_objects_url(id: &str, relationship: &str) -> String {
        format!("{}/{}/{}", Self::collection_name(), id, relationship)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_object_serialization() {
        let obj = Object {
            object_type: "file".to_string(),
            id: "abc123".to_string(),
            links: Some(Links {
                self_link: "https://www.virustotal.com/api/v3/files/abc123".to_string(),
                next: None,
                related: None,
            }),
            attributes: json!({"name": "test.exe", "size": 1024}),
            relationships: None,
        };

        let json = serde_json::to_string(&obj).unwrap();
        assert!(json.contains("\"type\":\"file\""));
        assert!(json.contains("\"id\":\"abc123\""));
    }

    #[test]
    fn test_collection_deserialization() {
        let json = r#"{
            "data": [
                {"type": "file", "id": "1"},
                {"type": "file", "id": "2"}
            ],
            "meta": {
                "cursor": "next_cursor"
            }
        }"#;

        let collection: Collection<ObjectDescriptor> = serde_json::from_str(json).unwrap();
        assert_eq!(collection.data.len(), 2);
        assert_eq!(collection.meta.unwrap().cursor.unwrap(), "next_cursor");
    }
}
