use crate::objects::{Collection, Object, ObjectDescriptor};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TestAttributes {
    name: String,
    value: i32,
}

#[test]
fn test_object_creation() {
    let obj = Object {
        id: "test_id".to_string(),
        object_type: "test_type".to_string(),
        links: None,
        relationships: None,
        attributes: TestAttributes {
            name: "test".to_string(),
            value: 42,
        },
    };

    assert_eq!(obj.id, "test_id");
    assert_eq!(obj.object_type, "test_type");
    assert_eq!(obj.attributes.name, "test");
    assert_eq!(obj.attributes.value, 42);
}

#[test]
fn test_object_descriptor_creation() {
    let desc = ObjectDescriptor {
        id: "desc_id".to_string(),
        object_type: "desc_type".to_string(),
    };

    assert_eq!(desc.id, "desc_id");
    assert_eq!(desc.object_type, "desc_type");
}

#[test]
fn test_collection_creation() {
    let collection = Collection {
        data: vec![
            TestAttributes {
                name: "item1".to_string(),
                value: 1,
            },
            TestAttributes {
                name: "item2".to_string(),
                value: 2,
            },
        ],
        links: None,
        meta: None,
    };

    assert_eq!(collection.data.len(), 2);
    assert_eq!(collection.data[0].name, "item1");
    assert_eq!(collection.data[1].value, 2);
}

#[test]
fn test_collection_is_empty() {
    let empty_collection: Collection<TestAttributes> = Collection {
        data: vec![],
        links: None,
        meta: None,
    };

    assert!(empty_collection.data.is_empty());

    let full_collection = Collection {
        data: vec![TestAttributes {
            name: "test".to_string(),
            value: 1,
        }],
        links: None,
        meta: None,
    };

    assert!(!full_collection.data.is_empty());
}

#[test]
fn test_object_with_links() {
    use crate::objects::Links;

    let obj = Object {
        id: "test_id".to_string(),
        object_type: "test_type".to_string(),
        links: Some(Links {
            self_link: "https://example.com/object".to_string(),
            next: None,
            related: None,
        }),
        relationships: None,
        attributes: TestAttributes {
            name: "test".to_string(),
            value: 42,
        },
    };

    assert!(obj.links.is_some());
    let links = obj.links.unwrap();
    assert_eq!(links.self_link, "https://example.com/object".to_string());
}

#[test]
fn test_collection_with_meta() {
    use crate::objects::CollectionMeta;

    let collection: Collection<TestAttributes> = Collection {
        data: vec![],
        links: None,
        meta: Some(CollectionMeta {
            count: Some(100),
            cursor: Some("next_cursor".to_string()),
        }),
    };

    assert!(collection.meta.is_some());
    let meta = collection.meta.unwrap();
    assert_eq!(meta.count, Some(100));
    assert_eq!(meta.cursor, Some("next_cursor".to_string()));
}

#[test]
fn test_object_clone() {
    let obj1 = Object {
        id: "test_id".to_string(),
        object_type: "test_type".to_string(),
        links: None,
        relationships: None,
        attributes: TestAttributes {
            name: "test".to_string(),
            value: 42,
        },
    };

    let obj2 = obj1.clone();
    assert_eq!(obj1.id, obj2.id);
    assert_eq!(obj1.attributes.name, obj2.attributes.name);
}

#[test]
fn test_object_descriptor_serialization() {
    let desc = ObjectDescriptor {
        id: "desc_id".to_string(),
        object_type: "desc_type".to_string(),
    };

    let json = serde_json::to_string(&desc).unwrap();
    assert!(json.contains("\"id\":\"desc_id\""));
    assert!(json.contains("\"type\":\"desc_type\""));
}

#[test]
fn test_collection_serialization() {
    let collection = Collection {
        data: vec![TestAttributes {
            name: "item1".to_string(),
            value: 1,
        }],
        links: None,
        meta: None,
    };

    let serialized = serde_json::to_string(&collection);
    assert!(serialized.is_ok());

    let json = serialized.unwrap();
    assert!(json.contains("\"data\""));
    assert!(json.contains("\"item1\""));
}
