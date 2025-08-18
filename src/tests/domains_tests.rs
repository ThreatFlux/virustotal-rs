use crate::domains::{Domain, DomainAttributes};
use crate::objects::{Object, ObjectOperations};

#[test]
fn test_domain_object_operations() {
    assert_eq!(Domain::collection_name(), "domains");
    assert_eq!(Domain::object_url("example.com"), "domains/example.com");
    assert_eq!(
        Domain::relationships_url("example.com", "subdomains"),
        "domains/example.com/relationships/subdomains"
    );
}

#[test]
fn test_domain_creation() {
    let domain = Domain {
        object: Object {
            id: "example.com".to_string(),
            object_type: "domain".to_string(),
            links: None,
            relationships: None,
            attributes: DomainAttributes {
                registrar: Some("Example Registrar".to_string()),
                creation_date: Some(1234567890),
                last_update_date: Some(1234567900),
                reputation: Some(50),
                ..Default::default()
            },
        },
    };

    assert_eq!(domain.object.id, "example.com");
    assert_eq!(
        domain.object.attributes.registrar,
        Some("Example Registrar".to_string())
    );
    assert_eq!(domain.object.attributes.reputation, Some(50));
}

#[test]
fn test_domain_attributes_default() {
    let attrs = DomainAttributes::default();
    assert!(attrs.registrar.is_none());
    assert!(attrs.creation_date.is_none());
    assert!(attrs.reputation.is_none());
}

#[test]
fn test_domain_with_whois() {
    let domain = Domain {
        object: Object {
            id: "test.com".to_string(),
            object_type: "domain".to_string(),
            links: None,
            relationships: None,
            attributes: DomainAttributes {
                whois: Some("Domain Name: test.com\nRegistrar: Test Registrar".to_string()),
                whois_date: Some(1234567890),
                ..Default::default()
            },
        },
    };

    assert!(domain.object.attributes.whois.is_some());
    assert!(domain.object.attributes.whois.unwrap().contains("test.com"));
    assert_eq!(domain.object.attributes.whois_date, Some(1234567890));
}

#[test]
fn test_domain_with_popularity_ranks() {
    use std::collections::HashMap;

    let mut ranks = HashMap::new();
    ranks.insert(
        "alexa".to_string(),
        crate::domains::PopularityRank {
            rank: 100,
            timestamp: 1234567890,
        },
    );
    ranks.insert(
        "cisco".to_string(),
        crate::domains::PopularityRank {
            rank: 200,
            timestamp: 1234567891,
        },
    );

    let domain = Domain {
        object: Object {
            id: "popular.com".to_string(),
            object_type: "domain".to_string(),
            links: None,
            relationships: None,
            attributes: DomainAttributes {
                popularity_ranks: Some(ranks),
                ..Default::default()
            },
        },
    };

    let pop_ranks = domain.object.attributes.popularity_ranks.unwrap();
    assert_eq!(pop_ranks.len(), 2);
    assert!(pop_ranks.contains_key("alexa"));
    assert!(pop_ranks.contains_key("cisco"));
}

#[test]
fn test_domain_with_categories() {
    use std::collections::HashMap;

    let mut categories = HashMap::new();
    categories.insert("forcepoint".to_string(), "news".to_string());
    categories.insert("websense".to_string(), "media".to_string());

    let domain = Domain {
        object: Object {
            id: "news.com".to_string(),
            object_type: "domain".to_string(),
            links: None,
            relationships: None,
            attributes: DomainAttributes {
                categories: Some(categories),
                ..Default::default()
            },
        },
    };

    let categories = domain.object.attributes.categories.unwrap();
    assert_eq!(categories.len(), 2);
    assert!(categories.contains_key("forcepoint"));
    assert!(categories.contains_key("websense"));
}
