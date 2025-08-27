#[cfg(test)]
mod unit_tests {
    use crate::collections::*;

    #[test]
    fn test_create_collection_request() {
        let request = CreateCollectionRequest::new(
            "Test Collection".to_string(),
            Some("A test collection description".to_string()),
        )
        .with_domains(vec!["example.com".to_string(), "test.com".to_string()])
        .with_urls(vec!["https://example.com".to_string()])
        .with_ip_addresses(vec!["8.8.8.8".to_string()])
        .with_files(vec!["abc123def456".to_string()]);

        assert_eq!(request.data.attributes.name, "Test Collection");
        assert_eq!(
            request.data.attributes.description.unwrap(),
            "A test collection description"
        );
        assert!(request.data.relationships.is_some());

        let relationships = request.data.relationships.unwrap();
        assert_eq!(relationships.domains.unwrap().data.len(), 2);
        assert_eq!(relationships.urls.unwrap().data.len(), 1);
        assert_eq!(relationships.ip_addresses.unwrap().data.len(), 1);
        assert_eq!(relationships.files.unwrap().data.len(), 1);
    }

    #[test]
    fn test_url_descriptor_variants() {
        let url_desc = UrlDescriptor::WithUrl {
            object_type: "url".to_string(),
            url: "https://example.com".to_string(),
        };

        let id_desc = UrlDescriptor::WithId {
            object_type: "url".to_string(),
            id: "abc123".to_string(),
        };

        // Test serialization
        let url_json = serde_json::to_string(&url_desc).unwrap();
        assert!(url_json.contains("\"url\""));
        assert!(url_json.contains("https://example.com"));

        let id_json = serde_json::to_string(&id_desc).unwrap();
        assert!(id_json.contains("\"id\""));
        assert!(id_json.contains("abc123"));
    }

    #[test]
    fn test_collection_order_strings() {
        assert_eq!(
            CollectionOrder::CreationDateAsc.to_string(),
            "creation_date+"
        );
        assert_eq!(
            CollectionOrder::CreationDateDesc.to_string(),
            "creation_date-"
        );
        assert_eq!(CollectionOrder::FilesAsc.to_string(), "files+");
        assert_eq!(CollectionOrder::FilesDesc.to_string(), "files-");
        assert_eq!(CollectionOrder::DomainsAsc.to_string(), "domains+");
        assert_eq!(CollectionOrder::DomainsDesc.to_string(), "domains-");
    }

    #[test]
    fn test_export_format_strings() {
        assert_eq!(ExportFormat::Json.to_string(), "json");
        assert_eq!(ExportFormat::Csv.to_string(), "csv");
        assert_eq!(ExportFormat::Stix.to_string(), "stix");
    }

    #[test]
    fn test_update_collection_request() {
        let request = UpdateCollectionRequest {
            data: UpdateCollectionData {
                attributes: Some(UpdateCollectionAttributes {
                    name: Some("Updated Name".to_string()),
                    description: Some("Updated description".to_string()),
                }),
                raw_items: Some("example.com, 8.8.8.8, malware.exe".to_string()),
                object_type: "collection".to_string(),
            },
        };

        assert!(request.data.attributes.is_some());
        let attrs = request.data.attributes.unwrap();
        assert_eq!(attrs.name.unwrap(), "Updated Name");
        assert_eq!(attrs.description.unwrap(), "Updated description");
        assert_eq!(
            request.data.raw_items.unwrap(),
            "example.com, 8.8.8.8, malware.exe"
        );
    }

    #[test]
    fn test_collection_attributes() {
        let attrs = CollectionAttributes {
            name: Some("Threat Intel Collection".to_string()),
            description: Some("APT campaign IOCs".to_string()),
            creation_date: Some(1234567890),
            owner: Some("analyst@example.com".to_string()),
            tags: Some(vec!["apt".to_string(), "malware".to_string()]),
            source_region: Some("US".to_string()),
            targeted_regions: Some(vec!["EU".to_string(), "ASIA".to_string()]),
            threat_category: Some("ransomware".to_string()),
            domains_count: Some(10),
            files_count: Some(25),
            ip_addresses_count: Some(5),
            urls_count: Some(15),
            ..Default::default()
        };

        assert_eq!(attrs.name.unwrap(), "Threat Intel Collection");
        assert_eq!(attrs.tags.unwrap().len(), 2);
        assert_eq!(attrs.source_region.unwrap(), "US");
        assert_eq!(attrs.files_count.unwrap(), 25);
    }

    #[test]
    fn test_collection_items_request() {
        let domains = vec![
            DomainDescriptor {
                object_type: "domain".to_string(),
                id: "example.com".to_string(),
            },
            DomainDescriptor {
                object_type: "domain".to_string(),
                id: "test.com".to_string(),
            },
        ];

        let request = CollectionItemsRequest { data: domains };
        assert_eq!(request.data.len(), 2);
        assert_eq!(request.data[0].id, "example.com");
        assert_eq!(request.data[1].id, "test.com");
    }

    #[test]
    fn test_create_collection_with_raw_items() {
        let request = CreateCollectionRequest::new("Raw Items Collection".to_string(), None)
            .with_raw_items(
                "This text contains IOCs: example.com, 192.168.1.1, https://malware.com"
                    .to_string(),
            );

        assert_eq!(request.data.attributes.name, "Raw Items Collection");
        assert!(request.data.raw_items.is_some());
        assert!(request.data.raw_items.unwrap().contains("example.com"));
    }
}
