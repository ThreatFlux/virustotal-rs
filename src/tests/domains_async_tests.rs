// Async domain tests focused on domain-related API operations
use crate::{
    create_collection_response, setup_mock_http, setup_test_client, test_domain_relationship,
};
use serde_json::json;

/// Test domain client basic operations
#[cfg(test)]
mod domain_client_tests {
    use super::*;

    #[tokio::test]
    async fn test_domain_client_get() {
        let (mock_server, client) = setup_test_client!();

        let domain_data = json!({
            "data": {
                "type": "domain",
                "id": "example.com",
                "attributes": {
                    "registrar": "Example Registrar",
                    "reputation": 0
                }
            }
        });

        setup_mock_http!(
            &mock_server,
            "GET",
            "/domains/example.com",
            200,
            &domain_data
        );

        let domain_client = client.domains();
        let result = domain_client.get("example.com").await;

        assert!(result.is_ok());
        let domain = result.unwrap();
        assert_eq!(domain.object.id, "example.com");
    }

    #[tokio::test]
    async fn test_domain_client_get_with_relationships() {
        let (mock_server, client) = setup_test_client!();

        let domain_data = json!({
            "data": {
                "type": "domain",
                "id": "example.com",
                "attributes": {
                    "registrar": "Example Registrar"
                },
                "relationships": {
                    "subdomains": {"data": []}
                }
            }
        });

        setup_mock_http!(
            &mock_server,
            "GET",
            "/domains/example.com",
            200,
            &domain_data
        );

        let domain_client = client.domains();
        let result = domain_client
            .get_with_relationships("example.com", &["subdomains"])
            .await;

        assert!(result.is_ok());
    }
}

/// Test domain relationship operations
#[cfg(test)]
mod domain_relationship_tests {
    use super::*;

    // Use the new macro to generate all relationship tests
    test_domain_relationship!(test_domain_get_subdomains, "subdomains");
    test_domain_relationship!(test_domain_get_urls, "urls");
    test_domain_relationship!(test_domain_get_resolutions, "resolutions");
    test_domain_relationship!(test_domain_get_siblings, "siblings");

    #[tokio::test]
    async fn test_domain_get_parent() {
        let (mock_server, client) = setup_test_client!();

        let parent_data = json!({
            "data": {
                "type": "domain",
                "id": "parent.com",
                "attributes": {
                    "registrar": "Parent Registrar"
                }
            }
        });

        setup_mock_http!(
            &mock_server,
            "GET",
            "/domains/example.com/parent",
            200,
            &parent_data
        );

        let domain_client = client.domains();
        let result = domain_client.get_parent("example.com").await;

        assert!(result.is_ok());
    }
}

/// Test domain file relationship operations
#[cfg(test)]
mod domain_file_relationship_tests {
    use super::*;

    // Use the macro to generate all file relationship tests
    test_domain_relationship!(test_domain_get_communicating_files, "communicating_files");
    test_domain_relationship!(test_domain_get_downloaded_files, "downloaded_files");
    test_domain_relationship!(test_domain_get_referrer_files, "referrer_files");
}
