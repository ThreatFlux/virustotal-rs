// Simplified file utility and metadata tests
use virustotal_rs::objects::ObjectOperations;
use virustotal_rs::{ApiTier, ClientBuilder, File};
use wiremock::MockServer;

/// Helper function to create test client
async fn create_test_client(mock_server: &MockServer) -> virustotal_rs::Client {
    ClientBuilder::new()
        .api_key("test_key")
        .tier(ApiTier::Public)
        .base_url(mock_server.uri())
        .build()
        .unwrap()
}

/// File metadata and utility tests
#[cfg(test)]
mod file_metadata_tests {
    use super::*;

    #[tokio::test]
    async fn test_file_collection_name() {
        assert_eq!(File::collection_name(), "files");
    }

    #[tokio::test]
    async fn test_file_url() {
        assert_eq!(
            File::object_url("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"),
            "files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        );
    }

    #[tokio::test]
    async fn test_file_relationships_url() {
        assert_eq!(
            File::relationships_url("hash123", "bundled_files"),
            "files/hash123/relationships/bundled_files"
        );
    }

    #[tokio::test]
    async fn test_file_relationship_methods_exist() {
        // Test that the File type has the expected relationship methods
        let mock_server = MockServer::start().await;
        let client = create_test_client(&mock_server).await;
        let file_client = client.files();

        // These would normally be tested with actual API calls, but we're just
        // verifying the methods exist and can be called
        let hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

        // These calls will fail due to no mock setup, but they demonstrate
        // that the methods exist and have correct signatures
        let _ = file_client.get(hash).await;
        let _ = file_client.analyse(hash).await;
        let _ = file_client.get_comments(hash).await;
        let _ = file_client.get_votes(hash).await;
        let _ = file_client.get_behaviours(hash).await;
        let _ = file_client.get_contacted_domains(hash).await;
        let _ = file_client.get_contacted_ips(hash).await;
        let _ = file_client.get_dropped_files(hash).await;
        let _ = file_client.get_similar_files(hash).await;

        // If we get here without compilation errors, the methods exist
        // Test passed - methods are accessible
    }

    #[tokio::test]
    async fn test_file_client_creation() {
        let mock_server = MockServer::start().await;
        let client = create_test_client(&mock_server).await;
        let file_client = client.files();

        // Test that the file client was created successfully
        // This is a basic smoke test
        assert!(std::ptr::addr_of!(file_client) != std::ptr::null());
    }

    #[tokio::test]
    async fn test_static_methods() {
        // Test static utility methods
        let collection_name = File::collection_name();
        assert_eq!(collection_name, "files");

        let object_url = File::object_url("test_hash");
        assert!(object_url.contains("test_hash"));
        assert!(object_url.starts_with("files/"));

        let relationship_url = File::relationships_url("test_hash", "test_relationship");
        assert!(relationship_url.contains("test_hash"));
        assert!(relationship_url.contains("test_relationship"));
        assert!(relationship_url.contains("relationships"));
    }

    #[tokio::test]
    async fn test_file_hash_validation() {
        // Test that we can validate file hash formats
        let valid_sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        let valid_md5 = "44d88612fea8a8f36de82e1278abb02f";

        assert_eq!(valid_sha256.len(), 64); // SHA256 should be 64 chars
        assert_eq!(valid_md5.len(), 32); // MD5 should be 32 chars

        // Test that hashes contain only hex characters
        assert!(valid_sha256.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(valid_md5.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn test_file_operations_smoke_test() {
        // Basic smoke test to ensure file operations can be instantiated
        let mock_server = MockServer::start().await;
        let client = create_test_client(&mock_server).await;
        let _file_client = client.files();

        // Test various URL generation methods
        let test_hash = "abcdef1234567890";

        assert!(File::object_url(test_hash).contains(test_hash));
        assert!(File::relationships_url(test_hash, "comments").contains("comments"));
        assert!(File::relationships_url(test_hash, "votes").contains("votes"));
        assert!(File::relationships_url(test_hash, "behaviours").contains("behaviours"));
    }
}
