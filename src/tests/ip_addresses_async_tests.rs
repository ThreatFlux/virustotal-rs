// Async IP address tests focused on IP-related API operations
use crate::test_utils::test_utilities::*;
use crate::assert_api_success;
use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::Mock;

/// Test IP address client basic operations
#[cfg(test)]
mod ip_client_tests {
    use super::*;

    #[tokio::test]
    async fn test_ip_client_get() {
        let mock_client = MockApiClient::new().await.unwrap();
        let ip_data = IpResponseBuilder::clean_ip().build();
        let response_data = ResponseFactory::success_response(ip_data);
        
        Mock::given(method("GET"))
            .and(path("/ip_addresses/8.8.8.8"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response_data))
            .mount(mock_client.mock_server())
            .await;
        
        let result = mock_client.client().ip_addresses().get("8.8.8.8").await;
        let ip = assert_api_success!(result);
        assert_eq!(ip.object.id, constants::SAMPLE_IP);
    }

    #[tokio::test]
    async fn test_ip_client_get_with_relationships() {
        let mock_client = MockApiClient::new().await.unwrap();
        let mut ip_data = IpResponseBuilder::clean_ip().build();
        ip_data["relationships"] = json!({"urls": {"data": []}});
        let response_data = ResponseFactory::success_response(ip_data);
        
        Mock::given(method("GET"))
            .and(path("/ip_addresses/8.8.8.8"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response_data))
            .mount(mock_client.mock_server())
            .await;
        
        let result = mock_client.client().ip_addresses()
            .get_with_relationships("8.8.8.8", &["urls"]).await;
        assert_api_success!(result);
    }
}

/// Macro to reduce duplication in relationship tests
macro_rules! test_ip_relationship {
    ($test_name:ident, $method:ident, $endpoint:expr) => {
        #[tokio::test]
        async fn $test_name() {
            let mock_client = MockApiClient::new().await.unwrap();
            let response_data = ResponseFactory::collection_response(vec![], None);
            
            Mock::given(method("GET"))
                .and(path($endpoint))
                .and(header("x-apikey", constants::TEST_API_KEY))
                .respond_with(create_json_response(200, &response_data))
                .mount(mock_client.mock_server())
                .await;
            
            let result = mock_client.client().ip_addresses().$method("8.8.8.8").await;
            assert_api_success!(result);
        }
    };
}

/// Test IP address relationship operations
#[cfg(test)]
mod ip_relationship_tests {
    use super::*;
    
    test_ip_relationship!(test_ip_get_urls, get_urls, "/ip_addresses/8.8.8.8/urls");
    test_ip_relationship!(test_ip_get_resolutions, get_resolutions, "/ip_addresses/8.8.8.8/resolutions");
}

/// Test IP address file relationship operations
#[cfg(test)]
mod ip_file_relationship_tests {
    use super::*;
    
    test_ip_relationship!(test_ip_get_communicating_files, get_communicating_files, "/ip_addresses/8.8.8.8/communicating_files");
    test_ip_relationship!(test_ip_get_downloaded_files, get_downloaded_files, "/ip_addresses/8.8.8.8/downloaded_files");
    test_ip_relationship!(test_ip_get_referrer_files, get_referrer_files, "/ip_addresses/8.8.8.8/referrer_files");
}