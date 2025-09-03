#[cfg(test)]
use serde_json::{json, Value};
#[cfg(test)]
use wiremock::matchers::{header, method, path};
#[cfg(test)]
use wiremock::{Mock, ResponseTemplate};

#[cfg(test)]
/// Response factory for creating various mock responses
pub struct ResponseFactory;

#[cfg(test)]
impl ResponseFactory {
    /// Create a successful response with data
    pub fn success_response(data: Value) -> Value {
        json!({ "data": data })
    }

    /// Create a collection response with pagination
    pub fn collection_response(items: Vec<Value>, cursor: Option<&str>) -> Value {
        let mut response = json!({
            "data": items,
            "meta": {
                "count": items.len()
            }
        });

        if let Some(cursor_value) = cursor {
            response["links"] = json!({
                "next": format!("https://www.virustotal.com/api/v3/files?cursor={}", cursor_value)
            });
        }

        response
    }

    /// Create an error response
    pub fn error_response(status_code: u16, error_code: &str, message: &str) -> (u16, Value) {
        (
            status_code,
            json!({
                "error": {
                    "code": error_code,
                    "message": message
                }
            }),
        )
    }

    /// Create a rate limit error response
    pub fn rate_limit_error() -> (u16, Value) {
        Self::error_response(429, "QuotaExceededError", "Request rate limit exceeded")
    }

    /// Create a not found error response
    pub fn not_found_error() -> (u16, Value) {
        Self::error_response(404, "NotFoundError", "The requested resource was not found")
    }

    /// Create an unauthorized error response
    pub fn unauthorized_error() -> (u16, Value) {
        Self::error_response(401, "AuthenticationRequiredError", "API key is required")
    }

    /// Create a forbidden error response
    pub fn forbidden_error() -> (u16, Value) {
        Self::error_response(403, "ForbiddenError", "Access to the resource is forbidden")
    }
}

#[cfg(test)]
/// Mock response template with common VirusTotal headers
pub fn create_mock_response(status: u16) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .append_header("Content-Type", "application/json")
        .append_header("X-RateLimit-Remaining", "999")
        .append_header("X-RateLimit-Reset", "3600")
}

#[cfg(test)]
/// Mock response with JSON body
pub fn create_json_response(status: u16, body: &Value) -> ResponseTemplate {
    create_mock_response(status).set_body_json(body)
}

#[cfg(test)]
/// Common mock setup helpers to reduce duplication across tests
pub struct MockSetup;

#[cfg(test)]
impl MockSetup {
    /// Setup a standard GET endpoint mock with API key authentication
    pub async fn setup_get_endpoint(
        mock_server: &wiremock::MockServer,
        endpoint_path: &str,
        response_data: Value,
        status_code: Option<u16>,
    ) {
        let status = status_code.unwrap_or(200);
        Mock::given(method("GET"))
            .and(path(endpoint_path))
            .and(header("x-apikey", super::constants::TEST_API_KEY))
            .respond_with(create_json_response(status, &response_data))
            .mount(mock_server)
            .await;
    }

    /// Setup a GET endpoint with error response
    pub async fn setup_error_endpoint(
        mock_server: &wiremock::MockServer,
        endpoint_path: &str,
        status_code: u16,
        error_code: &str,
        error_message: &str,
    ) {
        let (_, error_response) =
            ResponseFactory::error_response(status_code, error_code, error_message);
        Mock::given(method("GET"))
            .and(path(endpoint_path))
            .and(header("x-apikey", super::constants::TEST_API_KEY))
            .respond_with(create_json_response(status_code, &error_response))
            .mount(mock_server)
            .await;
    }

    /// Setup a standard POST endpoint mock
    pub async fn setup_post_endpoint(
        mock_server: &wiremock::MockServer,
        endpoint_path: &str,
        response_data: Value,
        status_code: Option<u16>,
    ) {
        let status = status_code.unwrap_or(200);
        Mock::given(method("POST"))
            .and(path(endpoint_path))
            .and(header("x-apikey", super::constants::TEST_API_KEY))
            .respond_with(create_json_response(status, &response_data))
            .mount(mock_server)
            .await;
    }

    /// Setup multiple endpoints from a configuration
    pub async fn setup_multiple_endpoints(
        mock_server: &wiremock::MockServer,
        configs: Vec<(String, Value, Option<u16>)>,
    ) {
        for (endpoint, response, status) in configs {
            Self::setup_get_endpoint(mock_server, &endpoint, response, status).await;
        }
    }
}
