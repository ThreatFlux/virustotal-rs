use serde_json::{json, Value};
use std::collections::HashMap;
use wiremock::{
    matchers::{header, method, path, query_param},
    Mock, MockBuilder, ResponseTemplate,
};

/// A builder for creating mock VirusTotal API responses
pub struct MockResponseBuilder {
    response_data: Value,
    status_code: u16,
    headers: HashMap<String, String>,
}

impl MockResponseBuilder {
    pub fn new() -> Self {
        Self {
            response_data: json!({}),
            status_code: 200,
            headers: HashMap::new(),
        }
    }

    pub fn with_data(mut self, data: Value) -> Self {
        self.response_data = json!({ "data": data });
        self
    }

    pub fn with_error(mut self, error_code: &str, message: &str) -> Self {
        self.response_data = json!({
            "error": {
                "code": error_code,
                "message": message
            }
        });
        self
    }

    pub fn with_status(mut self, status: u16) -> Self {
        self.status_code = status;
        self
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(name.to_string(), value.to_string());
        self
    }

    pub fn build(self) -> ResponseTemplate {
        let mut response =
            ResponseTemplate::new(self.status_code).set_body_json(&self.response_data);

        for (name, value) in self.headers {
            response = response.append_header(&name, &value);
        }

        response
    }
}

impl Default for MockResponseBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper to create a mock for GET requests
pub fn mock_get(path_str: &str) -> MockBuilder {
    Mock::given(method("GET")).and(path(path_str))
}

/// Helper to create a mock for POST requests
pub fn mock_post(path_str: &str) -> MockBuilder {
    Mock::given(method("POST")).and(path(path_str))
}

/// Helper to create a mock for PUT requests
pub fn mock_put(path_str: &str) -> MockBuilder {
    Mock::given(method("PUT")).and(path(path_str))
}

/// Helper to create a mock for DELETE requests
pub fn mock_delete(path_str: &str) -> MockBuilder {
    Mock::given(method("DELETE")).and(path(path_str))
}

/// Helper to add API key header matcher
pub fn with_api_key(mock: MockBuilder, api_key: &str) -> MockBuilder {
    mock.and(header("x-apikey", api_key))
}

/// Helper to add query parameter matcher
pub fn with_query_param(mock: MockBuilder, key: &str, value: &str) -> MockBuilder {
    mock.and(query_param(key, value))
}

/// Sample file data for testing
pub fn sample_file_data() -> Value {
    json!({
        "type": "file",
        "id": "44d88612fea8a8f36de82e1278abb02f",
        "attributes": {
            "md5": "44d88612fea8a8f36de82e1278abb02f",
            "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
            "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            "size": 68,
            "type_description": "ASCII text",
            "type_tag": "text",
            "names": ["hello.txt"],
            "creation_date": 1609459200,
            "last_modification_date": 1609459200,
            "last_analysis_date": 1609459200,
            "last_analysis_stats": {
                "harmless": 70,
                "type-unsupported": 3,
                "suspicious": 0,
                "confirmed-timeout": 0,
                "timeout": 0,
                "failure": 0,
                "malicious": 0,
                "undetected": 0
            },
            "reputation": 0
        }
    })
}

/// Sample domain data for testing
pub fn sample_domain_data() -> Value {
    json!({
        "type": "domain",
        "id": "example.com",
        "attributes": {
            "categories": {
                "Forcepoint ThreatSeeker": "search engines and portals"
            },
            "creation_date": 820454400,
            "last_analysis_date": 1609459200,
            "last_analysis_stats": {
                "harmless": 82,
                "malicious": 0,
                "suspicious": 0,
                "undetected": 1,
                "timeout": 0
            },
            "reputation": 0,
            "whois": "Domain Name: EXAMPLE.COM\\nRegistry Domain ID: 2336799_DOMAIN_COM-VRSN",
            "whois_date": 1609459200
        }
    })
}

/// Sample IP address data for testing
pub fn sample_ip_data() -> Value {
    json!({
        "type": "ip_address",
        "id": "8.8.8.8",
        "attributes": {
            "country": "US",
            "as_owner": "Google LLC",
            "asn": 15169,
            "last_analysis_date": 1609459200,
            "last_analysis_stats": {
                "harmless": 82,
                "malicious": 0,
                "suspicious": 0,
                "undetected": 1,
                "timeout": 0
            },
            "network": "8.8.8.0/24",
            "reputation": 0,
            "whois": "NetRange: 8.8.8.0 - 8.8.8.255"
        }
    })
}

/// Sample error response for different HTTP status codes
pub fn sample_error_response(status_code: u16) -> (u16, Value) {
    let (error_code, message) = match status_code {
        400 => ("BadRequestError", "Bad request"),
        401 => ("AuthenticationRequiredError", "API key is required"),
        403 => ("ForbiddenError", "Access denied"),
        404 => ("NotFoundError", "Resource not found"),
        429 => ("QuotaExceededError", "Rate limit exceeded"),
        500 => ("InternalServerError", "Internal server error"),
        _ => ("UnknownError", "Unknown error"),
    };

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

/// Sample analysis data
pub fn sample_analysis_data() -> Value {
    json!({
        "type": "analysis",
        "id": "MTYzNzc3NzA4NTpkMDJhNGM5OTdjYmY4YzQ5ZTQ5NGZjYmU5MTYzYWQzNTpyZWFsdGltZQ==",
        "attributes": {
            "date": 1637777085,
            "status": "completed",
            "stats": {
                "harmless": 70,
                "type-unsupported": 3,
                "suspicious": 0,
                "confirmed-timeout": 0,
                "timeout": 0,
                "failure": 0,
                "malicious": 0,
                "undetected": 0
            }
        }
    })
}

/// Sample comment data
pub fn sample_comment_data() -> Value {
    json!({
        "type": "comment",
        "id": "f-44d88612fea8a8f36de82e1278abb02f-1609459200",
        "attributes": {
            "date": 1609459200,
            "html": "<p>This is a test comment</p>",
            "text": "This is a test comment",
            "votes": {
                "positive": 5,
                "negative": 1,
                "abuse": 0
            }
        }
    })
}

/// Sample vote data
pub fn sample_vote_data() -> Value {
    json!({
        "type": "vote",
        "id": "f-44d88612fea8a8f36de82e1278abb02f-verdict",
        "attributes": {
            "verdict": "harmless",
            "date": 1609459200
        }
    })
}

/// Sample collection data with pagination
pub fn sample_collection_data(items: Vec<Value>, cursor: Option<&str>) -> Value {
    let mut collection = json!({
        "data": items,
        "meta": {
            "count": items.len()
        }
    });

    if let Some(cursor_value) = cursor {
        collection["links"] = json!({
            "next": format!("https://www.virustotal.com/api/v3/files?cursor={}", cursor_value)
        });
    }

    collection
}

/// Sample Sigma rule data
pub fn sample_sigma_rule_data() -> Value {
    json!({
        "type": "sigma_rule",
        "id": "sigma-rule-123",
        "attributes": {
            "title": "Suspicious PowerShell Execution",
            "author": "Test Author",
            "date": "2023/01/01",
            "description": "Detects suspicious PowerShell execution patterns",
            "level": "medium",
            "status": "experimental",
            "rule_text": "title: Suspicious PowerShell\\ndetection:\\n  condition: selection",
            "tags": ["attack.execution", "attack.t1059.001"]
        }
    })
}

/// Sample YARA ruleset data
pub fn sample_yara_ruleset_data() -> Value {
    json!({
        "type": "yara_ruleset",
        "id": "yara-ruleset-456",
        "attributes": {
            "name": "Test Ruleset",
            "description": "Test YARA ruleset for malware detection",
            "creation_date": 1609459200,
            "modification_date": 1609459200,
            "rules_count": 5
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sample_data_creation() {
        let file_data = sample_file_data();
        assert_eq!(file_data["type"], "file");
        assert_eq!(file_data["id"], "44d88612fea8a8f36de82e1278abb02f");

        let domain_data = sample_domain_data();
        assert_eq!(domain_data["type"], "domain");
        assert_eq!(domain_data["id"], "example.com");

        let ip_data = sample_ip_data();
        assert_eq!(ip_data["type"], "ip_address");
        assert_eq!(ip_data["id"], "8.8.8.8");
    }

    #[test]
    fn test_sample_error_responses() {
        let (status, response) = sample_error_response(404);
        assert_eq!(status, 404);
        assert_eq!(response["error"]["code"], "NotFoundError");

        let (status, response) = sample_error_response(429);
        assert_eq!(status, 429);
        assert_eq!(response["error"]["code"], "QuotaExceededError");
    }
}
