//! Constants for client utilities

use std::time::Duration;

/// Default timeout for HTTP requests
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default number of retry attempts
pub const DEFAULT_RETRY_ATTEMPTS: u32 = 3;

/// Default initial retry delay
pub const DEFAULT_RETRY_DELAY: Duration = Duration::from_millis(1000);

/// Maximum retry delay
pub const MAX_RETRY_DELAY: Duration = Duration::from_secs(60);

/// Default user agent prefix
pub(crate) const USER_AGENT_PREFIX: &str = "virustotal-rs";

/// Environment variable names for API keys
pub const COMMON_API_KEY_VARS: &[&str] = &["VIRUSTOTAL_API_KEY", "VT_API_KEY", "VTI_API_KEY"];

/// Environment variable names for private API keys
pub const PRIVATE_API_KEY_VARS: &[&str] = &["VT_PRIVATE_API_KEY", "VIRUSTOTAL_PRIVATE_API_KEY"];
