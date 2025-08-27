/// Custom assertion macros for common test patterns
///
/// Assert that analysis statistics indicate clean results
#[macro_export]
macro_rules! assert_analysis_clean {
    ($stats:expr) => {
        assert_eq!($stats.malicious, 0, "Expected no malicious detections");
        assert_eq!($stats.suspicious, 0, "Expected no suspicious detections");
        assert!($stats.harmless > 0, "Expected some harmless detections");
    };
}

/// Assert that analysis statistics indicate malicious results
#[macro_export]
macro_rules! assert_analysis_malicious {
    ($stats:expr) => {
        assert!(
            $stats.malicious > 0 || $stats.suspicious > 0,
            "Expected malicious or suspicious detections"
        );
    };
}

/// Assert that a result has a specific error type
#[macro_export]
macro_rules! assert_error_type {
    ($result:expr, $error_type:pat) => {
        match $result {
            Err($error_type) => {}
            Ok(_) => panic!("Expected error, got success"),
            Err(other) => panic!("Expected specific error type, got: {:?}", other),
        }
    };
}

/// Assert that a value is within a specific range
#[macro_export]
macro_rules! assert_in_range {
    ($value:expr, $min:expr, $max:expr) => {
        assert!(
            ($min..=$max).contains(&$value),
            "Expected {} to be between {} and {}",
            $value,
            $min,
            $max
        );
    };
}

/// Assert that a string contains a substring
#[macro_export]
macro_rules! assert_contains_substring {
    ($haystack:expr, $needle:expr) => {
        assert!(
            $haystack.contains($needle),
            "Expected '{}' to contain '{}'",
            $haystack,
            $needle
        );
    };
}

/// Assert that an HTTP status code is successful
#[macro_export]
macro_rules! assert_http_success {
    ($status:expr) => {
        assert!(
            $status >= 200 && $status < 300,
            "Expected successful HTTP status, got: {}",
            $status
        );
    };
}

/// Assert that an HTTP status code indicates an error
#[macro_export]
macro_rules! assert_http_error {
    ($status:expr) => {
        assert!(
            $status >= 400,
            "Expected HTTP error status, got: {}",
            $status
        );
    };
}
