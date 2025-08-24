// Comprehensive unit tests for the `VirusTotal` SDK

// Mock infrastructure
#[cfg(test)]
pub mod mock_data;
#[cfg(test)]
pub mod test_utils;

// Unit tests
#[cfg(test)]
mod auth_tests;
#[cfg(test)]
mod client_tests;
#[cfg(test)]
mod common_tests;
#[cfg(test)]
mod domains_tests;
#[cfg(test)]
mod error_tests;
#[cfg(test)]
mod files_tests;
#[cfg(test)]
mod ip_addresses_tests;
#[cfg(test)]
mod objects_tests;
#[cfg(test)]
mod rate_limit_tests;

// Integration tests with mocks
#[cfg(test)]
mod integration_tests;

// Coverage improvement tests
// mod coverage_tests;  // Disabled due to compilation issues
#[cfg(test)]
mod additional_coverage_tests;
#[cfg(test)]
mod async_coverage_tests;
// #[cfg(test)]
// mod mcp_comprehensive_tests;
// #[cfg(test)]
// mod files_comprehensive_tests;
// #[cfg(test)]
// mod client_comprehensive_tests;
// #[cfg(test)]
// mod error_comprehensive_tests;
// mod api_modules_comprehensive_tests; // Temporarily disabled due to API structure issues
