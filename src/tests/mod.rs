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

// Integration tests with mocks (split for better organization)
#[cfg(test)]
mod client_http_tests;
#[cfg(test)]
mod error_handling_integration_tests;
#[cfg(test)]
mod integration_consolidated_tests;

// Coverage improvement tests (simplified for compilation)
#[cfg(test)]
mod additional_coverage_tests;
#[cfg(test)]
mod simplified_coverage_tests;

// Focused async tests (split from large async_coverage_tests.rs)
#[cfg(test)]
mod collection_iterator_async_tests;
#[cfg(test)]
mod domains_async_tests;
#[cfg(test)]
mod file_behaviours_async_tests;
#[cfg(test)]
mod files_async_tests;
#[cfg(test)]
mod ip_addresses_async_tests;

// Example tests demonstrating new utilities
#[cfg(test)]
mod example_with_new_utilities;

// Tests for the test utilities themselves
#[cfg(test)]
mod test_utilities_tests;

// Refactoring examples showing before/after
#[cfg(test)]
mod refactored_example;
