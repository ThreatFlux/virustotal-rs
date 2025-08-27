#[cfg(test)]
/// Test environment setup and cleanup utilities
pub struct TestEnvironment;

#[cfg(test)]
impl TestEnvironment {
    /// Setup consistent test environment
    pub fn setup() {
        std::env::set_var("RUST_LOG", "debug");
        // Initialize other test environment variables if needed
    }

    /// Cleanup test environment
    pub fn cleanup() {
        // Cleanup any temporary files or state if needed
    }

    /// Execute a test with proper setup and cleanup
    pub async fn with_test_env<F, Fut, R>(test: F) -> R
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = R>,
    {
        Self::setup();
        let result = test().await;
        Self::cleanup();
        result
    }

    /// Execute a test with a temporary file
    pub async fn with_temp_file<F, Fut, R>(content: &[u8], test: F) -> R
    where
        F: FnOnce(std::path::PathBuf) -> Fut,
        Fut: std::future::Future<Output = R>,
    {
        use std::io::Write;
        let mut temp_file = tempfile::NamedTempFile::new().expect("Failed to create temp file");
        temp_file
            .write_all(content)
            .expect("Failed to write to temp file");
        let path = temp_file.path().to_path_buf();
        let result = test(path).await;
        result
    }
}
