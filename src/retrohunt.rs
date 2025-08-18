use crate::objects::{Collection, CollectionIterator, Object};
use crate::{Client, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a Retrohunt job in VirusTotal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetrohuntJob {
    #[serde(flatten)]
    pub object: Object<RetrohuntJobAttributes>,
}

/// Attributes for a Retrohunt job
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RetrohuntJobAttributes {
    /// YARA rules to be used for scanning
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules: Option<String>,

    /// Email address for notifications
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_email: Option<String>,

    /// Corpus to scan ("main" or "goodware")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub corpus: Option<String>,

    /// Time range for the scan
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_range: Option<TimeRange>,

    /// Job status
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<JobStatus>,

    /// Creation date (UTC timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creation_date: Option<i64>,

    /// Start time (UTC timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<i64>,

    /// Finish time (UTC timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finish_time: Option<i64>,

    /// Number of scanned files
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanned_files: Option<u64>,

    /// Number of matches
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matches: Option<u64>,

    /// Progress percentage (0-100)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<u8>,

    /// Estimated time to completion in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eta: Option<u64>,

    /// Error message if job failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Additional attributes
    #[serde(flatten)]
    pub additional_attributes: HashMap<String, serde_json::Value>,
}

/// Time range for Retrohunt jobs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    /// Start time (UTC timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start: Option<i64>,

    /// End time (UTC timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<i64>,
}

/// Status of a Retrohunt job
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Starting,
    Running,
    Aborting,
    Aborted,
    Finished,
}

/// Corpus options for Retrohunt
#[derive(Debug, Clone, Copy)]
pub enum Corpus {
    Main,
    Goodware,
}

impl Corpus {
    /// Convert to API parameter string
    pub fn to_string(&self) -> &'static str {
        match self {
            Corpus::Main => "main",
            Corpus::Goodware => "goodware",
        }
    }
}

/// Request to create a new Retrohunt job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRetrohuntJobRequest {
    pub data: CreateRetrohuntJobData,
}

/// Data for creating a Retrohunt job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRetrohuntJobData {
    #[serde(rename = "type")]
    pub object_type: String,
    pub attributes: CreateRetrohuntJobAttributes,
}

/// Attributes for creating a Retrohunt job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRetrohuntJobAttributes {
    /// YARA rules (required)
    pub rules: String,

    /// Email for notifications (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_email: Option<String>,

    /// Corpus to scan (optional, defaults to "main")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub corpus: Option<String>,

    /// Time range (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_range: Option<TimeRange>,
}

/// File matching information for Retrohunt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetrohuntMatchingFile {
    /// File object
    #[serde(flatten)]
    pub file: serde_json::Value,

    /// Context attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_attributes: Option<MatchingFileContext>,
}

/// Context attributes for matching files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchingFileContext {
    /// Rule that matched
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_name: Option<String>,

    /// Match offset in the file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_offset: Option<u64>,

    /// Match snippet
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_snippet: Option<String>,

    /// Whether match was in a subfile
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_in_subfile: Option<bool>,

    /// Additional context
    #[serde(flatten)]
    pub additional_context: HashMap<String, serde_json::Value>,
}

/// Client for Retrohunt operations
pub struct RetrohuntClient<'a> {
    pub(crate) client: &'a Client,
}

impl<'a> RetrohuntClient<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// List Retrohunt jobs
    ///
    /// Accepted filters:
    /// - status:(starting|running|aborting|aborted|finished)
    pub async fn list_jobs(
        &self,
        filter: Option<&str>,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<RetrohuntJob>> {
        let mut url = String::from("intelligence/retrohunt_jobs?");

        if let Some(f) = filter {
            url.push_str(&format!("filter={}&", urlencoding::encode(f)));
        }

        if let Some(l) = limit {
            url.push_str(&format!("limit={}&", l));
        }

        if let Some(c) = cursor {
            url.push_str(&format!("cursor={}&", urlencoding::encode(c)));
        }

        // Remove trailing '&' or '?'
        url.pop();

        self.client.get(&url).await
    }

    /// List jobs with pagination support
    pub fn list_jobs_iterator(&self, filter: Option<&str>) -> CollectionIterator<'_, RetrohuntJob> {
        let mut url = String::from("intelligence/retrohunt_jobs?");

        if let Some(f) = filter {
            url.push_str(&format!("filter={}&", urlencoding::encode(f)));
        }

        // Remove trailing '&' or '?'
        url.pop();

        CollectionIterator::new(self.client, url)
    }

    /// Create a new Retrohunt job
    ///
    /// Limits:
    /// - Maximum 10 concurrent jobs per user
    /// - Maximum 300 YARA rules per job
    /// - Scan range: 90 days (up to 365 for privileged users)
    pub async fn create_job(&self, request: &CreateRetrohuntJobRequest) -> Result<RetrohuntJob> {
        self.client
            .post("intelligence/retrohunt_jobs", request)
            .await
    }

    /// Get a Retrohunt job by ID
    pub async fn get_job(&self, job_id: &str) -> Result<RetrohuntJob> {
        let url = format!(
            "intelligence/retrohunt_jobs/{}",
            urlencoding::encode(job_id)
        );
        self.client.get(&url).await
    }

    /// Delete a Retrohunt job
    pub async fn delete_job(&self, job_id: &str) -> Result<()> {
        let url = format!(
            "intelligence/retrohunt_jobs/{}",
            urlencoding::encode(job_id)
        );
        self.client.delete(&url).await
    }

    /// Abort a running Retrohunt job
    pub async fn abort_job(&self, job_id: &str) -> Result<()> {
        let url = format!(
            "intelligence/retrohunt_jobs/{}/abort",
            urlencoding::encode(job_id)
        );
        // Abort is a POST with no body
        self.client.post(&url, &serde_json::json!({})).await
    }

    /// Retrieve matching files for a Retrohunt job
    pub async fn get_matching_files(
        &self,
        job_id: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<RetrohuntMatchingFile>> {
        let mut url = format!(
            "intelligence/retrohunt_jobs/{}/matching_files?",
            urlencoding::encode(job_id)
        );

        if let Some(l) = limit {
            url.push_str(&format!("limit={}&", l));
        }

        if let Some(c) = cursor {
            url.push_str(&format!("cursor={}&", urlencoding::encode(c)));
        }

        // Remove trailing '&' or '?'
        url.pop();

        self.client.get(&url).await
    }

    /// Get matching files with pagination support
    pub fn get_matching_files_iterator(
        &self,
        job_id: &str,
    ) -> CollectionIterator<'_, RetrohuntMatchingFile> {
        let url = format!(
            "intelligence/retrohunt_jobs/{}/matching_files",
            urlencoding::encode(job_id)
        );

        CollectionIterator::new(self.client, url)
    }

    /// Wait for a job to complete
    ///
    /// Polls the job status until it's finished, aborted, or an error occurs.
    /// Returns the final job status.
    pub async fn wait_for_completion(
        &self,
        job_id: &str,
        max_wait_seconds: Option<u64>,
        poll_interval_seconds: Option<u64>,
    ) -> Result<RetrohuntJob> {
        let max_wait = max_wait_seconds.unwrap_or(3600); // Default 1 hour
        let poll_interval = poll_interval_seconds.unwrap_or(10); // Poll every 10 seconds
        let max_iterations = max_wait / poll_interval;

        for _ in 0..max_iterations {
            let job = self.get_job(job_id).await?;

            if let Some(ref status) = job.object.attributes.status {
                match status {
                    JobStatus::Finished | JobStatus::Aborted => return Ok(job),
                    JobStatus::Starting | JobStatus::Running | JobStatus::Aborting => {
                        // Still processing, wait before next poll
                        tokio::time::sleep(tokio::time::Duration::from_secs(poll_interval)).await;
                    }
                }
            }
        }

        Err(crate::Error::Unknown(
            "Timeout waiting for Retrohunt job completion".to_string(),
        ))
    }
}

/// Helper methods for creating Retrohunt jobs
impl CreateRetrohuntJobRequest {
    /// Create a new Retrohunt job request with rules
    pub fn new(rules: String) -> Self {
        Self {
            data: CreateRetrohuntJobData {
                object_type: "retrohunt_job".to_string(),
                attributes: CreateRetrohuntJobAttributes {
                    rules,
                    notification_email: None,
                    corpus: None,
                    time_range: None,
                },
            },
        }
    }

    /// Set notification email
    pub fn with_notification_email(mut self, email: String) -> Self {
        self.data.attributes.notification_email = Some(email);
        self
    }

    /// Set corpus to scan
    pub fn with_corpus(mut self, corpus: Corpus) -> Self {
        self.data.attributes.corpus = Some(corpus.to_string().to_owned());
        self
    }

    /// Set time range for scanning
    pub fn with_time_range(mut self, start: Option<i64>, end: Option<i64>) -> Self {
        self.data.attributes.time_range = Some(TimeRange { start, end });
        self
    }

    /// Set start time for scanning (scan from this time onwards)
    pub fn with_start_time(mut self, start: i64) -> Self {
        if let Some(ref mut time_range) = self.data.attributes.time_range {
            time_range.start = Some(start);
        } else {
            self.data.attributes.time_range = Some(TimeRange {
                start: Some(start),
                end: None,
            });
        }
        self
    }

    /// Set end time for scanning (scan up to this time)
    pub fn with_end_time(mut self, end: i64) -> Self {
        if let Some(ref mut time_range) = self.data.attributes.time_range {
            time_range.end = Some(end);
        } else {
            self.data.attributes.time_range = Some(TimeRange {
                start: None,
                end: Some(end),
            });
        }
        self
    }
}

impl Client {
    /// Get the Retrohunt client
    pub fn retrohunt(&self) -> RetrohuntClient<'_> {
        RetrohuntClient::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retrohunt_job_attributes() {
        let attrs = RetrohuntJobAttributes {
            rules: Some("rule test { condition: true }".to_string()),
            notification_email: Some("test@example.com".to_string()),
            corpus: Some("main".to_string()),
            status: Some(JobStatus::Running),
            scanned_files: Some(1000),
            matches: Some(10),
            progress: Some(50),
            ..Default::default()
        };

        assert_eq!(attrs.rules.unwrap(), "rule test { condition: true }");
        assert_eq!(attrs.notification_email.unwrap(), "test@example.com");
        assert_eq!(attrs.corpus.unwrap(), "main");
        assert_eq!(attrs.status.unwrap(), JobStatus::Running);
        assert_eq!(attrs.progress.unwrap(), 50);
    }

    #[test]
    fn test_job_status() {
        let statuses = vec![
            JobStatus::Starting,
            JobStatus::Running,
            JobStatus::Aborting,
            JobStatus::Aborted,
            JobStatus::Finished,
        ];

        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let deserialized: JobStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, deserialized);
        }
    }

    #[test]
    fn test_corpus_strings() {
        assert_eq!(Corpus::Main.to_string(), "main");
        assert_eq!(Corpus::Goodware.to_string(), "goodware");
    }

    #[test]
    fn test_create_retrohunt_job_request() {
        let request = CreateRetrohuntJobRequest::new(
            "rule example { strings: $ = \"test\" condition: all of them }".to_string(),
        )
        .with_notification_email("notify@example.com".to_string())
        .with_corpus(Corpus::Main)
        .with_time_range(Some(1609459200), Some(1640995200));

        assert!(request.data.attributes.rules.contains("rule example"));
        assert_eq!(
            request.data.attributes.notification_email.unwrap(),
            "notify@example.com"
        );
        assert_eq!(request.data.attributes.corpus.unwrap(), "main");

        let time_range = request.data.attributes.time_range.unwrap();
        assert_eq!(time_range.start.unwrap(), 1609459200);
        assert_eq!(time_range.end.unwrap(), 1640995200);
    }

    #[test]
    fn test_time_range() {
        let time_range = TimeRange {
            start: Some(1609459200), // 2021-01-01
            end: Some(1640995200),   // 2022-01-01
        };

        assert_eq!(time_range.start.unwrap(), 1609459200);
        assert_eq!(time_range.end.unwrap(), 1640995200);
    }

    #[test]
    fn test_matching_file_context() {
        let context = MatchingFileContext {
            rule_name: Some("TestRule".to_string()),
            match_offset: Some(1024),
            match_snippet: Some("4D 5A 90 00".to_string()),
            match_in_subfile: Some(false),
            additional_context: HashMap::new(),
        };

        assert_eq!(context.rule_name.unwrap(), "TestRule");
        assert_eq!(context.match_offset.unwrap(), 1024);
        assert_eq!(context.match_snippet.unwrap(), "4D 5A 90 00");
        assert_eq!(context.match_in_subfile.unwrap(), false);
    }

    #[test]
    fn test_create_job_with_builders() {
        let request = CreateRetrohuntJobRequest::new("rule test { condition: true }".to_string())
            .with_start_time(1609459200)
            .with_end_time(1640995200);

        let time_range = request.data.attributes.time_range.unwrap();
        assert_eq!(time_range.start.unwrap(), 1609459200);
        assert_eq!(time_range.end.unwrap(), 1640995200);
    }

    #[test]
    fn test_job_progress() {
        let attrs = RetrohuntJobAttributes {
            status: Some(JobStatus::Running),
            progress: Some(75),
            eta: Some(300), // 5 minutes
            scanned_files: Some(750000),
            matches: Some(25),
            ..Default::default()
        };

        assert_eq!(attrs.status.unwrap(), JobStatus::Running);
        assert_eq!(attrs.progress.unwrap(), 75);
        assert_eq!(attrs.eta.unwrap(), 300);
        assert_eq!(attrs.scanned_files.unwrap(), 750000);
        assert_eq!(attrs.matches.unwrap(), 25);
    }
}
