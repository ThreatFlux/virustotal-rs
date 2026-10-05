//! Current analysis payloads and finite, cancelable analysis polling.

use crate::analysis::{Analysis, AnalysisAttributes};
use crate::objects::{ObjectDescriptor, ObjectResponse};
use crate::url_utils::Endpoints;
use crate::{Client, Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::time::Duration;

/// An analysis with nullable engine verdicts and retained extension attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    #[serde(rename = "type")]
    pub object_type: String,
    pub id: String,
    pub attributes: AnalysisReportAttributes,
    #[serde(flatten)]
    pub additional_fields: HashMap<String, Value>,
}

/// Current analysis attributes. Unknown status strings are preserved.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisReportAttributes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<HashMap<String, u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub results: Option<HashMap<String, AnalysisEngineResult>>,
    #[serde(flatten)]
    pub additional_attributes: HashMap<String, Value>,
}

/// One engine's result. `None` represents an absent or null verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisEngineResult {
    pub category: String,
    pub engine_name: String,
    pub method: String,
    pub result: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_update: Option<String>,
    #[serde(flatten)]
    pub additional_attributes: HashMap<String, Value>,
}

impl AnalysisReport {
    /// Only the provider's explicit `completed` state is terminal success.
    pub fn is_completed(&self) -> bool {
        self.attributes.status.as_deref() == Some("completed")
    }
}

/// Positive limits for polling an already submitted analysis.
#[derive(Debug, Clone, Copy)]
pub struct AnalysisPollOptions {
    interval: Duration,
    timeout: Duration,
    max_attempts: NonZeroU32,
}

impl AnalysisPollOptions {
    /// Reject zero durations and attempts before any HTTP request is sent.
    pub fn new(interval: Duration, timeout: Duration, max_attempts: u32) -> Result<Self> {
        if interval.is_zero() || timeout.is_zero() {
            return Err(Error::invalid_argument(
                "Polling durations must be positive",
            ));
        }
        let max_attempts = NonZeroU32::new(max_attempts)
            .ok_or_else(|| Error::invalid_argument("Polling attempts must be positive"))?;
        Ok(Self {
            interval,
            timeout,
            max_attempts,
        })
    }
}

impl Default for AnalysisPollOptions {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(15),
            timeout: Duration::from_secs(300),
            max_attempts: NonZeroU32::new(20).expect("20 is positive"),
        }
    }
}

/// Public file/URL analyses. Private scanning uses separate private endpoints.
pub struct AnalysisClient<'a> {
    client: &'a Client,
}

impl<'a> AnalysisClient<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// Retrieve the legacy model. Prefer [`Self::get_report`] for null verdicts.
    pub async fn get(&self, analysis_id: &str) -> Result<Analysis> {
        let endpoint = Endpoints::analysis(analysis_id).build();
        let response: ObjectResponse<AnalysisAttributes> = self.client.get(&endpoint).await?;
        Ok(Analysis {
            object: response.data,
        })
    }

    /// Retrieve a current analysis, retaining unknown object and engine fields.
    pub async fn get_report(&self, analysis_id: &str) -> Result<AnalysisReport> {
        let endpoint = Endpoints::analysis(analysis_id).build();
        let response: DataResponse<AnalysisReport> = self.client.get(&endpoint).await?;
        if response.data.object_type != "analysis" {
            return Err(Error::bad_request("Expected an analysis response object"));
        }
        Ok(response.data)
    }

    /// Fetch the single file or URL being analysed, with caller-selected typing.
    pub async fn get_item<T: serde::de::DeserializeOwned>(&self, analysis_id: &str) -> Result<T> {
        let endpoint = Endpoints::analysis(analysis_id).raw_segment("item").build();
        let response: DataResponse<T> = self.client.get(&endpoint).await?;
        Ok(response.data)
    }

    /// Retrieve the analysed item's descriptor rather than its full attributes.
    pub async fn get_item_descriptor(&self, analysis_id: &str) -> Result<ObjectDescriptor> {
        let endpoint = Endpoints::analysis(analysis_id)
            .raw_segment("relationships")
            .raw_segment("item")
            .build();
        let response: DataResponse<ObjectDescriptor> = self.client.get(&endpoint).await?;
        Ok(response.data)
    }

    /// Poll reads until explicitly completed, an API error, or either limit.
    ///
    /// The deadline includes requests and local rate-limit waits. Dropping this
    /// future cancels polling; it spawns no background task and submits no scans.
    /// Pending and future status strings are never returned as completed output.
    pub async fn wait_for_completion(
        &self,
        analysis_id: &str,
        options: AnalysisPollOptions,
    ) -> Result<AnalysisReport> {
        tokio::time::timeout(options.timeout, async {
            for attempt in 0..options.max_attempts.get() {
                let report = self.get_report(analysis_id).await?;
                if report.is_completed() {
                    return Ok(report);
                }
                if attempt + 1 < options.max_attempts.get() {
                    tokio::time::sleep(options.interval).await;
                }
            }
            Err(Error::DeadlineExceeded)
        })
        .await
        .map_err(|_| Error::DeadlineExceeded)?
    }
}

#[derive(Deserialize)]
struct DataResponse<T> {
    data: T,
}

impl Client {
    /// Access public file and URL analysis resources.
    pub fn analyses(&self) -> AnalysisClient<'_> {
        AnalysisClient::new(self)
    }
}
