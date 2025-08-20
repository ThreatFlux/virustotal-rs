use crate::client::Client;
use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Client for VirusTotal Intelligence Feeds (File, Domain, IP, URL, and Sandbox Analyses)
///
/// NOTE: Each feed type requires its specific license:
/// - File feeds: File feeds license
/// - Domain feeds: Domain feeds license  
/// - IP feeds: IP feeds license
/// - URL feeds: URL feeds license
/// - Sandbox analyses feeds: Sandbox feeds license
pub struct FeedsClient {
    client: Client,
}

impl FeedsClient {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Get a per-minute file feed batch
    ///
    /// Downloads an individual one-minute batch by providing a time in format YYYYMMDDhhmm.
    ///
    /// # Arguments
    /// * `time` - Time string in format YYYYMMDDhhmm (e.g., "202312010802" for Dec 1, 2023 08:02 UTC)
    ///
    /// # Notes
    /// - You can download batches up to 7 days old
    /// - The most recent batch has a 60 minutes lag from current time
    /// - Returns a redirect (302) to the download URL
    /// - The downloaded file is a bzip2 compressed UTF-8 text file with one JSON per line
    ///
    /// # Errors
    /// - 404 errors may occur for missing batches (rare but normal)
    /// - Multiple consecutive 404s should be treated as an error condition
    ///
    /// # Example
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = virustotal_rs::Client::new("your_api_key".into(), virustotal_rs::ApiTier::Public)?;
    /// # let feeds_client = client.feeds();
    /// let batch = feeds_client.get_file_feed_batch("202312010802").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_file_feed_batch(&self, time: &str) -> Result<Vec<u8>> {
        let endpoint = format!("feeds/files/{}", time);
        // This endpoint returns a redirect, so we get the raw bytes
        self.client.get_bytes(&endpoint).await
    }

    /// Get an hourly file feed batch
    ///
    /// Returns a single package containing all minutely packages for a given hour.
    ///
    /// # Arguments
    /// * `time` - Time string in format YYYYMMDDhh (e.g., "2023120108" for Dec 1, 2023 08:00-08:59 UTC)
    ///
    /// # Notes
    /// - Returns a .tar.bz2 file containing 60 minutely feeds
    /// - You can download batches up to 7 days old
    /// - The most recent batch has a 2 hours lag from current time
    /// - Each minute file is UTF-8 text with one JSON per line
    ///
    /// # Example
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = virustotal_rs::Client::new("your_api_key".into(), virustotal_rs::ApiTier::Public)?;
    /// # let feeds_client = client.feeds();
    /// let hourly_batch = feeds_client.get_hourly_file_feed_batch("2023120108").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_hourly_file_feed_batch(&self, time: &str) -> Result<Vec<u8>> {
        let endpoint = format!("feeds/files/hourly/{}", time);
        self.client.get_bytes(&endpoint).await
    }

    /// Download a file published in the file feed
    ///
    /// Downloads a specific file using the token from the feed.
    ///
    /// # Arguments
    /// * `token` - Download token found in the file's properties in the feed
    ///
    /// # Notes
    /// - Requires download file privilege in addition to File feeds license
    /// - Links are only valid for 7 days (feed's lifetime)
    /// - The token is found in the `download_url` attribute of feed items
    ///
    /// # Example
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = virustotal_rs::Client::new("your_api_key".into(), virustotal_rs::ApiTier::Public)?;
    /// # let feeds_client = client.feeds();
    /// let file_bytes = feeds_client.download_feed_file("abc123token").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn download_feed_file(&self, token: &str) -> Result<Vec<u8>> {
        let endpoint = format!("feeds/files/{}/download", token);
        self.client.get_bytes(&endpoint).await
    }

    /// Get a per-minute file behaviour feed batch
    ///
    /// Downloads an individual one-minute batch of sandbox behavior reports.
    ///
    /// # Arguments
    /// * `time` - Time string in format YYYYMMDDhhmm
    ///
    /// # Notes
    /// - Requires Sandbox feeds license
    /// - Returns bzip2 compressed UTF-8 text with one JSON per line
    /// - Each line contains a FileBehaviour object with context_attributes
    /// - context_attributes include links to download artifacts (PCAP, HTML, EVTX, memdump)
    pub async fn get_file_behaviour_feed_batch(&self, time: &str) -> Result<Vec<u8>> {
        let endpoint = format!("feeds/file_behaviours/{}", time);
        self.client.get_bytes(&endpoint).await
    }

    /// Get an hourly file behaviour feed batch
    ///
    /// Returns a package containing all minutely behavior feed packages for a given hour.
    ///
    /// # Arguments
    /// * `time` - Time string in format YYYYMMDDhh
    ///
    /// # Notes
    /// - Requires Sandbox feeds license
    /// - Returns a .tar.bz2 file containing 60 minutely feeds
    /// - 2-hour lag from current time
    pub async fn get_hourly_file_behaviour_feed_batch(&self, time: &str) -> Result<Vec<u8>> {
        let endpoint = format!("feeds/file_behaviours/hourly/{}", time);
        self.client.get_bytes(&endpoint).await
    }

    /// Download EVTX file from behavior analysis
    ///
    /// Downloads the Windows Event Log (EVTX) file generated during sandbox execution.
    ///
    /// # Arguments
    /// * `token` - Download token from the behavior feed's context_attributes.evtx URL
    ///
    /// # Notes
    /// - Requires Sandbox feeds license
    /// - Token is extracted from feed item's context_attributes.evtx URL
    /// - Links are valid for feed lifetime (7 days)
    pub async fn download_behaviour_evtx(&self, token: &str) -> Result<Vec<u8>> {
        let endpoint = format!("feeds/file_behaviours/{}/evtx", token);
        self.client.get_bytes(&endpoint).await
    }

    /// Download memory dump from behavior analysis
    ///
    /// Downloads the memory dump file generated during sandbox execution.
    ///
    /// # Arguments
    /// * `token` - Download token from the behavior feed's context_attributes.memdump URL
    ///
    /// # Notes
    /// - Requires Sandbox feeds license
    /// - Token is extracted from feed item's context_attributes.memdump URL
    /// - Links are valid for feed lifetime (7 days)
    pub async fn download_behaviour_memdump(&self, token: &str) -> Result<Vec<u8>> {
        let endpoint = format!("feeds/file_behaviours/{}/memdump", token);
        self.client.get_bytes(&endpoint).await
    }

    /// Download PCAP file from behavior analysis
    ///
    /// Downloads the network packet capture (PCAP) file from sandbox execution.
    ///
    /// # Arguments
    /// * `token` - Download token from the behavior feed's context_attributes.pcap URL
    ///
    /// # Notes
    /// - Requires Sandbox feeds license
    /// - Token is extracted from feed item's context_attributes.pcap URL
    /// - Links are valid for feed lifetime (7 days)
    pub async fn download_behaviour_pcap(&self, token: &str) -> Result<Vec<u8>> {
        let endpoint = format!("feeds/file_behaviours/{}/pcap", token);
        self.client.get_bytes(&endpoint).await
    }

    /// Download HTML report from behavior analysis
    ///
    /// Downloads the detailed HTML report of the sandbox execution.
    ///
    /// # Arguments
    /// * `token` - Download token from the behavior feed's context_attributes.html_report URL
    ///
    /// # Notes
    /// - Requires Sandbox feeds license
    /// - Token is extracted from feed item's context_attributes.html_report URL
    /// - Links are valid for feed lifetime (7 days)
    pub async fn download_behaviour_html(&self, token: &str) -> Result<Vec<u8>> {
        let endpoint = format!("feeds/file_behaviours/{}/html", token);
        self.client.get_bytes(&endpoint).await
    }

    /// Legacy method - redirects to get_file_behaviour_feed_batch
    #[deprecated(since = "0.2.0", note = "Use get_file_behaviour_feed_batch instead")]
    pub async fn get_sandbox_feed_batch(&self, time: &str) -> Result<Vec<u8>> {
        self.get_file_behaviour_feed_batch(time).await
    }

    /// Legacy method - redirects to get_hourly_file_behaviour_feed_batch
    #[deprecated(
        since = "0.2.0",
        note = "Use get_hourly_file_behaviour_feed_batch instead"
    )]
    pub async fn get_hourly_sandbox_feed_batch(&self, time: &str) -> Result<Vec<u8>> {
        self.get_hourly_file_behaviour_feed_batch(time).await
    }

    // ========== Domain Intelligence Feed ==========

    /// Get a per-minute domain feed batch
    ///
    /// Downloads an individual one-minute batch of domain analyses.
    ///
    /// # Arguments
    /// * `time` - Time string in format YYYYMMDDhhmm (e.g., "202312010802")
    ///
    /// # Notes
    /// - Requires Domain feeds license
    /// - Returns bzip2 compressed UTF-8 text with one JSON per line
    /// - Each line contains a Domain object as returned by GET /domains/{domain}
    /// - 60-minute lag from current time, 7-day retention
    ///
    /// # Example
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = virustotal_rs::Client::new("your_api_key".into(), virustotal_rs::ApiTier::Public)?;
    /// # let feeds_client = client.feeds();
    /// let batch = feeds_client.get_domain_feed_batch("202312010802").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_domain_feed_batch(&self, time: &str) -> Result<Vec<u8>> {
        let endpoint = format!("feeds/domains/{}", time);
        self.client.get_bytes(&endpoint).await
    }

    /// Get an hourly domain feed batch
    ///
    /// Returns a single package containing all minutely domain feed packages for a given hour.
    ///
    /// # Arguments
    /// * `time` - Time string in format YYYYMMDDhh (e.g., "2023120108")
    ///
    /// # Notes
    /// - Requires Domain feeds license
    /// - Returns a .tar.bz2 file containing 60 minutely feeds
    /// - 2-hour lag from current time, 7-day retention
    ///
    /// # Example
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = virustotal_rs::Client::new("your_api_key".into(), virustotal_rs::ApiTier::Public)?;
    /// # let feeds_client = client.feeds();
    /// let hourly_batch = feeds_client.get_hourly_domain_feed_batch("2023120108").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_hourly_domain_feed_batch(&self, time: &str) -> Result<Vec<u8>> {
        let endpoint = format!("feeds/domains/hourly/{}", time);
        self.client.get_bytes(&endpoint).await
    }

    // ========== IP Intelligence Feed ==========

    /// Get a per-minute IP address feed batch
    ///
    /// Downloads an individual one-minute batch of IP address analyses.
    ///
    /// # Arguments
    /// * `time` - Time string in format YYYYMMDDhhmm (e.g., "202312010802")
    ///
    /// # Notes
    /// - Requires IP feeds license
    /// - Returns bzip2 compressed UTF-8 text with one JSON per line
    /// - Each line contains an IP address object as returned by GET /ip_addresses/{ip}
    /// - 60-minute lag from current time, 7-day retention
    ///
    /// # Example
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = virustotal_rs::Client::new("your_api_key".into(), virustotal_rs::ApiTier::Public)?;
    /// # let feeds_client = client.feeds();
    /// let batch = feeds_client.get_ip_feed_batch("202312010802").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_ip_feed_batch(&self, time: &str) -> Result<Vec<u8>> {
        let endpoint = format!("feeds/ip_addresses/{}", time);
        self.client.get_bytes(&endpoint).await
    }

    /// Get an hourly IP address feed batch
    ///
    /// Returns a single package containing all minutely IP feed packages for a given hour.
    ///
    /// # Arguments
    /// * `time` - Time string in format YYYYMMDDhh (e.g., "2023120108")
    ///
    /// # Notes
    /// - Requires IP feeds license
    /// - Returns a .tar.bz2 file containing 60 minutely feeds
    /// - 2-hour lag from current time, 7-day retention
    ///
    /// # Example
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = virustotal_rs::Client::new("your_api_key".into(), virustotal_rs::ApiTier::Public)?;
    /// # let feeds_client = client.feeds();
    /// let hourly_batch = feeds_client.get_hourly_ip_feed_batch("2023120108").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_hourly_ip_feed_batch(&self, time: &str) -> Result<Vec<u8>> {
        let endpoint = format!("feeds/ip_addresses/hourly/{}", time);
        self.client.get_bytes(&endpoint).await
    }

    // ========== URL Intelligence Feed ==========

    /// Get a per-minute URL feed batch
    ///
    /// Downloads an individual one-minute batch of URL analyses.
    ///
    /// # Arguments
    /// * `time` - Time string in format YYYYMMDDhhmm (e.g., "202312010802")
    ///
    /// # Notes
    /// - Requires URL feeds license
    /// - Returns bzip2 compressed UTF-8 text with one JSON per line
    /// - Each line contains a URL object as returned by GET /urls/{id}
    /// - Includes additional context attribute: submitter (lossy-ciphered, non-identifiable)
    /// - 60-minute lag from current time, 7-day retention
    ///
    /// # Example
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = virustotal_rs::Client::new("your_api_key".into(), virustotal_rs::ApiTier::Public)?;
    /// # let feeds_client = client.feeds();
    /// let batch = feeds_client.get_url_feed_batch("202312010802").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_url_feed_batch(&self, time: &str) -> Result<Vec<u8>> {
        let endpoint = format!("feeds/urls/{}", time);
        self.client.get_bytes(&endpoint).await
    }

    /// Get an hourly URL feed batch
    ///
    /// Returns a single package containing all minutely URL feed packages for a given hour.
    ///
    /// # Arguments
    /// * `time` - Time string in format YYYYMMDDhh (e.g., "2023120108")
    ///
    /// # Notes
    /// - Requires URL feeds license
    /// - Returns a .tar.bz2 file containing 60 minutely feeds
    /// - 2-hour lag from current time, 7-day retention
    ///
    /// # Example
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = virustotal_rs::Client::new("your_api_key".into(), virustotal_rs::ApiTier::Public)?;
    /// # let feeds_client = client.feeds();
    /// let hourly_batch = feeds_client.get_hourly_url_feed_batch("2023120108").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_hourly_url_feed_batch(&self, time: &str) -> Result<Vec<u8>> {
        let endpoint = format!("feeds/urls/hourly/{}", time);
        self.client.get_bytes(&endpoint).await
    }

    /// Parse a feed batch line into a FeedItem
    ///
    /// Feed batches contain one JSON object per line. This method helps parse
    /// individual lines from the decompressed feed data.
    ///
    /// # Example
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = virustotal_rs::Client::new("your_api_key".into(), virustotal_rs::ApiTier::Public)?;
    /// # let feeds_client = client.feeds();
    /// # let decompressed_data = "sample data";
    /// let batch_data = feeds_client.get_file_feed_batch("202312010802").await?;
    /// // After decompressing the bzip2 data...
    /// for line in decompressed_data.lines() {
    ///     if let Ok(item) = feeds_client.parse_feed_line(line) {
    ///         println!("File: {}", item.id);
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn parse_feed_line(&self, line: &str) -> Result<FeedItem> {
        serde_json::from_str(line).map_err(crate::Error::Json)
    }

    /// Parse a behavior feed batch line into a BehaviorFeedItem
    ///
    /// Behavior feed batches contain one JSON object per line with sandbox analysis results.
    ///
    /// # Example
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = virustotal_rs::Client::new("your_api_key".into(), virustotal_rs::ApiTier::Public)?;
    /// # let feeds_client = client.feeds();
    /// # let decompressed_data = "sample data";
    /// # use virustotal_rs::feeds::BehaviorFeedItem;
    /// let batch_data = feeds_client.get_file_behaviour_feed_batch("202312010802").await?;
    /// // After decompressing the bzip2 data...
    /// for line in decompressed_data.lines() {
    ///     if let Ok(item) = feeds_client.parse_behaviour_feed_line(line) {
    ///         println!("Behavior: {}", item.id);
    ///         if let Some(evtx_url) = &item.context_attributes.evtx {
    ///             if let Some(token) = BehaviorFeedItem::extract_token(evtx_url) {
    ///                 let evtx_data = feeds_client.download_behaviour_evtx(&token).await?;
    ///             }
    ///         }
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn parse_behaviour_feed_line(&self, line: &str) -> Result<BehaviorFeedItem> {
        serde_json::from_str(line).map_err(crate::Error::Json)
    }

    /// Parse a domain feed batch line into a DomainFeedItem
    ///
    /// Domain feed batches contain one JSON object per line with domain analyses.
    ///
    /// # Example
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = virustotal_rs::Client::new("your_api_key".into(), virustotal_rs::ApiTier::Public)?;
    /// # let feeds_client = client.feeds();
    /// # let decompressed_data = "sample data";
    /// let batch_data = feeds_client.get_domain_feed_batch("202312010802").await?;
    /// // After decompressing the bzip2 data...
    /// for line in decompressed_data.lines() {
    ///     if let Ok(item) = feeds_client.parse_domain_feed_line(line) {
    ///         println!("Domain: {}", item.id);
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn parse_domain_feed_line(&self, line: &str) -> Result<DomainFeedItem> {
        serde_json::from_str(line).map_err(crate::Error::Json)
    }

    /// Parse an IP feed batch line into an IpFeedItem
    ///
    /// IP feed batches contain one JSON object per line with IP address analyses.
    ///
    /// # Example
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = virustotal_rs::Client::new("your_api_key".into(), virustotal_rs::ApiTier::Public)?;
    /// # let feeds_client = client.feeds();
    /// # let decompressed_data = "sample data";
    /// let batch_data = feeds_client.get_ip_feed_batch("202312010802").await?;
    /// // After decompressing the bzip2 data...
    /// for line in decompressed_data.lines() {
    ///     if let Ok(item) = feeds_client.parse_ip_feed_line(line) {
    ///         println!("IP: {}", item.id);
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn parse_ip_feed_line(&self, line: &str) -> Result<IpFeedItem> {
        serde_json::from_str(line).map_err(crate::Error::Json)
    }

    /// Parse a URL feed batch line into a UrlFeedItem
    ///
    /// URL feed batches contain one JSON object per line with URL analyses.
    ///
    /// # Example
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = virustotal_rs::Client::new("your_api_key".into(), virustotal_rs::ApiTier::Public)?;
    /// # let feeds_client = client.feeds();
    /// # let decompressed_data = "sample data";
    /// let batch_data = feeds_client.get_url_feed_batch("202312010802").await?;
    /// // After decompressing the bzip2 data...
    /// for line in decompressed_data.lines() {
    ///     if let Ok(item) = feeds_client.parse_url_feed_line(line) {
    ///         println!("URL: {}", item.id);
    ///         if let Some(submitter) = &item.submitter {
    ///             println!("  Submitted from: {:?}", submitter.country);
    ///         }
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn parse_url_feed_line(&self, line: &str) -> Result<UrlFeedItem> {
        serde_json::from_str(line).map_err(crate::Error::Json)
    }

    /// Helper to generate time strings for feed requests
    ///
    /// # Examples
    /// ```
    /// # use virustotal_rs::feeds::FeedsClient;
    /// // For per-minute feed: "202312010802"
    /// let minute_time = FeedsClient::format_time(2023, 12, 1, 8, Some(2));
    ///
    /// // For hourly feed: "2023120108"
    /// let hour_time = FeedsClient::format_time(2023, 12, 1, 8, None);
    /// ```
    pub fn format_time(year: u32, month: u32, day: u32, hour: u32, minute: Option<u32>) -> String {
        match minute {
            Some(m) => format!("{:04}{:02}{:02}{:02}{:02}", year, month, day, hour, m),
            None => format!("{:04}{:02}{:02}{:02}", year, month, day, hour),
        }
    }

    /// Calculate the latest available feed time
    ///
    /// Returns the latest time for which feeds should be available,
    /// accounting for the required lag (60 minutes for per-minute, 2 hours for hourly).
    ///
    /// # Arguments
    /// * `is_hourly` - true for hourly feeds (2h lag), false for per-minute (60m lag)
    pub fn get_latest_available_time(is_hourly: bool) -> String {
        use chrono::{Datelike, Duration, Timelike, Utc};

        let now = Utc::now();
        let lag = if is_hourly {
            Duration::hours(2)
        } else {
            Duration::hours(1)
        };

        let available_time = now - lag;

        if is_hourly {
            format!(
                "{:04}{:02}{:02}{:02}",
                available_time.year(),
                available_time.month(),
                available_time.day(),
                available_time.hour()
            )
        } else {
            format!(
                "{:04}{:02}{:02}{:02}{:02}",
                available_time.year(),
                available_time.month(),
                available_time.day(),
                available_time.hour(),
                available_time.minute()
            )
        }
    }

    /// Get feed times for a date range
    ///
    /// Generates a list of feed times for batch downloading.
    ///
    /// # Arguments
    /// * `start_time` - Start time in format YYYYMMDDhhmm or YYYYMMDDhh
    /// * `end_time` - End time in same format as start_time
    /// * `is_hourly` - true for hourly increments, false for per-minute
    ///
    /// # Returns
    /// Vector of time strings for feed requests
    pub fn get_time_range(start_time: &str, end_time: &str, is_hourly: bool) -> Vec<String> {
        use chrono::{DateTime, Datelike, Duration, NaiveDateTime, Timelike, Utc};

        let mut times = Vec::new();

        // Parse start and end times
        let _format_str = if is_hourly { "%Y%m%d%H" } else { "%Y%m%d%H%M" };

        // For hourly, add dummy minutes/seconds; for per-minute, add dummy seconds
        let (start_str, end_str) = if is_hourly {
            (format!("{}0000", start_time), format!("{}0000", end_time))
        } else {
            (format!("{}00", start_time), format!("{}00", end_time))
        };

        let full_format = "%Y%m%d%H%M%S";
        let start = NaiveDateTime::parse_from_str(&start_str, full_format);
        let end = NaiveDateTime::parse_from_str(&end_str, full_format);

        if let (Ok(start_dt), Ok(end_dt)) = (start, end) {
            let increment = if is_hourly {
                Duration::hours(1)
            } else {
                Duration::minutes(1)
            };

            let mut current = DateTime::<Utc>::from_naive_utc_and_offset(start_dt, Utc);
            let end = DateTime::<Utc>::from_naive_utc_and_offset(end_dt, Utc);

            while current <= end {
                let time_str = if is_hourly {
                    format!(
                        "{:04}{:02}{:02}{:02}",
                        current.year(),
                        current.month(),
                        current.day(),
                        current.hour()
                    )
                } else {
                    format!(
                        "{:04}{:02}{:02}{:02}{:02}",
                        current.year(),
                        current.month(),
                        current.day(),
                        current.hour(),
                        current.minute()
                    )
                };
                times.push(time_str);
                current += increment;
            }
        }

        times
    }
}

/// Represents an item from a file or sandbox feed
///
/// This is a simplified representation. The actual feed items contain
/// all file object attributes plus additional context attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedItem {
    /// File or sandbox report ID
    pub id: String,

    /// Object type
    #[serde(rename = "type")]
    pub object_type: String,

    /// File attributes (same as GET /files/{id} response)
    pub attributes: HashMap<String, serde_json::Value>,

    /// Download URL for the file (file feed only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_url: Option<String>,

    /// Submitter information (lossy-ciphered, non-identifiable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub submitter: Option<FeedSubmitter>,

    /// Additional context attributes
    #[serde(flatten)]
    pub context: HashMap<String, serde_json::Value>,
}

/// Submitter information in feed items
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedSubmitter {
    /// Country of submission
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,

    /// Submission method
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    /// Additional submitter attributes
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

/// Represents a behavior feed item
///
/// This structure represents a line from the file behaviour feed,
/// containing sandbox analysis results with artifact download links.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorFeedItem {
    /// Behavior ID (SHA256_SandboxName format)
    pub id: String,

    /// Object type (always "file_behaviour")
    #[serde(rename = "type")]
    pub object_type: String,

    /// FileBehaviour object attributes
    pub attributes: HashMap<String, serde_json::Value>,

    /// Context attributes with download links
    pub context_attributes: BehaviorContextAttributes,

    /// Relationships
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationships: Option<HashMap<String, serde_json::Value>>,

    /// Links
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<HashMap<String, serde_json::Value>>,
}

/// Context attributes for behavior feed items
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorContextAttributes {
    /// File MD5 hash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_md5: Option<String>,

    /// File SHA1 hash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_sha1: Option<String>,

    /// File type tag
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_type_tag: Option<String>,

    /// HTML report download URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub html_report: Option<String>,

    /// PCAP file download URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pcap: Option<String>,

    /// EVTX file download URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evtx: Option<String>,

    /// Memory dump download URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memdump: Option<String>,
}

impl BehaviorFeedItem {
    /// Extract the download token from a URL
    ///
    /// # Example
    /// ```
    /// use virustotal_rs::feeds::BehaviorFeedItem;
    /// let url = "https://www.virustotal.com/api/v3/feeds/file_behaviours/TOKEN123/evtx";
    /// let token = BehaviorFeedItem::extract_token(url);
    /// assert_eq!(token, Some("TOKEN123".to_string()));
    /// ```
    pub fn extract_token(url: &str) -> Option<String> {
        // Look for the pattern /file_behaviours/<TOKEN>/<artifact>
        if let Some(idx) = url.find("/file_behaviours/") {
            let after_prefix = &url[idx + 17..]; // Skip "/file_behaviours/"
            let parts: Vec<&str> = after_prefix.split('/').collect();
            if parts.len() >= 2 && !parts[0].is_empty() {
                return Some(parts[0].to_string());
            }
        }
        None
    }
}

/// Represents a domain feed item
///
/// This structure represents a line from the domain feed,
/// containing domain analysis results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainFeedItem {
    /// Domain name or ID
    pub id: String,

    /// Object type (always "domain")
    #[serde(rename = "type")]
    pub object_type: String,

    /// Domain attributes (same as GET /domains/{domain} response)
    pub attributes: HashMap<String, serde_json::Value>,

    /// Relationships
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationships: Option<HashMap<String, serde_json::Value>>,

    /// Links
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<HashMap<String, serde_json::Value>>,

    /// Additional context attributes
    #[serde(flatten)]
    pub context: HashMap<String, serde_json::Value>,
}

/// Represents an IP address feed item
///
/// This structure represents a line from the IP address feed,
/// containing IP address analysis results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpFeedItem {
    /// IP address
    pub id: String,

    /// Object type (always "ip_address")
    #[serde(rename = "type")]
    pub object_type: String,

    /// IP address attributes (same as GET /ip_addresses/{ip} response)
    pub attributes: HashMap<String, serde_json::Value>,

    /// Relationships
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationships: Option<HashMap<String, serde_json::Value>>,

    /// Links
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<HashMap<String, serde_json::Value>>,

    /// Additional context attributes
    #[serde(flatten)]
    pub context: HashMap<String, serde_json::Value>,
}

/// Represents a URL feed item
///
/// This structure represents a line from the URL feed,
/// containing URL analysis results with submitter information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlFeedItem {
    /// URL identifier
    pub id: String,

    /// Object type (always "url")
    #[serde(rename = "type")]
    pub object_type: String,

    /// URL attributes (same as GET /urls/{id} response)
    pub attributes: HashMap<String, serde_json::Value>,

    /// Submitter information (lossy-ciphered, non-identifiable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub submitter: Option<FeedSubmitter>,

    /// Relationships
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationships: Option<HashMap<String, serde_json::Value>>,

    /// Links
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<HashMap<String, serde_json::Value>>,

    /// Additional context attributes
    #[serde(flatten)]
    pub context: HashMap<String, serde_json::Value>,
}

/// Configuration for feed processing
#[derive(Debug, Clone)]
pub struct FeedConfig {
    /// Maximum number of retries for failed batches
    pub max_retries: u32,

    /// Delay between retries in seconds
    pub retry_delay_secs: u64,

    /// Continue on missing batches (404 errors)
    pub skip_missing: bool,

    /// Maximum consecutive missing batches before stopping
    pub max_consecutive_missing: u32,
}

impl Default for FeedConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            retry_delay_secs: 5,
            skip_missing: true,
            max_consecutive_missing: 10,
        }
    }
}

impl crate::Client {
    /// Get the Feeds client for file intelligence and sandbox feeds
    pub fn feeds(&self) -> FeedsClient {
        FeedsClient::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_time() {
        // Per-minute format
        let minute_time = FeedsClient::format_time(2023, 12, 1, 8, Some(2));
        assert_eq!(minute_time, "202312010802");

        // Hourly format
        let hour_time = FeedsClient::format_time(2023, 12, 1, 8, None);
        assert_eq!(hour_time, "2023120108");
    }

    #[test]
    fn test_time_range_generation() {
        // Test hourly range
        let hourly_range = FeedsClient::get_time_range("2023120108", "2023120110", true);
        assert_eq!(hourly_range.len(), 3);
        assert_eq!(hourly_range[0], "2023120108");
        assert_eq!(hourly_range[1], "2023120109");
        assert_eq!(hourly_range[2], "2023120110");

        // Test per-minute range
        let minute_range = FeedsClient::get_time_range("202312010800", "202312010802", false);
        assert_eq!(minute_range.len(), 3);
        assert_eq!(minute_range[0], "202312010800");
        assert_eq!(minute_range[1], "202312010801");
        assert_eq!(minute_range[2], "202312010802");
    }

    #[test]
    fn test_feed_config_default() {
        let config = FeedConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.retry_delay_secs, 5);
        assert!(config.skip_missing);
        assert_eq!(config.max_consecutive_missing, 10);
    }

    #[test]
    fn test_feed_item_deserialization() {
        let json = r#"{
            "id": "test_file_id",
            "type": "file",
            "attributes": {
                "sha256": "abc123",
                "size": 1024
            },
            "download_url": "https://example.com/download/token123",
            "submitter": {
                "country": "US",
                "method": "api"
            }
        }"#;

        let item: FeedItem = serde_json::from_str(json).unwrap();
        assert_eq!(item.id, "test_file_id");
        assert_eq!(item.object_type, "file");
        assert!(item.download_url.is_some());
        assert!(item.submitter.is_some());

        let submitter = item.submitter.unwrap();
        assert_eq!(submitter.country, Some("US".to_string()));
        assert_eq!(submitter.method, Some("api".to_string()));
    }

    #[tokio::test]
    async fn test_feeds_client_creation() {
        use crate::{ApiTier, ClientBuilder};

        let client = ClientBuilder::new()
            .api_key("test_key")
            .tier(ApiTier::Premium)
            .build()
            .unwrap();

        let feeds = client.feeds();

        // Test that methods exist and return errors without valid API key
        let result = feeds.get_file_feed_batch("202312010802").await;
        assert!(result.is_err());

        let hourly_result = feeds.get_hourly_file_feed_batch("2023120108").await;
        assert!(hourly_result.is_err());

        let download_result = feeds.download_feed_file("test_token").await;
        assert!(download_result.is_err());

        // Test behavior feed methods
        let behaviour_result = feeds.get_file_behaviour_feed_batch("202312010802").await;
        assert!(behaviour_result.is_err());

        let hourly_behaviour = feeds
            .get_hourly_file_behaviour_feed_batch("2023120108")
            .await;
        assert!(hourly_behaviour.is_err());

        // Test artifact downloads
        let evtx_result = feeds.download_behaviour_evtx("test_token").await;
        assert!(evtx_result.is_err());

        let pcap_result = feeds.download_behaviour_pcap("test_token").await;
        assert!(pcap_result.is_err());

        let html_result = feeds.download_behaviour_html("test_token").await;
        assert!(html_result.is_err());

        let memdump_result = feeds.download_behaviour_memdump("test_token").await;
        assert!(memdump_result.is_err());

        // Test domain feed methods
        let domain_result = feeds.get_domain_feed_batch("202312010802").await;
        assert!(domain_result.is_err());

        let hourly_domain = feeds.get_hourly_domain_feed_batch("2023120108").await;
        assert!(hourly_domain.is_err());

        // Test IP feed methods
        let ip_result = feeds.get_ip_feed_batch("202312010802").await;
        assert!(ip_result.is_err());

        let hourly_ip = feeds.get_hourly_ip_feed_batch("2023120108").await;
        assert!(hourly_ip.is_err());

        // Test URL feed methods
        let url_result = feeds.get_url_feed_batch("202312010802").await;
        assert!(url_result.is_err());

        let hourly_url = feeds.get_hourly_url_feed_batch("2023120108").await;
        assert!(hourly_url.is_err());
    }

    #[test]
    fn test_latest_available_time() {
        // Just test that the method runs and returns a string of correct length
        let minute_time = FeedsClient::get_latest_available_time(false);
        assert_eq!(minute_time.len(), 12); // YYYYMMDDhhmm

        let hourly_time = FeedsClient::get_latest_available_time(true);
        assert_eq!(hourly_time.len(), 10); // YYYYMMDDhh
    }

    #[test]
    fn test_parse_feed_line() {
        use crate::{ApiTier, ClientBuilder};

        let client = ClientBuilder::new()
            .api_key("test_key")
            .tier(ApiTier::Premium)
            .build()
            .unwrap();

        let feeds = client.feeds();

        let line = r#"{"id":"test","type":"file","attributes":{"sha256":"abc"}}"#;
        let result = feeds.parse_feed_line(line);
        assert!(result.is_ok());

        let item = result.unwrap();
        assert_eq!(item.id, "test");
        assert_eq!(item.object_type, "file");
    }

    #[test]
    fn test_behavior_feed_item_deserialization() {
        let json = r#"{
            "id": "abc123_cape",
            "type": "file_behaviour",
            "attributes": {
                "sandbox_name": "cape",
                "analysis_date": 1234567890
            },
            "context_attributes": {
                "file_md5": "abc123",
                "file_sha1": "def456",
                "file_type_tag": "exe",
                "html_report": "https://www.virustotal.com/api/v3/feeds/file_behaviours/TOKEN123/html",
                "pcap": "https://www.virustotal.com/api/v3/feeds/file_behaviours/TOKEN123/pcap",
                "evtx": "https://www.virustotal.com/api/v3/feeds/file_behaviours/TOKEN123/evtx",
                "memdump": "https://www.virustotal.com/api/v3/feeds/file_behaviours/TOKEN123/memdump"
            }
        }"#;

        let item: BehaviorFeedItem = serde_json::from_str(json).unwrap();
        assert_eq!(item.id, "abc123_cape");
        assert_eq!(item.object_type, "file_behaviour");
        assert_eq!(item.context_attributes.file_md5, Some("abc123".to_string()));
        assert_eq!(
            item.context_attributes.file_sha1,
            Some("def456".to_string())
        );
        assert_eq!(
            item.context_attributes.file_type_tag,
            Some("exe".to_string())
        );
        assert!(item.context_attributes.html_report.is_some());
        assert!(item.context_attributes.pcap.is_some());
        assert!(item.context_attributes.evtx.is_some());
        assert!(item.context_attributes.memdump.is_some());
    }

    #[test]
    fn test_extract_token() {
        let url = "https://www.virustotal.com/api/v3/feeds/file_behaviours/TOKEN123/evtx";
        let token = BehaviorFeedItem::extract_token(url);
        assert_eq!(token, Some("TOKEN123".to_string()));

        let url2 = "https://www.virustotal.com/api/v3/feeds/file_behaviours/ANOTHER_TOKEN/pcap";
        let token2 = BehaviorFeedItem::extract_token(url2);
        assert_eq!(token2, Some("ANOTHER_TOKEN".to_string()));

        let invalid_url = "https://www.virustotal.com/invalid/url";
        let no_token = BehaviorFeedItem::extract_token(invalid_url);
        assert!(no_token.is_none());
    }

    #[test]
    fn test_parse_behaviour_feed_line() {
        use crate::{ApiTier, ClientBuilder};

        let client = ClientBuilder::new()
            .api_key("test_key")
            .tier(ApiTier::Premium)
            .build()
            .unwrap();

        let feeds = client.feeds();

        let line = r#"{
            "id": "test_behavior",
            "type": "file_behaviour",
            "attributes": {},
            "context_attributes": {
                "file_md5": "md5hash",
                "evtx": "https://www.virustotal.com/api/v3/feeds/file_behaviours/TOKEN/evtx"
            }
        }"#;

        let result = feeds.parse_behaviour_feed_line(line);
        assert!(result.is_ok());

        let item = result.unwrap();
        assert_eq!(item.id, "test_behavior");
        assert_eq!(item.object_type, "file_behaviour");
        assert_eq!(
            item.context_attributes.file_md5,
            Some("md5hash".to_string())
        );

        // Test token extraction from URL
        if let Some(evtx_url) = &item.context_attributes.evtx {
            let token = BehaviorFeedItem::extract_token(evtx_url);
            assert_eq!(token, Some("TOKEN".to_string()));
        }
    }

    #[test]
    fn test_domain_feed_item_deserialization() {
        let json = r#"{
            "id": "example.com",
            "type": "domain",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 2,
                    "suspicious": 1,
                    "undetected": 70,
                    "harmless": 10
                },
                "reputation": 15
            },
            "relationships": {
                "subdomains": {
                    "data": []
                }
            }
        }"#;

        let item: DomainFeedItem = serde_json::from_str(json).unwrap();
        assert_eq!(item.id, "example.com");
        assert_eq!(item.object_type, "domain");
        assert!(item.attributes.contains_key("reputation"));
        assert!(item.relationships.is_some());
    }

    #[test]
    fn test_ip_feed_item_deserialization() {
        let json = r#"{
            "id": "192.168.1.1",
            "type": "ip_address",
            "attributes": {
                "country": "US",
                "as_owner": "Example ISP",
                "reputation": 0,
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 83,
                    "harmless": 0
                }
            }
        }"#;

        let item: IpFeedItem = serde_json::from_str(json).unwrap();
        assert_eq!(item.id, "192.168.1.1");
        assert_eq!(item.object_type, "ip_address");
        assert!(item.attributes.contains_key("country"));
        assert!(item.attributes.contains_key("as_owner"));
    }

    #[test]
    fn test_url_feed_item_deserialization() {
        let json = r#"{
            "id": "https://example.com/path",
            "type": "url",
            "attributes": {
                "last_final_url": "https://example.com/path",
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 83,
                    "harmless": 10
                }
            },
            "submitter": {
                "country": "US",
                "method": "api"
            }
        }"#;

        let item: UrlFeedItem = serde_json::from_str(json).unwrap();
        assert_eq!(item.id, "https://example.com/path");
        assert_eq!(item.object_type, "url");
        assert!(item.attributes.contains_key("last_final_url"));
        assert!(item.submitter.is_some());

        let submitter = item.submitter.unwrap();
        assert_eq!(submitter.country, Some("US".to_string()));
        assert_eq!(submitter.method, Some("api".to_string()));
    }

    #[test]
    fn test_parse_domain_feed_line() {
        use crate::{ApiTier, ClientBuilder};

        let client = ClientBuilder::new()
            .api_key("test_key")
            .tier(ApiTier::Premium)
            .build()
            .unwrap();

        let feeds = client.feeds();

        let line = r#"{"id":"test.com","type":"domain","attributes":{"reputation":10}}"#;

        let result = feeds.parse_domain_feed_line(line);
        assert!(result.is_ok());

        let item = result.unwrap();
        assert_eq!(item.id, "test.com");
        assert_eq!(item.object_type, "domain");
    }

    #[test]
    fn test_parse_ip_feed_line() {
        use crate::{ApiTier, ClientBuilder};

        let client = ClientBuilder::new()
            .api_key("test_key")
            .tier(ApiTier::Premium)
            .build()
            .unwrap();

        let feeds = client.feeds();

        let line = r#"{"id":"10.0.0.1","type":"ip_address","attributes":{"country":"US"}}"#;

        let result = feeds.parse_ip_feed_line(line);
        assert!(result.is_ok());

        let item = result.unwrap();
        assert_eq!(item.id, "10.0.0.1");
        assert_eq!(item.object_type, "ip_address");
    }

    #[test]
    fn test_parse_url_feed_line() {
        use crate::{ApiTier, ClientBuilder};

        let client = ClientBuilder::new()
            .api_key("test_key")
            .tier(ApiTier::Premium)
            .build()
            .unwrap();

        let feeds = client.feeds();

        let line = r#"{"id":"https://test.com","type":"url","attributes":{},"submitter":{"country":"UK"}}"#;

        let result = feeds.parse_url_feed_line(line);
        assert!(result.is_ok());

        let item = result.unwrap();
        assert_eq!(item.id, "https://test.com");
        assert_eq!(item.object_type, "url");
        assert!(item.submitter.is_some());
    }
}
