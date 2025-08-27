use super::types::{BehaviorFeedItem, DomainFeedItem, FeedItem, IpFeedItem, UrlFeedItem};
use super::utilities::{format_time, get_latest_available_time, get_time_range};
use crate::client::Client;
use crate::error::Result;

/// Client for `VirusTotal` Intelligence Feeds (File, Domain, IP, URL, and Sandbox Analyses)
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

    // ========== File Intelligence Feed ==========

    /// Get a per-minute file feed batch
    ///
    /// Downloads an individual one-minute batch by providing a time in format `YYYYMMDDhhmm`.
    ///
    /// # Arguments
    /// * `time` - Time string in format `YYYYMMDDhhmm` (e.g., "202312010802" for Dec 1, 2023 08:02 UTC)
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
    /// * `time` - Time string in format `YYYYMMDDhh` (e.g., "2023120108" for Dec 1, 2023 08:00-08:59 UTC)
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

    // ========== File Behaviour Feed ==========

    /// Get a per-minute file behaviour feed batch
    ///
    /// Downloads an individual one-minute batch of sandbox behavior reports.
    ///
    /// # Arguments
    /// * `time` - Time string in format `YYYYMMDDhhmm`
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
    /// * `time` - Time string in format `YYYYMMDDhh`
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
    /// * `time` - Time string in format `YYYYMMDDhhmm` (e.g., "202312010802")
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
    /// * `time` - Time string in format `YYYYMMDDhh` (e.g., "2023120108")
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
    /// * `time` - Time string in format `YYYYMMDDhhmm` (e.g., "202312010802")
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
    /// * `time` - Time string in format `YYYYMMDDhh` (e.g., "2023120108")
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
    /// * `time` - Time string in format `YYYYMMDDhhmm` (e.g., "202312010802")
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
    /// * `time` - Time string in format `YYYYMMDDhh` (e.g., "2023120108")
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

    // ========== Parse Methods ==========

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

    // ========== Utility Methods ==========

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
        format_time(year, month, day, hour, minute)
    }

    /// Calculate the latest available feed time
    ///
    /// Returns the latest time for which feeds should be available,
    /// accounting for the required lag (60 minutes for per-minute, 2 hours for hourly).
    ///
    /// # Arguments
    /// * `is_hourly` - true for hourly feeds (2h lag), false for per-minute (60m lag)
    pub fn get_latest_available_time(is_hourly: bool) -> String {
        get_latest_available_time(is_hourly)
    }

    /// Get feed times for a date range
    ///
    /// Generates a list of feed times for batch downloading.
    ///
    /// # Arguments
    /// * `start_time` - Start time in format `YYYYMMDDhhmm` or `YYYYMMDDhh`
    /// * `end_time` - End time in same format as start_time
    /// * `is_hourly` - true for hourly increments, false for per-minute
    ///
    /// # Returns
    /// Vector of time strings for feed requests
    pub fn get_time_range(start_time: &str, end_time: &str, is_hourly: bool) -> Vec<String> {
        get_time_range(start_time, end_time, is_hourly)
    }
}

impl crate::Client {
    /// Get the Feeds client for file intelligence and sandbox feeds
    pub fn feeds(&self) -> FeedsClient {
        FeedsClient::new(self.clone())
    }
}
