//! Network-related structures for file analysis

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsLookup {
    pub hostname: Option<String>,
    pub resolved_ips: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpTraffic {
    pub destination_ip: Option<String>,
    pub destination_port: Option<u16>,
    pub protocol: Option<String>,
    pub bytes_sent: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConversation {
    pub url: Option<String>,
    pub request_method: Option<String>,
    pub response_status: Option<u16>,
    pub response_body_size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ja3Digest {
    pub digest: Option<String>,
    pub description: Option<String>,
}
