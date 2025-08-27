//! Common endpoint patterns for VirusTotal API

use super::builder::EndpointBuilder;
use super::validation::{validate_domain, validate_hash, validate_ip};
use crate::error::Result;

/// Common endpoint patterns
pub struct Endpoints;

impl Endpoints {
    /// Files collection endpoint
    pub fn files() -> EndpointBuilder {
        EndpointBuilder::new().raw_segment("files")
    }

    /// Specific file endpoint
    pub fn file(file_id: &str) -> Result<EndpointBuilder> {
        validate_hash(file_id)?;
        Ok(EndpointBuilder::new().raw_segment("files").segment(file_id))
    }

    /// URLs collection endpoint
    pub fn urls() -> EndpointBuilder {
        EndpointBuilder::new().raw_segment("urls")
    }

    /// Specific URL endpoint
    pub fn url(url_id: &str) -> EndpointBuilder {
        EndpointBuilder::new().raw_segment("urls").segment(url_id)
    }

    /// Domains collection endpoint
    pub fn domains() -> EndpointBuilder {
        EndpointBuilder::new().raw_segment("domains")
    }

    /// Specific domain endpoint
    pub fn domain(domain: &str) -> Result<EndpointBuilder> {
        validate_domain(domain)?;
        Ok(EndpointBuilder::new()
            .raw_segment("domains")
            .segment(domain))
    }

    /// IP addresses collection endpoint
    pub fn ip_addresses() -> EndpointBuilder {
        EndpointBuilder::new().raw_segment("ip_addresses")
    }

    /// Specific IP address endpoint
    pub fn ip_address(ip: &str) -> Result<EndpointBuilder> {
        validate_ip(ip)?;
        Ok(EndpointBuilder::new()
            .raw_segment("ip_addresses")
            .segment(ip))
    }

    /// Analyses endpoint
    pub fn analyses() -> EndpointBuilder {
        EndpointBuilder::new().raw_segment("analyses")
    }

    /// Specific analysis endpoint
    pub fn analysis(analysis_id: &str) -> EndpointBuilder {
        EndpointBuilder::new()
            .raw_segment("analyses")
            .segment(analysis_id)
    }

    /// Comments endpoint for a resource
    pub fn comments(resource_type: &str, resource_id: &str) -> EndpointBuilder {
        EndpointBuilder::new()
            .raw_segment(resource_type)
            .segment(resource_id)
            .raw_segment("comments")
    }

    /// Votes endpoint for a resource
    pub fn votes(resource_type: &str, resource_id: &str) -> EndpointBuilder {
        EndpointBuilder::new()
            .raw_segment(resource_type)
            .segment(resource_id)
            .raw_segment("votes")
    }

    /// Search endpoint
    pub fn search() -> EndpointBuilder {
        EndpointBuilder::new().raw_segment("search")
    }

    /// Private files endpoint
    pub fn private_files() -> EndpointBuilder {
        EndpointBuilder::new()
            .raw_segment("private")
            .raw_segment("files")
    }

    /// Specific private file endpoint
    pub fn private_file(sha256: &str) -> Result<EndpointBuilder> {
        validate_hash(sha256)?;
        Ok(EndpointBuilder::new()
            .raw_segment("private")
            .raw_segment("files")
            .segment(sha256))
    }

    /// Private URLs endpoint
    pub fn private_urls() -> EndpointBuilder {
        EndpointBuilder::new()
            .raw_segment("private")
            .raw_segment("urls")
    }

    /// Feeds endpoint
    pub fn feeds(resource_type: &str) -> EndpointBuilder {
        EndpointBuilder::new()
            .raw_segment("feeds")
            .raw_segment(resource_type)
    }

    /// Collections endpoint
    pub fn collections() -> EndpointBuilder {
        EndpointBuilder::new().raw_segment("collections")
    }

    /// Specific collection endpoint
    pub fn collection(collection_id: &str) -> EndpointBuilder {
        EndpointBuilder::new()
            .raw_segment("collections")
            .segment(collection_id)
    }
}
