//! Builder pattern implementation for collection requests

use super::descriptors::*;
use super::requests::*;

/// Helper methods for creating collections
impl CreateCollectionRequest {
    /// Create a new collection request with name and optional description
    pub fn new(name: String, description: Option<String>) -> Self {
        Self {
            data: CreateCollectionData {
                attributes: CreateCollectionAttributes { name, description },
                relationships: None,
                object_type: "collection".to_string(),
                raw_items: None,
            },
        }
    }

    /// Add domain relationships
    pub fn with_domains(mut self, domains: Vec<String>) -> Self {
        let domain_descriptors = self.create_domain_descriptors(domains);
        self.add_domain_relationships(domain_descriptors);
        self
    }

    /// Add URL relationships (using URLs)
    pub fn with_urls(mut self, urls: Vec<String>) -> Self {
        let url_descriptors = self.create_url_descriptors_from_urls(urls);
        self.add_url_relationships(url_descriptors);
        self
    }

    /// Add URL relationships (using IDs)
    pub fn with_url_ids(mut self, url_ids: Vec<String>) -> Self {
        let url_descriptors = self.create_url_descriptors_from_ids(url_ids);
        self.add_url_relationships(url_descriptors);
        self
    }

    /// Add IP address relationships
    pub fn with_ip_addresses(mut self, ips: Vec<String>) -> Self {
        let ip_descriptors = self.create_ip_descriptors(ips);
        self.add_ip_relationships(ip_descriptors);
        self
    }

    /// Add file relationships
    pub fn with_files(mut self, file_hashes: Vec<String>) -> Self {
        let file_descriptors = self.create_file_descriptors(file_hashes);
        self.add_file_relationships(file_descriptors);
        self
    }

    /// Add raw items text for extraction
    pub fn with_raw_items(mut self, raw_text: String) -> Self {
        self.data.raw_items = Some(raw_text);
        self
    }

    // Private helper methods to reduce complexity
    fn create_domain_descriptors(&self, domains: Vec<String>) -> Vec<DomainDescriptor> {
        domains
            .into_iter()
            .map(|id| DomainDescriptor {
                object_type: "domain".to_string(),
                id,
            })
            .collect()
    }

    fn create_url_descriptors_from_urls(&self, urls: Vec<String>) -> Vec<UrlDescriptor> {
        urls.into_iter()
            .map(|url| UrlDescriptor::WithUrl {
                object_type: "url".to_string(),
                url,
            })
            .collect()
    }

    fn create_url_descriptors_from_ids(&self, url_ids: Vec<String>) -> Vec<UrlDescriptor> {
        url_ids
            .into_iter()
            .map(|id| UrlDescriptor::WithId {
                object_type: "url".to_string(),
                id,
            })
            .collect()
    }

    fn create_ip_descriptors(&self, ips: Vec<String>) -> Vec<IpAddressDescriptor> {
        ips.into_iter()
            .map(|id| IpAddressDescriptor {
                object_type: "ip_address".to_string(),
                id,
            })
            .collect()
    }

    fn create_file_descriptors(&self, file_hashes: Vec<String>) -> Vec<FileDescriptor> {
        file_hashes
            .into_iter()
            .map(|id| FileDescriptor {
                object_type: "file".to_string(),
                id,
            })
            .collect()
    }

    fn add_domain_relationships(&mut self, domain_descriptors: Vec<DomainDescriptor>) {
        if let Some(ref mut relationships) = self.data.relationships {
            relationships.domains = Some(RelationshipData {
                data: domain_descriptors,
            });
        } else {
            self.data.relationships = Some(CollectionRelationships {
                domains: Some(RelationshipData {
                    data: domain_descriptors,
                }),
                ..Default::default()
            });
        }
    }

    fn add_url_relationships(&mut self, url_descriptors: Vec<UrlDescriptor>) {
        if let Some(ref mut relationships) = self.data.relationships {
            relationships.urls = Some(RelationshipData {
                data: url_descriptors,
            });
        } else {
            self.data.relationships = Some(CollectionRelationships {
                urls: Some(RelationshipData {
                    data: url_descriptors,
                }),
                ..Default::default()
            });
        }
    }

    fn add_ip_relationships(&mut self, ip_descriptors: Vec<IpAddressDescriptor>) {
        if let Some(ref mut relationships) = self.data.relationships {
            relationships.ip_addresses = Some(RelationshipData {
                data: ip_descriptors,
            });
        } else {
            self.data.relationships = Some(CollectionRelationships {
                ip_addresses: Some(RelationshipData {
                    data: ip_descriptors,
                }),
                ..Default::default()
            });
        }
    }

    fn add_file_relationships(&mut self, file_descriptors: Vec<FileDescriptor>) {
        if let Some(ref mut relationships) = self.data.relationships {
            relationships.files = Some(RelationshipData {
                data: file_descriptors,
            });
        } else {
            self.data.relationships = Some(CollectionRelationships {
                files: Some(RelationshipData {
                    data: file_descriptors,
                }),
                ..Default::default()
            });
        }
    }
}
