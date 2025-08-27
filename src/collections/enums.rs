//! Enumeration types for collection operations

/// Options for collection ordering
#[derive(Debug, Clone, Copy)]
pub enum CollectionOrder {
    CreationDateAsc,
    CreationDateDesc,
    CreationDayAsc,
    CreationDayDesc,
    DomainsAsc,
    DomainsDesc,
    FilesAsc,
    FilesDesc,
    IpAddressesAsc,
    IpAddressesDesc,
    LastModificationDateAsc,
    LastModificationDateDesc,
    LastModificationDayAsc,
    LastModificationDayDesc,
    ReferencesAsc,
    ReferencesDesc,
    UrlsAsc,
    UrlsDesc,
}

impl CollectionOrder {
    /// Convert to API parameter string
    pub fn to_string(&self) -> &'static str {
        match self {
            CollectionOrder::CreationDateAsc => "creation_date+",
            CollectionOrder::CreationDateDesc => "creation_date-",
            CollectionOrder::CreationDayAsc => "creation_day+",
            CollectionOrder::CreationDayDesc => "creation_day-",
            CollectionOrder::DomainsAsc => "domains+",
            CollectionOrder::DomainsDesc => "domains-",
            CollectionOrder::FilesAsc => "files+",
            CollectionOrder::FilesDesc => "files-",
            CollectionOrder::IpAddressesAsc => "ip_addresses+",
            CollectionOrder::IpAddressesDesc => "ip_addresses-",
            CollectionOrder::LastModificationDateAsc => "last_modification_date+",
            CollectionOrder::LastModificationDateDesc => "last_modification_date-",
            CollectionOrder::LastModificationDayAsc => "last_modification_day+",
            CollectionOrder::LastModificationDayDesc => "last_modification_day-",
            CollectionOrder::ReferencesAsc => "references+",
            CollectionOrder::ReferencesDesc => "references-",
            CollectionOrder::UrlsAsc => "urls+",
            CollectionOrder::UrlsDesc => "urls-",
        }
    }
}

/// Export format for collections
#[derive(Debug, Clone, Copy)]
pub enum ExportFormat {
    Json,
    Csv,
    Stix,
}

impl ExportFormat {
    /// Convert to API parameter string
    pub fn to_string(&self) -> &'static str {
        match self {
            ExportFormat::Json => "json",
            ExportFormat::Csv => "csv",
            ExportFormat::Stix => "stix",
        }
    }
}
