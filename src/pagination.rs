//! Shared finite cursor pagination for collection clients.

use crate::{Error, Result};
use std::collections::HashSet;
use std::num::NonZeroUsize;

pub(crate) struct PaginationState {
    seen: HashSet<String>,
    pages: usize,
    items: usize,
    max_pages: usize,
    max_items: usize,
    pending_error: bool,
}

impl Default for PaginationState {
    fn default() -> Self {
        Self {
            seen: HashSet::new(),
            pages: 0,
            items: 0,
            max_pages: 1000,
            max_items: 1_000_000,
            pending_error: false,
        }
    }
}

impl PaginationState {
    pub(crate) fn set_bounds(&mut self, pages: NonZeroUsize, items: NonZeroUsize) {
        self.max_pages = pages.get();
        self.max_items = items.get();
    }

    pub(crate) fn before_request(&mut self, cursor: Option<&str>) -> Result<()> {
        if self.pending_error {
            return Err(Error::bad_request("Pagination cursor repeated or cycled"));
        }
        if self.pages >= self.max_pages || self.items >= self.max_items {
            return Err(Error::bad_request(
                "Pagination did not finish within the configured bounds",
            ));
        }
        if let Some(cursor) = cursor {
            self.seen.insert(cursor.to_owned());
        }
        Ok(())
    }

    pub(crate) fn record(&mut self, count: usize, next: Option<&str>) -> Result<()> {
        let items = self.items.saturating_add(count);
        if items > self.max_items {
            return Err(Error::bad_request(
                "Pagination exceeded the configured item bound",
            ));
        }
        self.items = items;
        self.pages += 1;
        // Return this page once; fail before any repeated request, so manual callers
        // retain the final distinct batch without a silent success from collectors.
        self.pending_error = next.is_some_and(|cursor| self.seen.contains(cursor));
        Ok(())
    }
}

pub(crate) fn page_url(endpoint: &str, cursor: Option<&str>, limit: Option<u32>) -> Result<String> {
    if limit == Some(0) {
        return Err(Error::bad_request("Pagination page size must be positive"));
    }
    let (endpoint, _) = endpoint.split_once('#').unwrap_or((endpoint, ""));
    let (path, existing) = endpoint.split_once('?').unwrap_or((endpoint, ""));
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in url::form_urlencoded::parse(existing.as_bytes()) {
        if (name == "cursor" && cursor.is_some()) || (name == "limit" && limit.is_some()) {
            continue;
        }
        query.append_pair(&name, &value);
    }
    if let Some(cursor) = cursor {
        query.append_pair("cursor", cursor);
    }
    if let Some(limit) = limit {
        query.append_pair("limit", &limit.to_string());
    }
    let query = query.finish();
    Ok(if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    })
}

pub(crate) fn endpoint_cursor(endpoint: &str) -> Option<String> {
    let (_, query) = endpoint.split_once('?')?;
    let (query, _) = query.split_once('#').unwrap_or((query, ""));
    url::form_urlencoded::parse(query.as_bytes())
        .find(|(name, _)| name == "cursor")
        .map(|(_, value)| value.into_owned())
}
