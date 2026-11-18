use jiff::{SignedDuration, Timestamp, civil::DateTime, tz::TimeZone};

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
    let now = Timestamp::now();
    let lag = if is_hourly {
        SignedDuration::from_hours(2)
    } else {
        SignedDuration::from_hours(1)
    };

    let available_time = now
        .checked_sub(lag)
        .expect("current clock minus the feed lag is representable")
        .to_zoned_datetime(TimeZone::UTC)
        .datetime();

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
/// Prepare time strings for parsing by adding missing seconds/minutes
fn prepare_time_strings(start_time: &str, end_time: &str, is_hourly: bool) -> (String, String) {
    if is_hourly {
        (format!("{}0000", start_time), format!("{}0000", end_time))
    } else {
        (format!("{}00", start_time), format!("{}00", end_time))
    }
}

/// Format datetime to feed time string
fn format_feed_time_string(current: DateTime, is_hourly: bool) -> String {
    if is_hourly {
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
    }
}

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
    let mut times = Vec::new();

    let (start_str, end_str) = prepare_time_strings(start_time, end_time, is_hourly);
    let full_format = "%Y%m%d%H%M%S";

    let start = DateTime::strptime(full_format, &start_str);
    let end = DateTime::strptime(full_format, &end_str);

    if let (Ok(start_dt), Ok(end_dt)) = (start, end) {
        let increment = if is_hourly {
            SignedDuration::from_hours(1)
        } else {
            SignedDuration::from_mins(1)
        };

        let mut current = start_dt;
        let end = end_dt;

        while current <= end {
            let time_str = format_feed_time_string(current, is_hourly);
            times.push(time_str);
            let Ok(next) = current.checked_add(increment) else {
                break;
            };
            current = next;
        }
    }

    times
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_time() {
        // Per-minute format
        let minute_time = format_time(2023, 12, 1, 8, Some(2));
        assert_eq!(minute_time, "202312010802");

        // Hourly format
        let hour_time = format_time(2023, 12, 1, 8, None);
        assert_eq!(hour_time, "2023120108");
    }

    #[test]
    fn test_time_range_generation() {
        // Test hourly range
        let hourly_range = get_time_range("2023120108", "2023120110", true);
        assert_eq!(hourly_range.len(), 3);
        assert_eq!(hourly_range[0], "2023120108");
        assert_eq!(hourly_range[1], "2023120109");
        assert_eq!(hourly_range[2], "2023120110");

        // Test per-minute range
        let minute_range = get_time_range("202312010800", "202312010802", false);
        assert_eq!(minute_range.len(), 3);
        assert_eq!(minute_range[0], "202312010800");
        assert_eq!(minute_range[1], "202312010801");
        assert_eq!(minute_range[2], "202312010802");
    }

    #[test]
    fn test_latest_available_time() {
        // Just test that the method runs and returns a string of correct length
        let minute_time = get_latest_available_time(false);
        assert_eq!(minute_time.len(), 12); // `YYYYMMDDhhmm`

        let hourly_time = get_latest_available_time(true);
        assert_eq!(hourly_time.len(), 10); // `YYYYMMDDhh`
    }

    #[test]
    fn feed_ranges_keep_leap_days_and_stop_at_the_last_representable_minute() {
        assert_eq!(
            get_time_range("2024022823", "2024022901", true),
            ["2024022823", "2024022900", "2024022901"]
        );
        assert_eq!(
            get_time_range("999912312359", "999912312359", false),
            ["999912312359"]
        );
        assert!(get_time_range("2026022900", "2026030100", true).is_empty());
        assert!(get_time_range("2026111900", "2026111800", true).is_empty());
    }
}
