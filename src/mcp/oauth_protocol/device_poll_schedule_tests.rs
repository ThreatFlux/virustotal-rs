use super::tests::new_device_auth_details;
use crate::mcp::oauth_protocol::{HttpRequest, tests::new_client};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use time::OffsetDateTime;

fn response(status: u16, body: &str) -> http::Response<Vec<u8>> {
    http::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(body.as_bytes().to_vec())
        .unwrap()
}

fn polling_http(
    error: &str,
) -> impl Fn(HttpRequest) -> Result<http::Response<Vec<u8>>, std::io::Error> {
    let responses = Mutex::new(
        [
            response(400, &format!("{{\"error\":\"{error}\"}}")),
            response(
                200,
                "{\"access_token\":\"fixture-token\",\"token_type\":\"bearer\"}",
            ),
        ]
        .into_iter(),
    );
    move |_: HttpRequest| Ok(responses.lock().unwrap().next().unwrap())
}

#[test]
fn actual_polling_waits_advance_the_clock_by_one_or_six_seconds() {
    for (error, expected_seconds) in [("authorization_pending", 1), ("slow_down", 6)] {
        let clock = Arc::new(Mutex::new(OffsetDateTime::UNIX_EPOCH));
        let sleeps = Arc::new(Mutex::new(Vec::new()));
        let http = polling_http(error);
        let now = Arc::clone(&clock);
        let elapsed = Arc::clone(&clock);
        let waits = Arc::clone(&sleeps);
        let details = new_device_auth_details(20);
        new_client()
            .exchange_device_access_token(&details)
            .set_time_fn(move || *now.lock().unwrap())
            .request(
                &http,
                move |duration| {
                    waits.lock().unwrap().push(duration);
                    *elapsed.lock().unwrap() += time::Duration::try_from(duration).unwrap();
                },
                None,
            )
            .unwrap();
        assert_eq!(
            *sleeps.lock().unwrap(),
            [Duration::from_secs(expected_seconds)]
        );
        assert_eq!(
            clock.lock().unwrap().unix_timestamp(),
            expected_seconds as i64
        );
    }
}

#[test]
fn overflowing_slow_down_returns_error_without_sleeping() {
    let details =
        serde_json::from_value::<super::StandardDeviceAuthorizationResponse>(serde_json::json!({
            "device_code": "fixture-code",
            "user_code": "fixture-user-code",
            "verification_uri": "https://example.invalid/device",
            "expires_in": 20,
            "interval": u64::MAX,
        }))
        .unwrap();
    let http = polling_http("slow_down");
    let result = new_client()
        .exchange_device_access_token(&details)
        .set_time_fn(|| OffsetDateTime::UNIX_EPOCH)
        .request(
            &http,
            |_| panic!("overflow must return before sleeping"),
            None,
        );
    assert!(
        matches!(result, Err(super::RequestTokenError::Other(message))
        if message == "device polling interval is not representable")
    );
}
