use super::{TokenIntrospectionResponse, basic::BasicTokenIntrospectionResponse};

#[test]
fn introspection_preserves_signed_integer_seconds_and_null_timestamps() {
    let response: BasicTokenIntrospectionResponse = serde_json::from_value(serde_json::json!({
        "active": true, "exp": -1, "iat": 0, "nbf": null
    }))
    .unwrap();
    assert_eq!(response.exp().unwrap().unix_timestamp(), -1);
    assert_eq!(response.iat().unwrap().unix_timestamp(), 0);
    assert_eq!(response.nbf(), None);
    let encoded = serde_json::to_value(response).unwrap();
    assert_eq!(encoded["exp"], -1);
    assert_eq!(encoded["iat"], 0);
    assert!(encoded.get("nbf").is_none_or(serde_json::Value::is_null));
}

#[test]
fn introspection_rejects_unrepresentable_and_fractional_numeric_instants() {
    for value in [serde_json::json!(i64::MAX), serde_json::json!(1.5)] {
        assert!(
            serde_json::from_value::<BasicTokenIntrospectionResponse>(serde_json::json!({
                "active": true, "exp": value
            }))
            .is_err()
        );
    }
}
