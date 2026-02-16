use crate::ip_addresses::{IpAddress, IpAddressAttributes};
use crate::objects::Object;

// Test object operations using the macro to eliminate duplication
crate::test_object_operations!(IpAddress, "ip_addresses", "192.168.1.1", "resolutions");

#[test]
fn test_ip_address_creation() {
    let ip = IpAddress {
        object: Object {
            id: "192.168.1.1".to_string(),
            object_type: "ip_address".to_string(),
            links: None,
            relationships: None,
            attributes: IpAddressAttributes {
                country: Some("US".to_string()),
                continent: Some("NA".to_string()),
                asn: Some(15169),
                as_owner: Some("Google LLC".to_string()),
                reputation: Some(0),
                ..Default::default()
            },
        },
    };

    assert_eq!(ip.object.id, "192.168.1.1");
    assert_eq!(ip.object.attributes.country, Some("US".to_string()));
    assert_eq!(ip.object.attributes.asn, Some(15169));
    assert_eq!(
        ip.object.attributes.as_owner,
        Some("Google LLC".to_string())
    );
}

#[test]
fn test_ip_address_attributes_default() {
    let attrs = IpAddressAttributes::default();
    assert!(attrs.country.is_none());
    assert!(attrs.asn.is_none());
    assert!(attrs.reputation.is_none());
}

#[test]
fn test_ip_address_with_network_info() {
    let ip = IpAddress {
        object: Object {
            id: "10.0.0.1".to_string(),
            object_type: "ip_address".to_string(),
            links: None,
            relationships: None,
            attributes: IpAddressAttributes {
                network: Some("10.0.0.0/24".to_string()),
                regional_internet_registry: Some("ARIN".to_string()),
                ..Default::default()
            },
        },
    };

    assert_eq!(
        ip.object.attributes.network,
        Some("10.0.0.0/24".to_string())
    );
    assert_eq!(
        ip.object.attributes.regional_internet_registry,
        Some("ARIN".to_string())
    );
}

#[test]
fn test_ip_address_with_whois() {
    let ip = IpAddress {
        object: Object {
            id: "8.8.8.8".to_string(),
            object_type: "ip_address".to_string(),
            links: None,
            relationships: None,
            attributes: IpAddressAttributes {
                whois: Some("NetRange: 8.8.8.0 - 8.8.8.255\nCIDR: 8.8.8.0/24".to_string()),
                whois_date: Some(1234567890),
                ..Default::default()
            },
        },
    };

    assert!(ip.object.attributes.whois.is_some());
    assert!(ip.object.attributes.whois.unwrap().contains("8.8.8.0"));
    assert_eq!(ip.object.attributes.whois_date, Some(1234567890));
}

#[test]
fn test_ip_address_ipv6() {
    let ip = IpAddress {
        object: Object {
            id: "2001:4860:4860::8888".to_string(),
            object_type: "ip_address".to_string(),
            links: None,
            relationships: None,
            attributes: IpAddressAttributes {
                country: Some("US".to_string()),
                ..Default::default()
            },
        },
    };

    assert!(ip.object.id.contains("2001:4860"));
    assert_eq!(ip.object.attributes.country, Some("US".to_string()));
}
