# virustotal-rs

A Rust SDK for the VirusTotal API v3.

## Features

- Full support for Public and Premium API tiers
- Built-in rate limiting (4 req/min for Public, configurable for Premium)
- Comprehensive error handling matching VirusTotal API errors
- Async/await support with Tokio
- Type-safe API with strong Rust types

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
virustotal-rs = "0.1.0"
```

## Usage

```rust
use virustotal_rs::{ClientBuilder, ApiTier};

#[tokio::main]
async fn main() {
    // Create a client for Public API
    let client = ClientBuilder::new()
        .api_key("your-api-key")
        .tier(ApiTier::Public)
        .build()
        .unwrap();

    // For Premium API users
    let premium_client = ClientBuilder::new()
        .api_key("your-premium-api-key")
        .tier(ApiTier::Premium)
        .build()
        .unwrap();
}
```

## Rate Limiting

The SDK automatically handles rate limiting based on your API tier:

- **Public API**: 4 requests per minute, 500 requests per day
- **Premium API**: No built-in limits (configurable based on your plan)

## Error Handling

All VirusTotal API errors are mapped to strongly-typed Rust errors:

```rust
use virustotal_rs::Error;

match client.get("/files/some-hash").await {
    Ok(file) => println!("File info: {:?}", file),
    Err(Error::NotFound) => println!("File not found"),
    Err(Error::QuotaExceeded(msg)) => println!("Quota exceeded: {}", msg),
    Err(e) if e.is_retryable() => println!("Retryable error: {}", e),
    Err(e) => println!("Error: {}", e),
}
```

## License

MIT OR Apache-2.0