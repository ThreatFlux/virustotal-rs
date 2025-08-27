use std::time::Duration;
use virustotal_rs::{
    iterator_utils::{Collectable, EnhancedCollectionIterator, IteratorExt, ProgressTracker},
    ApiTier, Client, Comment, Result,
};

/// Initialize the demo client
fn initialize_demo_client() -> Result<Client> {
    // Create a client (you'd use your actual API key here)
    let client = Client::new("your_api_key_here".into(), ApiTier::Public)?;
    Ok(client)
}

/// Print the main demo header
fn print_demo_header() {
    println!("=== VirusTotal Iterator Utilities Demo ===\n");
}

/// Demonstrate basic enhanced iteration capabilities
fn demonstrate_basic_iteration(client: &Client) {
    println!("1. Basic Enhanced Iteration");
    println!("--------------------------");

    // Create an enhanced collection iterator directly
    let enhanced_iter: EnhancedCollectionIterator<'_, Comment> =
        EnhancedCollectionIterator::new(client, "comments").with_limit(3);

    println!("Created enhanced iterator for comments endpoint");
    println!(
        "Fetched {} items in {} batches so far",
        enhanced_iter.total_fetched(),
        enhanced_iter.batch_count()
    );
}

/// Demonstrate chained operations with progress tracking
async fn demonstrate_chained_operations(client: &Client) -> Result<()> {
    println!("\n2. Chained Operations with Progress");
    println!("----------------------------------");

    let enhanced_iter: EnhancedCollectionIterator<'_, Comment> =
        EnhancedCollectionIterator::new(client, "comments").with_limit(5);

    let progress_tracker =
        ProgressTracker::new("Comment Processing").with_update_interval(Duration::from_millis(100));

    let chained_iter = enhanced_iter
        .throttle(Duration::from_millis(200)) // Be nice to the API
        .with_progress(progress_tracker);

    // Take only first 10 items across all batches
    match chained_iter.take(10).await {
        Ok(comments) => {
            println!(
                "Successfully processed {} comments with utilities",
                comments.len()
            );
        }
        Err(e) => {
            println!(
                "Note: This demo would work with a real API key. Error: {}",
                e
            );
        }
    }

    Ok(())
}

/// Demonstrate available map and filter operations
fn demonstrate_map_filter_operations() {
    println!("\n3. Map and Filter Operations");
    println!("----------------------------");

    // Create a mock demonstration showing the fluent API
    println!("The iterator utilities provide a fluent API for:");
    println!("• map() - Transform items during iteration");
    println!("• filter() - Filter items during iteration");
    println!("• take_until() - Take items until condition is met");
    println!("• batch() - Group items into batches");
    println!("• throttle() - Add rate limiting");
    println!("• retry_on_error() - Automatic retry on failures");
    println!("• with_progress() - Progress tracking");
    println!("• cached() - Cache results for reuse");
}

/// Demonstrate available collection utilities
fn demonstrate_collection_utilities() {
    println!("\n4. Collection Utilities");
    println!("----------------------");
    println!("Available collection methods:");
    println!("• collect_vec() - Collect into Vec");
    println!("• collect_set() - Collect into HashSet (deduplicates)");
    println!("• take(n) - Take first N items");
    println!("• skip(n) - Skip first N items");
}

/// Print the final demo completion message
fn print_demo_completion() {
    println!("\n=== Demo Complete ===");
    println!("\nThis demonstrates the comprehensive iterator utilities that eliminate");
    println!("duplication across the VirusTotal Rust library by providing:");
    println!("• Generic PaginatedIterator trait");
    println!("• Rate limit-aware iteration");
    println!("• Progress tracking and throttling");
    println!("• Functional programming patterns (map, filter, etc.)");
    println!("• Easy collection into different container types");
}

#[tokio::main]
async fn main() -> Result<()> {
    let client = initialize_demo_client()?;

    print_demo_header();
    demonstrate_basic_iteration(&client);
    demonstrate_chained_operations(&client).await?;
    demonstrate_map_filter_operations();
    demonstrate_collection_utilities();
    print_demo_completion();

    Ok(())
}