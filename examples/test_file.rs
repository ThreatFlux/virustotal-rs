use virustotal_rs::{ApiTier, Client};
#[path = "common/mod.rs"]
mod common;
use common::{console, error_handling, file_info, workflow, SAMPLE_FILE_HASH};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use the new workflow utility to eliminate duplicate main patterns
    workflow::run_example_workflow(
        "Testing File API",
        "VTI_API_KEY",
        ApiTier::Public,
        |client| run_workflow(client, SAMPLE_FILE_HASH),
    )
    .await
}

async fn run_workflow(client: Client, file_hash: &str) -> Result<(), Box<dyn std::error::Error>> {
    console::print_fetching("file", file_hash);

    // Use enhanced error handling
    if let Some(file) =
        error_handling::handle_api_error(client.files().get(file_hash).await, "fetching file")
    {
        file_info::print_standard_file_info(&file);

        workflow::run_test_section("Testing Comments", || async {
            show_comments(&client, file_hash).await
        })
        .await?;

        workflow::run_test_section("Testing Votes", || async {
            show_votes(&client, file_hash).await
        })
        .await?;

        workflow::run_test_section("Testing Relationships", || async {
            show_relationships(&client, file_hash).await
        })
        .await?;
    } else {
        println!("Suggestion: Make sure your API key is valid and has access to this file");
    }

    Ok(())
}

// Function removed - now using file_info::print_standard_file_info()

async fn show_comments(client: &Client, file_hash: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Use enhanced error handling pattern
    if let Some(comments) = error_handling::handle_api_error(
        client.files().get_comments_with_limit(file_hash, 5).await,
        "retrieving comments",
    ) {
        console::print_check_success(&format!("Retrieved {} comments", comments.data.len()));
        for (i, comment) in comments.data.iter().take(3).enumerate() {
            let snippet: String = comment.object.attributes.text.chars().take(100).collect();
            console::print_step(&format!("Comment {}: {}", i + 1, snippet));
        }
    }
    Ok(())
}

async fn show_votes(client: &Client, file_hash: &str) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(votes) = error_handling::handle_api_error(
        client.files().get_votes(file_hash).await,
        "retrieving votes",
    ) {
        console::print_check_success(&format!("Retrieved {} votes", votes.data.len()));
        for (i, vote) in votes.data.iter().take(3).enumerate() {
            console::print_step(&format!(
                "Vote {}: {:?}",
                i + 1,
                vote.object.attributes.verdict
            ));
        }
    }
    Ok(())
}

async fn show_relationships(
    client: &Client,
    file_hash: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(domains) = error_handling::handle_api_error(
        client.files().get_contacted_domains(file_hash).await,
        "retrieving contacted domains",
    ) {
        console::print_check_success(&format!("Contacted domains: {} found", domains.data.len()));
        for (i, domain) in domains.data.iter().take(3).enumerate() {
            if let Some(id) = domain.get("id").and_then(|v| v.as_str()) {
                console::print_step(&format!("Domain {}: {}", i + 1, id));
            }
        }
    }

    if let Some(similar) = error_handling::handle_api_error(
        client.files().get_similar_files(file_hash).await,
        "retrieving similar files",
    ) {
        console::print_check_success(&format!("Similar files: {} found", similar.data.len()));
    }

    Ok(())
}
