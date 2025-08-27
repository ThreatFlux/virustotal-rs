use virustotal_rs::{ApiTier, Corpus, CreateRetrohuntJobRequest, JobStatus};

mod common;
use common::*;
mod matching_files_helper;
use matching_files_helper::*;

type ExampleResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Create a test YARA rule for retrohunt scanning
fn create_test_yara_rule() -> String {
    r#"
rule TestRetrohunt {
    meta:
        description = "Test rule for retrohunt scanning"
        author = "SDK Test"
    strings:
        $pe_header = { 4D 5A }
        $dos_stub = "This program cannot be run in DOS mode"
    condition:
        $pe_header at 0 and $dos_stub
}
"#
    .to_string()
}

/// Calculate time range for the last 7 days
fn calculate_time_range() -> ExampleResult<(i64, i64)> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    let seven_days_ago = now - (7 * 24 * 60 * 60);
    Ok((seven_days_ago, now))
}

/// Display pagination cursor if available
fn display_pagination_cursor(meta: &Option<virustotal_rs::objects::CollectionMeta>) {
    if let Some(meta) = meta {
        if let Some(cursor) = &meta.cursor {
            println!(
                "   - Cursor for pagination: {}",
                truncate_string(cursor, 20)
            );
        }
    }
}

/// Handle job listing result and display information
fn handle_job_listing_result(
    result: Option<virustotal_rs::Collection<virustotal_rs::RetrohuntJob>>,
) {
    match result {
        Some(jobs) => {
            display_pagination_cursor(&jobs.meta);
            display_job_list(&jobs.data);
        }
        None => {
            print_warning("Retrohunt requires premium API privileges");
        }
    }
}

/// List existing retrohunt jobs
async fn list_retrohunt_jobs(retrohunt: &virustotal_rs::RetrohuntClient<'_>) {
    print_step_header(1, "LISTING RETROHUNT JOBS");

    let result = retrohunt
        .list_jobs(Some("status:finished"), Some(10), None)
        .await;

    let jobs_result = handle_result(result, "Retrieved Retrohunt jobs", "Error listing jobs");
    handle_job_listing_result(jobs_result);
}

/// Display job list information
fn display_job_list(jobs: &[virustotal_rs::RetrohuntJob]) {
    for job in jobs.iter().take(5) {
        println!("   - Job ID: {}", job.object.id);
        if let Some(status) = &job.object.attributes.status {
            print!("     Status: {:?}", status);
        }
        if let Some(progress) = &job.object.attributes.progress {
            print!(" ({}%)", progress);
        }
        if let Some(matches) = &job.object.attributes.matches {
            print!(" - {} matches", matches);
        }
        println!();

        if let Some(creation_date) = &job.object.attributes.creation_date {
            println!("     Created: {}", creation_date);
        }
        if let Some(scanned) = &job.object.attributes.scanned_files {
            println!("     Scanned files: {}", scanned);
        }
    }
}

/// Create a new retrohunt job
async fn create_retrohunt_job(retrohunt: &virustotal_rs::RetrohuntClient<'_>) -> Option<String> {
    print_step_header(2, "CREATING RETROHUNT JOB");

    let yara_rule = create_test_yara_rule();
    let (seven_days_ago, now) = match calculate_time_range() {
        Ok(range) => range,
        Err(e) => {
            print_error(&format!("Error calculating time range: {}", e));
            return None;
        }
    };

    let create_request = CreateRetrohuntJobRequest::new(yara_rule)
        .with_notification_email("notifications@example.com".to_string())
        .with_corpus(Corpus::Main)
        .with_time_range(Some(seven_days_ago), Some(now));

    match retrohunt.create_job(&create_request).await {
        Ok(job) => {
            print_success("Retrohunt job created successfully");
            display_created_job(&job);
            Some(job.object.id)
        }
        Err(e) => {
            print_error(&format!("Error creating job: {}", e));
            println!("   Note: Limits - max 10 concurrent jobs, 300 rules, 90 days scan range");
            None
        }
    }
}

/// Display information about a created job
fn display_created_job(job: &virustotal_rs::RetrohuntJob) {
    println!("   - Job ID: {}", job.object.id);
    if let Some(status) = &job.object.attributes.status {
        println!("   - Status: {:?}", status);
    }
    if let Some(creation_date) = &job.object.attributes.creation_date {
        println!("   - Created: {}", creation_date);
    }
    if let Some(time_range) = &job.object.attributes.time_range {
        if let Some(start) = time_range.start {
            println!("   - Scan start time: {}", start);
        }
        if let Some(end) = time_range.end {
            println!("   - Scan end time: {}", end);
        }
    }
}

/// Check and display job status
fn check_and_display_status(job: &virustotal_rs::RetrohuntJob) -> bool {
    if let Some(status) = &job.object.attributes.status {
        print!("   - Status: {:?}", status);
        match status {
            JobStatus::Finished => {
                println!(" ✓");
                return true;
            }
            JobStatus::Aborted => {
                println!(" ✗");
                if let Some(error) = &job.object.attributes.error {
                    println!("   - Error: {}", error);
                }
                return true;
            }
            _ => println!(),
        }
    }
    false
}

/// Perform single job status check
async fn perform_job_check(
    retrohunt: &virustotal_rs::RetrohuntClient<'_>,
    job_id: &str,
    check_number: usize,
) -> Result<bool, String> {
    match retrohunt.get_job(job_id).await {
        Ok(job) => {
            println!("\n   Check #{}: Job {}", check_number + 1, job.object.id);
            let is_terminal = check_and_display_status(&job);
            display_job_progress(&job);
            Ok(is_terminal)
        }
        Err(e) => Err(format!("Error checking job status: {}", e)),
    }
}

/// Monitor job progress with polling
async fn monitor_job_progress(retrohunt: &virustotal_rs::RetrohuntClient<'_>, job_id: &str) {
    print_step_header(3, "MONITORING JOB PROGRESS");

    for i in 0..3 {
        match perform_job_check(retrohunt, job_id, i).await {
            Ok(is_terminal) => {
                if is_terminal {
                    break;
                }
                if i < 2 {
                    println!("   Waiting 5 seconds before next check...");
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                }
            }
            Err(error_msg) => {
                print_error(&error_msg);
                break;
            }
        }
    }
}

/// Display job progress information
fn display_job_progress(job: &virustotal_rs::RetrohuntJob) {
    if let Some(progress) = &job.object.attributes.progress {
        println!("   - Progress: {}%", progress);
    }
    if let Some(scanned) = &job.object.attributes.scanned_files {
        println!("   - Scanned files: {}", scanned);
    }
    if let Some(matches) = &job.object.attributes.matches {
        println!("   - Matches found: {}", matches);
    }
    if let Some(eta) = &job.object.attributes.eta {
        println!("   - ETA: {} seconds", eta);
    }
}

/// Retrieve matching files from completed job
async fn get_matching_files(retrohunt: &virustotal_rs::RetrohuntClient<'_>, job_id: &str) {
    print_step_header(4, "RETRIEVING MATCHING FILES");

    let result = retrohunt.get_matching_files(job_id, Some(10), None).await;
    handle_matching_files_result(result);
}

/// Test pagination functionality
async fn test_pagination(retrohunt: &virustotal_rs::RetrohuntClient<'_>, job_id: &str) {
    print_step_header(5, "PAGINATION TEST");

    let mut files_iterator = retrohunt.get_matching_files_iterator(job_id);

    println!("Fetching first batch of matching files:");
    let batch_result = files_iterator.next_batch().await;
    handle_pagination_batch_result(batch_result);
}

/// Manage job lifecycle (abort if needed)
async fn manage_job_lifecycle(retrohunt: &virustotal_rs::RetrohuntClient<'_>, job_id: &str) {
    print_step_header(6, "JOB MANAGEMENT");

    match retrohunt.get_job(job_id).await {
        Ok(job) => {
            if let Some(status) = &job.object.attributes.status {
                match status {
                    JobStatus::Starting | JobStatus::Running => {
                        println!("   Job is still running, attempting to abort...");
                        match retrohunt.abort_job(job_id).await {
                            Ok(_) => print_success("Job abort request sent"),
                            Err(e) => print_error(&format!("Error aborting job: {}", e)),
                        }
                    }
                    _ => {
                        println!(
                            "   Job is not running (status: {:?}), skipping abort",
                            status
                        );
                    }
                }
            }
        }
        Err(e) => {
            print_error(&format!("Error checking job status: {}", e));
        }
    }
}

/// Clean up created job
async fn cleanup_job(retrohunt: &virustotal_rs::RetrohuntClient<'_>, job_id: &str) {
    print_step_header(7, "CLEANUP");

    match retrohunt.delete_job(job_id).await {
        Ok(_) => print_success("Deleted test job"),
        Err(e) => print_error(&format!("Error deleting job: {}", e)),
    }
}

/// Test helper methods including wait_for_completion
async fn test_helper_methods(retrohunt: &virustotal_rs::RetrohuntClient<'_>) {
    print_step_header(8, "HELPER METHODS");

    println!("\nTesting wait_for_completion (demonstration):");
    println!("   Note: In real usage, this would poll until job completes");

    let (_, now) = calculate_time_range().unwrap_or((0, 0));
    let wait_test_request =
        CreateRetrohuntJobRequest::new("rule QuickTest { condition: false }".to_string())
            .with_corpus(Corpus::Goodware)
            .with_start_time(now - (24 * 60 * 60))
            .with_end_time(now);

    match retrohunt.create_job(&wait_test_request).await {
        Ok(job) => {
            print_success("Created test job for wait demonstration");
            println!("   - Job ID: {}", job.object.id);
            test_wait_completion(retrohunt, &job.object.id).await;
        }
        Err(e) => {
            print_error(&format!("Error creating test job: {}", e));
        }
    }
}

/// Test wait for completion functionality
async fn test_wait_completion(retrohunt: &virustotal_rs::RetrohuntClient<'_>, job_id: &str) {
    println!("   Waiting for job completion (max 30 seconds)...");
    match retrohunt
        .wait_for_completion(job_id, Some(30), Some(5))
        .await
    {
        Ok(completed_job) => {
            print_success("Job completed!");
            if let Some(status) = &completed_job.object.attributes.status {
                println!("   - Final status: {:?}", status);
            }
            if let Some(matches) = &completed_job.object.attributes.matches {
                println!("   - Total matches: {}", matches);
            }
        }
        Err(e) => {
            print_error(&format!("Error or timeout waiting for completion: {}", e));
        }
    }

    // Clean up
    let _ = retrohunt.delete_job(job_id).await;
}

/// Test filtering jobs by status
async fn test_job_filtering(retrohunt: &virustotal_rs::RetrohuntClient<'_>) {
    print_step_header(9, "FILTERING JOBS");

    let statuses = vec!["starting", "running", "finished", "aborted"];
    for status in statuses {
        let filter = format!("status:{}", status);
        match retrohunt.list_jobs(Some(&filter), Some(5), None).await {
            Ok(jobs) => {
                println!("   Jobs with status '{}': {}", status, jobs.data.len());
            }
            Err(e) => {
                print_error(&format!("Error filtering by status '{}': {}", status, e));
            }
        }
    }
}

/// Test job list iteration
async fn test_job_iteration(retrohunt: &virustotal_rs::RetrohuntClient<'_>) {
    print_step_header(10, "JOB LIST ITERATION");

    let mut job_iterator = retrohunt.list_jobs_iterator(Some("status:finished"));

    println!("Fetching first batch of finished jobs:");
    match job_iterator.next_batch().await {
        Ok(batch) => {
            print_success(&format!("Retrieved {} jobs in first batch", batch.len()));
            for job in batch.iter().take(3) {
                println!("   - Job {}", job.object.id);
                if let Some(matches) = &job.object.attributes.matches {
                    println!("     Matches: {}", matches);
                }
            }
        }
        Err(e) => {
            print_error(&format!("Error fetching batch: {}", e));
        }
    }
}

#[tokio::main]
async fn main() -> ExampleResult<()> {
    let client = create_client_from_env("VT_API_KEY", ApiTier::Premium)?;

    print_header("Testing VirusTotal Retrohunt API");

    let retrohunt = client.retrohunt();

    // Execute all test scenarios in sequence
    list_retrohunt_jobs(&retrohunt).await;

    let created_job_id = create_retrohunt_job(&retrohunt).await;

    if let Some(job_id) = &created_job_id {
        monitor_job_progress(&retrohunt, job_id).await;
        get_matching_files(&retrohunt, job_id).await;
        test_pagination(&retrohunt, job_id).await;
        manage_job_lifecycle(&retrohunt, job_id).await;
        cleanup_job(&retrohunt, job_id).await;
    }

    test_helper_methods(&retrohunt).await;
    test_job_filtering(&retrohunt).await;
    test_job_iteration(&retrohunt).await;

    println!("\n==================================");
    println!("Retrohunt API testing complete!");

    Ok(())
}
