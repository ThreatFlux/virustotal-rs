use virustotal_rs::{ApiTier, ClientBuilder, Corpus, CreateRetrohuntJobRequest, JobStatus};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_key = std::env::var("VT_API_KEY").unwrap_or_else(|_| "test_key".to_string());

    let client = ClientBuilder::new()
        .api_key(api_key)
        .tier(ApiTier::Premium) // Retrohunt requires premium privileges
        .build()?;

    println!("Testing VirusTotal Retrohunt API");
    println!("=================================\n");

    let retrohunt = client.retrohunt();

    // 1. List existing Retrohunt jobs
    println!("1. LISTING RETROHUNT JOBS");
    println!("-------------------------");

    match retrohunt
        .list_jobs(Some("status:finished"), Some(10), None)
        .await
    {
        Ok(jobs) => {
            println!("   ✓ Retrieved Retrohunt jobs");
            if let Some(meta) = &jobs.meta {
                if let Some(cursor) = &meta.cursor {
                    println!(
                        "   - Cursor for pagination: {}",
                        &cursor[..20.min(cursor.len())]
                    );
                }
            }

            for job in jobs.data.iter().take(5) {
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
        Err(e) => {
            println!("   ✗ Error listing jobs: {}", e);
            println!("   Note: Retrohunt requires premium API privileges");
        }
    }

    // 2. Create a new Retrohunt job
    println!("\n2. CREATING RETROHUNT JOB");
    println!("-------------------------");

    let yara_rule = r#"
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
"#;

    // Calculate time range: last 7 days
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    let seven_days_ago = now - (7 * 24 * 60 * 60);

    let create_request = CreateRetrohuntJobRequest::new(yara_rule.to_string())
        .with_notification_email("notifications@example.com".to_string())
        .with_corpus(Corpus::Main)
        .with_time_range(Some(seven_days_ago), Some(now));

    let created_job_id = match retrohunt.create_job(&create_request).await {
        Ok(job) => {
            println!("   ✓ Retrohunt job created successfully");
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
            Some(job.object.id)
        }
        Err(e) => {
            println!("   ✗ Error creating job: {}", e);
            println!("   Note: Limits - max 10 concurrent jobs, 300 rules, 90 days scan range");
            None
        }
    };

    // 3. Monitor job progress
    if let Some(job_id) = &created_job_id {
        println!("\n3. MONITORING JOB PROGRESS");
        println!("--------------------------");

        // Check job status a few times
        for i in 0..3 {
            match retrohunt.get_job(job_id).await {
                Ok(job) => {
                    println!("\n   Check #{}: Job {}", i + 1, job.object.id);
                    if let Some(status) = &job.object.attributes.status {
                        print!("   - Status: {:?}", status);

                        match status {
                            JobStatus::Finished => {
                                println!(" ✓");
                                break;
                            }
                            JobStatus::Aborted => {
                                println!(" ✗");
                                if let Some(error) = &job.object.attributes.error {
                                    println!("   - Error: {}", error);
                                }
                                break;
                            }
                            _ => println!(),
                        }
                    }

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

                    // Wait before next check (in real usage)
                    if i < 2 {
                        println!("   Waiting 5 seconds before next check...");
                        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    }
                }
                Err(e) => {
                    println!("   ✗ Error checking job status: {}", e);
                    break;
                }
            }
        }

        // 4. Get matching files
        println!("\n4. RETRIEVING MATCHING FILES");
        println!("-----------------------------");

        match retrohunt.get_matching_files(job_id, Some(10), None).await {
            Ok(files) => {
                println!("   ✓ Retrieved matching files");
                println!("   - Total matches: {}", files.data.len());

                for (i, file) in files.data.iter().take(5).enumerate() {
                    println!("\n   Match #{}:", i + 1);
                    if let Some(context) = &file.context_attributes {
                        if let Some(rule_name) = &context.rule_name {
                            println!("   - Matched rule: {}", rule_name);
                        }
                        if let Some(offset) = &context.match_offset {
                            println!("   - Match offset: 0x{:X}", offset);
                        }
                        if let Some(snippet) = &context.match_snippet {
                            println!("   - Match snippet: {}", &snippet[..50.min(snippet.len())]);
                        }
                        if let Some(in_subfile) = &context.match_in_subfile {
                            if *in_subfile {
                                println!("   - Match in subfile: yes");
                            }
                        }
                    }
                }
            }
            Err(e) => {
                println!("   ✗ Error getting matching files: {}", e);
                println!("   Note: Job may still be running or have no matches");
            }
        }

        // 5. Test pagination for matching files
        println!("\n5. PAGINATION TEST");
        println!("------------------");

        let mut files_iterator = retrohunt.get_matching_files_iterator(job_id);

        println!("Fetching first batch of matching files:");
        match files_iterator.next_batch().await {
            Ok(batch) => {
                println!("   ✓ Retrieved {} files in first batch", batch.len());
                for file in batch.iter().take(3) {
                    if let Some(context) = &file.context_attributes {
                        if let Some(rule) = &context.rule_name {
                            println!("   - Matched by rule: {}", rule);
                        }
                    }
                }
            }
            Err(e) => {
                println!("   ✗ Error fetching batch: {}", e);
            }
        }

        // 6. Abort a job (demonstration only)
        println!("\n6. JOB MANAGEMENT");
        println!("-----------------");

        // First check if job is still running
        match retrohunt.get_job(job_id).await {
            Ok(job) => {
                if let Some(status) = &job.object.attributes.status {
                    match status {
                        JobStatus::Starting | JobStatus::Running => {
                            println!("   Job is still running, attempting to abort...");
                            match retrohunt.abort_job(job_id).await {
                                Ok(_) => println!("   ✓ Job abort request sent"),
                                Err(e) => println!("   ✗ Error aborting job: {}", e),
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
                println!("   ✗ Error checking job status: {}", e);
            }
        }

        // 7. Clean up - delete the created job
        println!("\n7. CLEANUP");
        println!("----------");

        match retrohunt.delete_job(job_id).await {
            Ok(_) => println!("   ✓ Deleted test job"),
            Err(e) => println!("   ✗ Error deleting job: {}", e),
        }
    }

    // 8. Test wait_for_completion helper
    println!("\n8. HELPER METHODS");
    println!("-----------------");

    println!("\nTesting wait_for_completion (demonstration):");
    println!("   Note: In real usage, this would poll until job completes");

    // Create another test job for demonstration
    let wait_test_request =
        CreateRetrohuntJobRequest::new("rule QuickTest { condition: false }".to_string())
            .with_corpus(Corpus::Goodware)
            .with_start_time(now - (24 * 60 * 60)) // Last 24 hours
            .with_end_time(now);

    match retrohunt.create_job(&wait_test_request).await {
        Ok(job) => {
            println!("   ✓ Created test job for wait demonstration");
            println!("   - Job ID: {}", job.object.id);

            // Wait for completion (with short timeout for demo)
            println!("   Waiting for job completion (max 30 seconds)...");
            match retrohunt
                .wait_for_completion(&job.object.id, Some(30), Some(5))
                .await
            {
                Ok(completed_job) => {
                    println!("   ✓ Job completed!");
                    if let Some(status) = &completed_job.object.attributes.status {
                        println!("   - Final status: {:?}", status);
                    }
                    if let Some(matches) = &completed_job.object.attributes.matches {
                        println!("   - Total matches: {}", matches);
                    }
                }
                Err(e) => {
                    println!("   ✗ Error or timeout waiting for completion: {}", e);
                }
            }

            // Clean up
            let _ = retrohunt.delete_job(&job.object.id).await;
        }
        Err(e) => {
            println!("   ✗ Error creating test job: {}", e);
        }
    }

    // 9. Test filtering by status
    println!("\n9. FILTERING JOBS");
    println!("-----------------");

    let statuses = vec!["starting", "running", "finished", "aborted"];
    for status in statuses {
        let filter = format!("status:{}", status);
        match retrohunt.list_jobs(Some(&filter), Some(5), None).await {
            Ok(jobs) => {
                println!("   Jobs with status '{}': {}", status, jobs.data.len());
            }
            Err(e) => {
                println!("   ✗ Error filtering by status '{}': {}", status, e);
            }
        }
    }

    // 10. Test iterator for jobs list
    println!("\n10. JOB LIST ITERATION");
    println!("----------------------");

    let mut job_iterator = retrohunt.list_jobs_iterator(Some("status:finished"));

    println!("Fetching first batch of finished jobs:");
    match job_iterator.next_batch().await {
        Ok(batch) => {
            println!("   ✓ Retrieved {} jobs in first batch", batch.len());
            for job in batch.iter().take(3) {
                println!("   - Job {}", job.object.id);
                if let Some(matches) = &job.object.attributes.matches {
                    println!("     Matches: {}", matches);
                }
            }
        }
        Err(e) => {
            println!("   ✗ Error fetching batch: {}", e);
        }
    }

    println!("\n=================================");
    println!("Retrohunt API testing complete!");

    Ok(())
}
