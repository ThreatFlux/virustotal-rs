// Helper functions needed by this module
fn print_error(message: &str) {
    println!("❌ {}", message);
}

fn print_success(message: &str) {
    println!("✅ {}", message);
}

fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len])
    } else {
        s.to_string()
    }
}
use virustotal_rs::RetrohuntMatchingFile;

/// Display detailed information about a single matching file
pub fn display_file_context(file: &RetrohuntMatchingFile, match_number: usize) {
    println!("\n   Match #{}:", match_number + 1);

    if let Some(context) = &file.context_attributes {
        display_rule_name(context);
        display_match_offset(context);
        display_match_snippet(context);
        display_subfile_status(context);
    }
}

/// Display the rule name if available
fn display_rule_name(context: &virustotal_rs::MatchingFileContext) {
    if let Some(rule_name) = &context.rule_name {
        println!("   - Matched rule: {}", rule_name);
    }
}

/// Display the match offset if available
fn display_match_offset(context: &virustotal_rs::MatchingFileContext) {
    if let Some(offset) = &context.match_offset {
        println!("   - Match offset: 0x{:X}", offset);
    }
}

/// Display the match snippet if available
fn display_match_snippet(context: &virustotal_rs::MatchingFileContext) {
    if let Some(snippet) = &context.match_snippet {
        println!("   - Match snippet: {}", truncate_string(snippet, 50));
    }
}

/// Display whether the match was in a subfile
fn display_subfile_status(context: &virustotal_rs::MatchingFileContext) {
    if let Some(in_subfile) = &context.match_in_subfile {
        if *in_subfile {
            println!("   - Match in subfile: yes");
        }
    }
}

/// Display matching files information (full details for up to 5 files)
pub fn display_matching_files(files: &[RetrohuntMatchingFile]) {
    for (i, file) in files.iter().take(5).enumerate() {
        display_file_context(file, i);
    }
}

/// Display brief information about matching files in a batch
pub fn display_matching_files_batch(batch: &[RetrohuntMatchingFile]) {
    for file in batch.iter().take(3) {
        display_batch_file_rule(file);
    }
}

/// Display rule information for a file in a batch
fn display_batch_file_rule(file: &RetrohuntMatchingFile) {
    if let Some(context) = &file.context_attributes {
        if let Some(rule) = &context.rule_name {
            println!("   - Matched by rule: {}", rule);
        }
    }
}

/// Handle the result of retrieving a batch of matching files
pub fn handle_pagination_batch_result(
    result: Result<Vec<RetrohuntMatchingFile>, virustotal_rs::Error>,
) {
    match result {
        Ok(batch) => {
            print_success(&format!("Retrieved {} files in first batch", batch.len()));
            display_matching_files_batch(&batch);
        }
        Err(e) => {
            print_error(&format!("Error fetching batch: {}", e));
        }
    }
}

/// Handle the main matching files retrieval result
pub fn handle_matching_files_result(
    result: Result<virustotal_rs::Collection<RetrohuntMatchingFile>, virustotal_rs::Error>,
) {
    match result {
        Ok(files) => {
            print_success("Retrieved matching files");
            println!("   - Total matches: {}", files.data.len());
            display_matching_files(&files.data);
        }
        Err(e) => {
            print_error(&format!("Error getting matching files: {}", e));
            println!("   Note: Job may still be running or have no matches");
        }
    }
}

#[allow(dead_code)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("This is a utility module for matching files operations.");
    println!("It provides helper functions for displaying retrohunt matching files.");
    println!("This module is used by other examples like test_retrohunt.rs");
    Ok(())
}
