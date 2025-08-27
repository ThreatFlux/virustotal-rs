use virustotal_rs::file_behaviours::FileBehaviourAttributes;
use virustotal_rs::objects::CollectionMeta;
use virustotal_rs::{ApiTier, ClientBuilder};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = setup_client()?;
    let behaviour_client = client.file_behaviours();
    let sandbox_id = get_example_sandbox_id();

    print_header();
    run_all_tests(&behaviour_client, &sandbox_id).await;
    print_completion();

    Ok(())
}

/// Setup client with API key
fn setup_client() -> Result<virustotal_rs::Client, Box<dyn std::error::Error>> {
    let api_key = std::env::var("VT_API_KEY").unwrap_or_else(|_| "test_key".to_string());

    Ok(ClientBuilder::new()
        .api_key(api_key)
        .tier(ApiTier::Public)
        .build()?)
}

/// Get example sandbox ID
fn get_example_sandbox_id() -> String {
    "5353e23f3653402339c93a8565307c6308ff378e03fcf23a4378f31c434030b0_VirusTotal Jujubox"
        .to_string()
}

/// Print application header
fn print_header() {
    println!("Testing FileBehaviour API methods:");
    println!("===================================");
}

/// Run all test scenarios
async fn run_all_tests(
    behaviour_client: &virustotal_rs::FileBehaviourClient<'_>,
    sandbox_id: &str,
) {
    test_get_behaviour_report(behaviour_client, sandbox_id).await;
    test_get_html_report(behaviour_client, sandbox_id).await;
    test_get_privileged_files(behaviour_client, sandbox_id).await;
    test_get_relationships(behaviour_client, sandbox_id).await;
}

/// Test getting behaviour report
async fn test_get_behaviour_report(
    behaviour_client: &virustotal_rs::FileBehaviourClient<'_>,
    sandbox_id: &str,
) {
    println!("\n1. Getting behaviour report for sandbox: {}", sandbox_id);

    match behaviour_client.get(sandbox_id).await {
        Ok(behaviour) => {
            print_behaviour_success(&behaviour);
            display_behaviour_attributes(&behaviour.object.attributes);
        }
        Err(e) => println!("   ✗ Error: {}", e),
    }
}

/// Print successful behaviour retrieval
fn print_behaviour_success(behaviour: &virustotal_rs::FileBehaviour) {
    println!("   ✓ Successfully retrieved behaviour report");
    println!("   - Sandbox: {:?}", behaviour.object.attributes.sandbox);
}

/// Display behaviour attributes
fn display_behaviour_attributes(attributes: &FileBehaviourAttributes) {
    println!("   - Has HTML report: {:?}", attributes.has_html_report);
    println!("   - Has PCAP: {:?}", attributes.has_pcap);
    println!("   - Has EVTX: {:?}", attributes.has_evtx);
    println!("   - Has memdump: {:?}", attributes.has_memdump);
}

/// Test getting HTML report
async fn test_get_html_report(
    behaviour_client: &virustotal_rs::FileBehaviourClient<'_>,
    sandbox_id: &str,
) {
    println!("\n2. Getting HTML report:");

    match behaviour_client.get_html_report(sandbox_id).await {
        Ok(html) => {
            println!("   ✓ Successfully retrieved HTML report");
            println!("   - Report size: {} bytes", html.len());
        }
        Err(e) => println!("   ✗ Error: {}", e),
    }
}

/// Test getting privileged files (PCAP, EVTX, memdump)
async fn test_get_privileged_files(
    behaviour_client: &virustotal_rs::FileBehaviourClient<'_>,
    sandbox_id: &str,
) {
    test_get_pcap(behaviour_client, sandbox_id).await;
    test_get_evtx(behaviour_client, sandbox_id).await;
    test_get_memdump(behaviour_client, sandbox_id).await;
}

/// Test getting PCAP file
async fn test_get_pcap(
    behaviour_client: &virustotal_rs::FileBehaviourClient<'_>,
    sandbox_id: &str,
) {
    println!("\n3. Getting PCAP file (requires special privileges):");

    match behaviour_client.get_pcap(sandbox_id).await {
        Ok(pcap_data) => {
            println!("   ✓ Successfully retrieved PCAP file");
            display_pcap_info(&pcap_data);
        }
        Err(e) => print_privilege_error("PCAP", &e),
    }
}

/// Display PCAP file information
fn display_pcap_info(pcap_data: &[u8]) {
    println!("   - PCAP size: {} bytes", pcap_data.len());
    if pcap_data.len() >= 4 {
        let magic = &pcap_data[0..4];
        println!(
            "   - PCAP magic number: {:02X} {:02X} {:02X} {:02X}",
            magic[0], magic[1], magic[2], magic[3]
        );
    }
}

/// Test getting EVTX file
async fn test_get_evtx(
    behaviour_client: &virustotal_rs::FileBehaviourClient<'_>,
    sandbox_id: &str,
) {
    println!("\n4. Getting EVTX file (requires special privileges):");

    match behaviour_client.get_evtx(sandbox_id).await {
        Ok(evtx_data) => {
            println!("   ✓ Successfully retrieved EVTX file");
            println!("   - EVTX size: {} bytes", evtx_data.len());
        }
        Err(e) => print_privilege_error("EVTX", &e),
    }
}

/// Test getting memdump file
async fn test_get_memdump(
    behaviour_client: &virustotal_rs::FileBehaviourClient<'_>,
    sandbox_id: &str,
) {
    println!("\n5. Getting memdump file (requires special privileges):");

    match behaviour_client.get_memdump(sandbox_id).await {
        Ok(memdump_data) => {
            println!("   ✓ Successfully retrieved memdump file");
            display_memdump_info(&memdump_data);
        }
        Err(e) => print_privilege_error("memdump", &e),
    }
}

/// Display memory dump information
fn display_memdump_info(memdump_data: &[u8]) {
    println!("   - Memdump size: {} bytes", memdump_data.len());
    if memdump_data.len() >= 2 {
        let sig = &memdump_data[0..2];
        println!(
            "   - PE signature check: {:02X}{:02X} (MZ expected)",
            sig[0], sig[1]
        );
    }
}

/// Print privilege error message
fn print_privilege_error(file_type: &str, error: &virustotal_rs::Error) {
    println!("   ✗ Error (expected if no special privileges): {}", error);
    println!(
        "   Note: {} file access requires special permissions",
        file_type
    );
}

/// Test getting related objects
async fn test_get_relationships(
    behaviour_client: &virustotal_rs::FileBehaviourClient<'_>,
    sandbox_id: &str,
) {
    test_get_contacted_domains(behaviour_client, sandbox_id).await;
    test_get_dropped_files(behaviour_client, sandbox_id).await;
}

/// Test getting contacted domains
async fn test_get_contacted_domains(
    behaviour_client: &virustotal_rs::FileBehaviourClient<'_>,
    sandbox_id: &str,
) {
    println!("\n6. Getting related contacted domains:");

    match behaviour_client.get_contacted_domains(sandbox_id).await {
        Ok(domains) => {
            println!("   ✓ Successfully retrieved contacted domains");
            display_relationship_count(&domains.meta, "contacted domains");
        }
        Err(e) => println!("   ✗ Error: {}", e),
    }
}

/// Test getting dropped files
async fn test_get_dropped_files(
    behaviour_client: &virustotal_rs::FileBehaviourClient<'_>,
    sandbox_id: &str,
) {
    println!("\n7. Getting dropped files:");

    match behaviour_client.get_dropped_files(sandbox_id).await {
        Ok(files) => {
            println!("   ✓ Successfully retrieved dropped files");
            display_relationship_count(&files.meta, "dropped files");
        }
        Err(e) => println!("   ✗ Error: {}", e),
    }
}

/// Display relationship count from metadata
fn display_relationship_count(meta: &Option<CollectionMeta>, relationship_type: &str) {
    if let Some(meta) = meta {
        if let Some(count) = meta.count {
            println!("   - Number of {}: {}", relationship_type, count);
        }
    }
}

/// Print completion message
fn print_completion() {
    println!("\n===================================");
    println!("File Behaviour API testing complete!");
}
