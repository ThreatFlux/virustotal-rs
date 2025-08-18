use virustotal_rs::{ApiTier, ClientBuilder};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_key = std::env::var("VT_API_KEY").unwrap_or_else(|_| "test_key".to_string());

    let client = ClientBuilder::new()
        .api_key(api_key)
        .tier(ApiTier::Public)
        .build()?;

    let behaviour_client = client.file_behaviours();

    // Example sandbox ID (format: sha256_sandboxname)
    let sandbox_id =
        "5353e23f3653402339c93a8565307c6308ff378e03fcf23a4378f31c434030b0_VirusTotal Jujubox";

    println!("Testing FileBehaviour API methods:");
    println!("===================================");

    // Test getting behaviour report
    println!("\n1. Getting behaviour report for sandbox: {}", sandbox_id);
    match behaviour_client.get(sandbox_id).await {
        Ok(behaviour) => {
            println!("   ✓ Successfully retrieved behaviour report");
            println!("   - Sandbox: {:?}", behaviour.object.attributes.sandbox);
            println!(
                "   - Has HTML report: {:?}",
                behaviour.object.attributes.has_html_report
            );
            println!("   - Has PCAP: {:?}", behaviour.object.attributes.has_pcap);
            println!("   - Has EVTX: {:?}", behaviour.object.attributes.has_evtx);
            println!(
                "   - Has memdump: {:?}",
                behaviour.object.attributes.has_memdump
            );
        }
        Err(e) => println!("   ✗ Error: {}", e),
    }

    // Test getting HTML report
    println!("\n2. Getting HTML report:");
    match behaviour_client.get_html_report(sandbox_id).await {
        Ok(html) => {
            println!("   ✓ Successfully retrieved HTML report");
            println!("   - Report size: {} bytes", html.len());
        }
        Err(e) => println!("   ✗ Error: {}", e),
    }

    // Test getting PCAP file (requires special privileges)
    println!("\n3. Getting PCAP file (requires special privileges):");
    match behaviour_client.get_pcap(sandbox_id).await {
        Ok(pcap_data) => {
            println!("   ✓ Successfully retrieved PCAP file");
            println!("   - PCAP size: {} bytes", pcap_data.len());
            if pcap_data.len() >= 4 {
                let magic = &pcap_data[0..4];
                println!(
                    "   - PCAP magic number: {:02X} {:02X} {:02X} {:02X}",
                    magic[0], magic[1], magic[2], magic[3]
                );
            }
        }
        Err(e) => println!("   ✗ Error (expected if no special privileges): {}", e),
    }

    // Test getting EVTX file (requires special privileges)
    println!("\n4. Getting EVTX file (requires special privileges):");
    match behaviour_client.get_evtx(sandbox_id).await {
        Ok(evtx_data) => {
            println!("   ✓ Successfully retrieved EVTX file");
            println!("   - EVTX size: {} bytes", evtx_data.len());
        }
        Err(e) => println!("   ✗ Error (expected if no special privileges): {}", e),
    }

    // Test getting memdump file (requires special privileges)
    println!("\n5. Getting memdump file (requires special privileges):");
    match behaviour_client.get_memdump(sandbox_id).await {
        Ok(memdump_data) => {
            println!("   ✓ Successfully retrieved memdump file");
            println!("   - Memdump size: {} bytes", memdump_data.len());
            if memdump_data.len() >= 2 {
                let sig = &memdump_data[0..2];
                println!(
                    "   - PE signature check: {:02X}{:02X} (MZ expected)",
                    sig[0], sig[1]
                );
            }
        }
        Err(e) => println!("   ✗ Error (expected if no special privileges): {}", e),
    }

    // Test getting related objects
    println!("\n6. Getting related contacted domains:");
    match behaviour_client.get_contacted_domains(sandbox_id).await {
        Ok(domains) => {
            println!("   ✓ Successfully retrieved contacted domains");
            if let Some(meta) = &domains.meta {
                if let Some(count) = meta.count {
                    println!("   - Number of contacted domains: {}", count);
                }
            }
        }
        Err(e) => println!("   ✗ Error: {}", e),
    }

    // Test getting dropped files
    println!("\n7. Getting dropped files:");
    match behaviour_client.get_dropped_files(sandbox_id).await {
        Ok(files) => {
            println!("   ✓ Successfully retrieved dropped files");
            if let Some(meta) = &files.meta {
                if let Some(count) = meta.count {
                    println!("   - Number of dropped files: {}", count);
                }
            }
        }
        Err(e) => println!("   ✗ Error: {}", e),
    }

    println!("\n===================================");
    println!("File Behaviour API testing complete!");

    Ok(())
}
