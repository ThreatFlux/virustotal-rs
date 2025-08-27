#[cfg(test)]
mod unit_tests {
    use crate::objects::Object;
    use crate::private_files::*;
    use std::collections::HashMap;

    #[test]
    fn test_private_file_attributes() {
        let attrs = PrivateFileAttributes {
            sha256: Some("abc123".to_string()),
            sha1: Some("def456".to_string()),
            md5: Some("ghi789".to_string()),
            size: Some(1024),
            type_description: Some("PE32 executable".to_string()),
            magic: Some("PE32".to_string()),
            tags: Some(vec!["malware".to_string()]),
            status: Some("completed".to_string()),
            first_submission_date: Some(1234567890),
            last_analysis_date: Some(1234567890),
            last_analysis_results: None,
            last_analysis_stats: None,
            reputation: Some(-50),
            additional_attributes: HashMap::new(),
        };

        assert_eq!(attrs.sha256.unwrap(), "abc123");
        assert_eq!(attrs.size.unwrap(), 1024);
        assert_eq!(attrs.reputation.unwrap(), -50);
    }

    #[test]
    fn test_analysis_stats() {
        let stats = AnalysisStats {
            malicious: Some(45),
            suspicious: Some(5),
            undetected: Some(20),
            failure: Some(2),
            timeout: Some(1),
            type_unsupported: Some(0),
        };

        assert_eq!(stats.malicious.unwrap(), 45);
        assert_eq!(stats.suspicious.unwrap(), 5);
        assert_eq!(stats.undetected.unwrap(), 20);
    }

    #[test]
    fn test_engine_result() {
        let result = EngineResult {
            category: Some("malicious".to_string()),
            engine_name: Some("TestEngine".to_string()),
            engine_version: Some("1.0.0".to_string()),
            result: Some("Trojan.Generic".to_string()),
            method: Some("signature".to_string()),
            engine_update: Some("20240101".to_string()),
        };

        assert_eq!(result.category.unwrap(), "malicious");
        assert_eq!(result.result.unwrap(), "Trojan.Generic");
    }

    #[test]
    fn test_upload_params() {
        let params = PrivateFileUploadParams::new()
            .disable_sandbox(true)
            .enable_internet(false)
            .command_line("/c calc.exe".to_string())
            .retention_period_days(7)
            .storage_region("EU".to_string())
            .locale("EN_US".to_string());

        assert_eq!(params.disable_sandbox, Some(true));
        assert_eq!(params.enable_internet, Some(false));
        assert_eq!(params.command_line, Some("/c calc.exe".to_string()));
        assert_eq!(params.retention_period_days, Some(7));
        assert_eq!(params.storage_region, Some("EU".to_string()));
        assert_eq!(params.locale, Some("EN_US".to_string()));
    }

    #[test]
    fn test_reanalyze_params() {
        let params = ReanalyzeParams::new()
            .disable_sandbox(false)
            .enable_internet(true)
            .interaction_sandbox("cape".to_string())
            .interaction_timeout(120);

        assert_eq!(params.disable_sandbox, Some(false));
        assert_eq!(params.enable_internet, Some(true));
        assert_eq!(params.interaction_sandbox, Some("cape".to_string()));
        assert_eq!(params.interaction_timeout, Some(120));
    }

    #[test]
    fn test_param_limits() {
        // Test retention period limits
        let params1 = PrivateFileUploadParams::new().retention_period_days(100);
        assert_eq!(params1.retention_period_days, Some(28)); // Capped at 28

        let params2 = PrivateFileUploadParams::new().retention_period_days(0);
        assert_eq!(params2.retention_period_days, Some(1)); // Minimum 1

        // Test interaction timeout limits
        let params3 = ReanalyzeParams::new().interaction_timeout(2000);
        assert_eq!(params3.interaction_timeout, Some(1800)); // Capped at 1800

        let params4 = ReanalyzeParams::new().interaction_timeout(30);
        assert_eq!(params4.interaction_timeout, Some(60)); // Minimum 60
    }

    #[test]
    fn test_dropped_file_attributes() {
        let attrs = DroppedFileAttributes {
            sha256: Some("dropped123".to_string()),
            path: Some("C:\\Windows\\Temp\\dropped.exe".to_string()),
            size: Some(2048),
            type_description: Some("PE32 executable".to_string()),
            additional_attributes: HashMap::new(),
        };

        assert_eq!(attrs.sha256.unwrap(), "dropped123");
        assert_eq!(attrs.path.unwrap(), "C:\\Windows\\Temp\\dropped.exe");
        assert_eq!(attrs.size.unwrap(), 2048);
    }

    #[test]
    fn test_private_analysis_attributes() {
        let attrs = PrivateAnalysisAttributes {
            status: Some("completed".to_string()),
            stats: Some(AnalysisStats {
                malicious: Some(30),
                suspicious: Some(10),
                undetected: Some(40),
                failure: Some(0),
                timeout: Some(0),
                type_unsupported: Some(0),
            }),
            results: None,
            date: Some(1234567890),
            additional_attributes: HashMap::new(),
        };

        assert_eq!(attrs.status.unwrap(), "completed");
        assert!(attrs.stats.is_some());
        let stats = attrs.stats.unwrap();
        assert_eq!(stats.malicious.unwrap(), 30);
    }

    #[test]
    fn test_private_file_upload_response() {
        let response = PrivateFileUploadResponse {
            data: PrivateFileUploadData {
                object_type: "analysis".to_string(),
                id: "analysis_123".to_string(),
                links: Some(PrivateFileUploadLinks {
                    self_link: "/api/v3/analyses/analysis_123".to_string(),
                }),
            },
        };

        assert_eq!(response.data.object_type, "analysis");
        assert_eq!(response.data.id, "analysis_123");
        assert!(response.data.links.is_some());
    }

    #[test]
    fn test_private_file_serialization() {
        let file = PrivateFile {
            object: Object {
                id: "test_hash".to_string(),
                object_type: "file".to_string(),
                links: None,
                relationships: None,
                attributes: PrivateFileAttributes {
                    sha256: Some("abc123".to_string()),
                    sha1: Some("def456".to_string()),
                    md5: Some("ghi789".to_string()),
                    size: Some(1024),
                    type_description: Some("PE32 executable".to_string()),
                    magic: Some("PE32".to_string()),
                    tags: Some(vec!["malware".to_string()]),
                    status: Some("completed".to_string()),
                    first_submission_date: Some(1234567890),
                    last_analysis_date: Some(1234567891),
                    last_analysis_results: None,
                    last_analysis_stats: None,
                    reputation: Some(-50),
                    additional_attributes: HashMap::new(),
                },
            },
        };

        // Test serialization
        let json = serde_json::to_string(&file).unwrap();
        assert!(json.contains("\"sha256\":\"abc123\""));
        assert!(json.contains("\"size\":1024"));

        // Test deserialization
        let deserialized: PrivateFile = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.object.id, "test_hash");
        assert_eq!(
            deserialized.object.attributes.sha256,
            Some("abc123".to_string())
        );
    }

    #[test]
    fn test_engine_results_map() {
        let mut results = HashMap::new();

        results.insert(
            "TestEngine1".to_string(),
            EngineResult {
                category: Some("malicious".to_string()),
                engine_name: Some("TestEngine1".to_string()),
                engine_version: Some("1.0".to_string()),
                result: Some("Trojan.Generic".to_string()),
                method: Some("signature".to_string()),
                engine_update: Some("20240101".to_string()),
            },
        );

        results.insert(
            "TestEngine2".to_string(),
            EngineResult {
                category: Some("undetected".to_string()),
                engine_name: Some("TestEngine2".to_string()),
                engine_version: Some("2.0".to_string()),
                result: None,
                method: Some("heuristic".to_string()),
                engine_update: Some("20240102".to_string()),
            },
        );

        assert_eq!(results.len(), 2);
        assert!(results.contains_key("TestEngine1"));
        assert_eq!(
            results.get("TestEngine1").unwrap().result.as_ref().unwrap(),
            "Trojan.Generic"
        );
    }

    #[test]
    fn test_analysis_stats_calculation() {
        let stats = AnalysisStats {
            malicious: Some(45),
            suspicious: Some(5),
            undetected: Some(20),
            failure: Some(2),
            timeout: Some(1),
            type_unsupported: Some(0),
        };

        // Calculate total
        let total = stats.malicious.unwrap_or(0)
            + stats.suspicious.unwrap_or(0)
            + stats.undetected.unwrap_or(0)
            + stats.failure.unwrap_or(0)
            + stats.timeout.unwrap_or(0)
            + stats.type_unsupported.unwrap_or(0);

        assert_eq!(total, 73);

        // Calculate detection rate
        let detections = stats.malicious.unwrap_or(0) + stats.suspicious.unwrap_or(0);
        let valid_scans = detections + stats.undetected.unwrap_or(0);
        let detection_rate = (detections as f64 / valid_scans as f64) * 100.0;

        assert!(detection_rate > 71.0 && detection_rate < 72.0);
    }

    #[test]
    fn test_upload_url_response() {
        let response = UploadUrlResponse {
            data: "https://upload.virustotal.com/private/upload/abc123".to_string(),
        };

        assert!(response.data.starts_with("https://"));
        assert!(response.data.contains("upload"));
    }

    #[test]
    fn test_create_private_zip_request() {
        let request = CreatePrivateZipRequest::new(vec![
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string(),
        ]);

        assert_eq!(request.data.hashes.len(), 2);
        assert!(request.data.password.is_none());
    }

    #[test]
    fn test_create_private_zip_with_password() {
        let request = CreatePrivateZipRequest::new_with_password(
            vec!["abc123".to_string()],
            "mysecretpassword".to_string(),
        );

        assert_eq!(request.data.hashes.len(), 1);
        assert_eq!(request.data.password.unwrap(), "mysecretpassword");
    }

    #[test]
    fn test_private_zip_builder_methods() {
        let request = CreatePrivateZipRequest::new(vec!["hash1".to_string()])
            .with_password("password123".to_string())
            .add_hash("hash2".to_string())
            .add_hashes(vec!["hash3".to_string(), "hash4".to_string()]);

        assert_eq!(request.data.hashes.len(), 4);
        assert_eq!(request.data.password.unwrap(), "password123");
    }

    #[test]
    fn test_private_zip_status_values() {
        let statuses = vec![
            "starting",
            "creating",
            "finished",
            "timeout",
            "error-starting",
            "error-creating",
        ];

        for status in statuses {
            let attrs = PrivateZipFileAttributes {
                status: status.to_string(),
                progress: 0,
                files_ok: 0,
                files_error: 0,
            };

            assert_eq!(attrs.status, status);
        }
    }

    #[tokio::test]
    async fn test_private_zip_operations() {
        use crate::{ApiTier, ClientBuilder};

        let client = ClientBuilder::new()
            .api_key("test_key")
            .tier(ApiTier::Premium)
            .build()
            .unwrap();

        let private_files = client.private_files();

        // Test create ZIP
        let request =
            CreatePrivateZipRequest::new(vec!["test_hash1".to_string(), "test_hash2".to_string()])
                .with_password("test_password".to_string());

        let result = private_files.create_zip(&request).await;
        assert!(result.is_err()); // Will fail without valid API key

        // Test get ZIP status
        let status_result = private_files.get_zip_status("test_zip_id").await;
        assert!(status_result.is_err());

        // Test get download URL
        let url_result = private_files.get_zip_download_url("test_zip_id").await;
        assert!(url_result.is_err());

        // Test download ZIP
        let download_result = private_files.download_zip("test_zip_id").await;
        assert!(download_result.is_err());
    }

    #[test]
    fn test_sha256_only_requirement() {
        // Test that we're documenting SHA-256 only requirement
        let valid_sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        let invalid_md5 = "e5828c564f71fea3a12dde8bd5d27063";
        let invalid_sha1 = "7bae8076a5771865123be7112468b79e9d78a640";

        assert_eq!(valid_sha256.len(), 64); // SHA-256 is 64 hex chars
        assert_eq!(invalid_md5.len(), 32); // MD5 is 32 hex chars
        assert_eq!(invalid_sha1.len(), 40); // SHA-1 is 40 hex chars
    }

    #[test]
    fn test_private_analysis_response() {
        let response = PrivateAnalysisResponse {
            data: PrivateAnalysis {
                object: Object {
                    id: "analysis_123".to_string(),
                    object_type: "private_analysis".to_string(),
                    links: None,
                    relationships: None,
                    attributes: PrivateAnalysisAttributes {
                        status: Some("completed".to_string()),
                        stats: None,
                        results: None,
                        date: Some(1620127014),
                        additional_attributes: HashMap::new(),
                    },
                },
            },
            meta: Some(PrivateAnalysisMeta {
                file_info: Some(FileInfo {
                    size: Some(5),
                    sha256: Some(
                        "11a77c3d96c06974b53d7f40a577e6813739eb5c811b2a86f59038ea90add772"
                            .to_string(),
                    ),
                    sha1: Some("7bae8076a5771865123be7112468b79e9d78a640".to_string()),
                    md5: Some("e5828c564f71fea3a12dde8bd5d27063".to_string()),
                }),
            }),
        };

        assert_eq!(response.data.object.attributes.status.unwrap(), "completed");
        assert!(response.meta.is_some());
        let meta = response.meta.unwrap();
        assert!(meta.file_info.is_some());
        let file_info = meta.file_info.unwrap();
        assert_eq!(file_info.size.unwrap(), 5);
        assert_eq!(file_info.sha256.unwrap().len(), 64);
    }

    #[test]
    fn test_private_file_behavior() {
        let behavior = PrivateFileBehavior {
            object: Object {
                id: "sandbox_123".to_string(),
                object_type: "private_file_behaviour".to_string(),
                links: None,
                relationships: None,
                attributes: PrivateFileBehaviorAttributes {
                    behash: Some("3f4a02b305dde56c7c606849289bb194".to_string()),
                    calls_highlighted: Some(vec!["GetTickCount".to_string()]),
                    files_opened: Some(vec!["C:\\Windows\\system32\\ws2_32.dll".to_string()]),
                    has_html_report: Some(true),
                    has_pcap: Some(true),
                    modules_loaded: Some(vec!["UxTheme.dll".to_string()]),
                    processes_tree: Some(vec![ProcessInfo {
                        name: Some("malware.exe".to_string()),
                        process_id: Some("2340".to_string()),
                    }]),
                    registry_keys_opened: Some(vec!["HKCU\\Software\\Test".to_string()]),
                    sandbox_name: Some("`VirusTotal` Jujubox".to_string()),
                    tags: Some(vec!["DIRECT_CPU_CLOCK_ACCESS".to_string()]),
                    text_highlighted: Some(vec!["PuTTY Configuration".to_string()]),
                    mutexes_created: Some(vec!["TestMutex".to_string()]),
                    mutexes_opened: Some(vec!["ShimCacheMutex".to_string()]),
                    processes_terminated: Some(vec!["C:\\Temp\\test.exe".to_string()]),
                    additional_attributes: HashMap::new(),
                },
            },
        };

        assert!(behavior.object.attributes.has_html_report.unwrap());
        assert!(behavior.object.attributes.has_pcap.unwrap());
        assert_eq!(
            behavior.object.attributes.sandbox_name.unwrap(),
            "`VirusTotal` Jujubox"
        );
        assert_eq!(behavior.object.attributes.processes_tree.unwrap().len(), 1);
    }
}
