//! Integration test against a real `roamswitch-mcp` binary.
//!
//! Skips (with a printed note) rather than failing if `roamswitch-mcp` isn't
//! installed on the machine running the tests — CI without RoamSwitch
//! installed, or a contributor's dev box, should still pass `cargo test`.

use roamswitch_linux_kit::RoamSwitchClient;
use std::path::PathBuf;

#[tokio::test]
async fn test_roamswitch_client() {
    let candidate_paths = [
        PathBuf::from("/usr/bin/roamswitch-mcp"),
        PathBuf::from("/usr/local/bin/roamswitch-mcp"),
    ];

    let binary_path = candidate_paths.into_iter().find(|p| p.exists());

    let Some(bin) = binary_path else {
        println!("roamswitch-mcp binary not found, skipping client integration test");
        return;
    };

    let client = RoamSwitchClient::new(Some(bin), None).expect("client creation");

    let report = client.security_report().await.expect("security_report");
    println!("Report score: {} ({})", report.score, report.grade);
    assert!(report.total_checks > 0);

    let ports = client.exposed_ports(true).await.expect("exposed_ports");
    println!("Ports count: {}", ports.ports.len());

    let guard = client.guard_status().await.expect("guard_status");
    assert!(!guard.guards.is_empty());

    let url_report = client
        .audit_url_safety("https://www.google.com")
        .await
        .expect("audit_url_safety");
    assert_eq!(url_report.risk_level, "safe");

    let secret_report = client
        .audit_secrets("export OPENAI_API_KEY=sk-1234567890abcdef1234567890abcdef")
        .await
        .expect("audit_secrets");
    assert!(secret_report.has_leaks);

    let logs = client.audit_security_logs(24).await.expect("audit_security_logs");
    assert_eq!(logs.hours, 24);

    let help = client
        .get_app_help(Some("nftables"), None)
        .await
        .expect("get_app_help");
    assert!(help.total_results >= 1);

    let q_status = client.quarantine_status().await.expect("quarantine_status");
    assert!(!q_status.quarantine_directory.is_empty());

    let c_status = client.canary_status().await.expect("canary_status");
    assert!(c_status.monitored_files_count > 0);

    // The embedded CVE map baseline can legitimately ship as an empty seed
    // until the daily updater installs real data, so only assert the call
    // succeeds and returns a well-formed result.
    let pkg_cve = client.package_cve_scan().await.expect("package_cve_scan");
    println!("Package CVE scan: map_installed={}, {} finding(s)", pkg_cve.map_installed, pkg_cve.findings.len());

    let lang_cve = client
        .package_cve_scan_languages(&[])
        .await
        .expect("package_cve_scan_languages");
    assert_eq!(lang_cve.scanned_folder_count, 0);
    assert!(lang_cve.findings.is_empty());

    // A baseline may not exist yet on this host (never `sudo roamswitch fim
    // update`'d) — verify_fim() errors rather than fabricating a report,
    // which is a legitimate outcome, not a bug, so tolerate either result.
    match client.verify_fim().await {
        Ok(report) => assert!(report.total_monitored > 0),
        Err(e) => println!("verify_fim returned an error (no baseline provisioned?): {e}"),
    }

    // The daemon may not have run a scan yet on this host, which is a
    // legitimate empty-default state, not an error.
    let pa = client.get_port_anomaly_incidents().await.expect("get_port_anomaly_incidents");
    println!("Port anomaly: baseline_captured={}, {} incident(s)", pa.baseline_captured, pa.incidents.len());

    // Server Edition only — a Client Edition host has no server-daemon, so
    // this legitimately returns an all-empty "not isolated" default.
    let ebpf = client.get_ebpf_incidents().await.expect("get_ebpf_incidents");
    assert!(!ebpf.current_status.is_isolated);
    println!("eBPF: {} incident(s), isolated={}", ebpf.incidents.len(), ebpf.current_status.is_isolated);
}
