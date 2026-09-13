//! Integration test against a real `roamswitch-mcp` binary.
//!
//! Skips (with a printed note) rather than failing if `roamswitch-mcp` isn't
//! installed on the machine running the tests — CI without RoamSwitch
//! installed, or a contributor's dev box, should still pass `cargo test`.

use roamswitch_linux_kit::RoamSwitchClient;
use std::path::PathBuf;

#[tokio::test]
async fn test_roamswitch_client() {
    // `ROAMSWITCH_MCP_TEST_BIN` is a local-dev-only override (e.g. a sibling
    // `roamswitch-linux` checkout's freshly built binary) so this test can
    // exercise new tools before a packaged `/usr/bin/roamswitch-mcp` catches
    // up. Not read by any non-test code.
    let candidate_paths: Vec<PathBuf> = std::env::var("ROAMSWITCH_MCP_TEST_BIN")
        .map(PathBuf::from)
        .into_iter()
        .chain([
            PathBuf::from("/usr/bin/roamswitch-mcp"),
            PathBuf::from("/usr/local/bin/roamswitch-mcp"),
        ])
        .collect();

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

    // Server Edition only — legitimately empty on a Client Edition host.
    let rg = client.get_resource_guard_incidents().await.expect("get_resource_guard_incidents");
    println!("Resource guard: {} incident(s)", rg.incidents.len());

    let fsg = client.get_file_scan_guard_status().await.expect("get_file_scan_guard_status");
    assert!(!fsg.quarantine.quarantine_directory.is_empty());

    let notifications = client.notification_history().await.expect("notification_history");
    println!("Notifications (7 days): {}", notifications.len());

    let timeline = client.get_incident_timeline().await.expect("get_incident_timeline");
    println!("Timeline: {} event(s)", timeline.len());

    // A directory scan of an empty temp dir: well-formed, no leaks.
    let tmp = std::env::temp_dir().join(format!("roamswitch-linux-kit-test-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).expect("temp dir");
    match client.audit_secrets_path(&tmp).await.expect("audit_secrets_path") {
        roamswitch_linux_kit::SecretPathAuditResult::Directory(d) => assert!(!d.has_leaks),
        other => panic!("expected a directory result, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&tmp);

    // Client Edition runtime status. Every one must succeed and carry a
    // non-empty localized summary, whether or not the daemon is running.
    let vpn = client.vpn_status().await.expect("vpn_status");
    assert!(vpn.backend == "wireguard" || vpn.backend == "tailscale");
    assert!(!vpn.summary.is_empty());

    let lg = client.link_guard_status().await.expect("link_guard_status");
    assert!(["off", "warn", "block"].contains(&lg.effective_mode.as_str()));
    assert!(!lg.summary.is_empty());

    let ag = client.air_gap_status().await.expect("air_gap_status");
    assert!(ag.auto_release_after_secs > 0);
    println!("Air-Gap: active={}, frozen={}", ag.active, ag.frozen_processes.len());

    let sharing = client.sharing_services_status().await.expect("sharing_services_status");
    assert!(!sharing.summary.is_empty());

    let bt = client.bluetooth_guard_status().await.expect("bluetooth_guard_status");
    assert_eq!(bt.controller.is_shielded_on_untrusted, bt.guard_enabled);

    let usb = client.usb_guard_status().await.expect("usb_guard_status");
    assert!(!usb.summary.is_empty());
}
