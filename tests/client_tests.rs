//! Integration test against a real `roamswitch-mcp` binary.
//!
//! Skips (with a printed note) rather than failing if `roamswitch-mcp` isn't
//! installed on the machine running the tests — CI without RoamSwitch
//! installed, or a contributor's dev box, should still pass `cargo test`.

use roamswitch_linux_kit::{ExecEventQuery, RoamSwitchClient, RoamSwitchClientError};
use std::path::PathBuf;

/// `ROAMSWITCH_MCP_TEST_BIN` is a local-dev-only override (e.g. a sibling
/// `roamswitch-linux` checkout's freshly built binary) so these tests can
/// exercise new tools before a packaged `/usr/bin/roamswitch-mcp` catches
/// up. Not read by any non-test code.
fn find_binary() -> Option<PathBuf> {
    std::env::var("ROAMSWITCH_MCP_TEST_BIN")
        .map(PathBuf::from)
        .into_iter()
        .chain([
            PathBuf::from("/usr/bin/roamswitch-mcp"),
            PathBuf::from("/usr/local/bin/roamswitch-mcp"),
        ])
        .find(|p| p.exists())
}

#[tokio::test]
async fn test_roamswitch_client() {
    let Some(bin) = find_binary() else {
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

    let logs = client
        .audit_security_logs(24)
        .await
        .expect("audit_security_logs");
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
    println!(
        "Package CVE scan: map_installed={}, {} finding(s)",
        pkg_cve.map_installed,
        pkg_cve.findings.len()
    );

    let lang_cve = client
        .package_cve_scan_languages(&[])
        .await
        .expect("package_cve_scan_languages");
    assert_eq!(lang_cve.scanned_folder_count, 0);
    assert!(lang_cve.findings.is_empty());

    // A baseline may not exist yet on this host (never `sudo roamswitch fim
    // update`'d) — the tool then answers with a tool error rather than
    // fabricating a report, which is a legitimate outcome, not a bug. Any
    // other error (for example a response this crate cannot decode) is a failure.
    match client.verify_fim_full().await {
        Ok(full) => assert!(full.critical_path_fim.total_monitored > 0),
        Err(RoamSwitchClientError::ToolError(e)) => {
            println!("verify_fim returned a tool error (no baseline provisioned?): {e}")
        }
        Err(e) => panic!("verify_fim: {e}"),
    }

    // The daemon may not have run a scan yet on this host, which is a
    // legitimate empty-default state, not an error.
    let pa = client
        .get_port_anomaly_incidents()
        .await
        .expect("get_port_anomaly_incidents");
    println!(
        "Port anomaly: baseline_captured={}, {} incident(s)",
        pa.baseline_captured,
        pa.incidents.len()
    );

    // Server Edition only — a Client Edition host has no server-daemon, so
    // this legitimately returns an all-empty "not isolated" default.
    let ebpf = client
        .get_ebpf_incidents()
        .await
        .expect("get_ebpf_incidents");
    assert!(!ebpf.current_status.is_isolated);
    println!(
        "eBPF: {} incident(s), isolated={}",
        ebpf.incidents.len(),
        ebpf.current_status.is_isolated
    );

    // Server Edition only — legitimately empty on a Client Edition host.
    let rg = client
        .get_resource_guard_incidents()
        .await
        .expect("get_resource_guard_incidents");
    println!("Resource guard: {} incident(s)", rg.incidents.len());

    let fsg = client
        .get_file_scan_guard_status()
        .await
        .expect("get_file_scan_guard_status");
    assert!(!fsg.quarantine.quarantine_directory.is_empty());

    let notifications = client
        .notification_history()
        .await
        .expect("notification_history");
    println!("Notifications (7 days): {}", notifications.len());

    let timeline = client
        .get_incident_timeline()
        .await
        .expect("get_incident_timeline");
    println!("Timeline: {} event(s)", timeline.len());

    // A directory scan of an empty temp dir: well-formed, no leaks.
    let tmp =
        std::env::temp_dir().join(format!("roamswitch-linux-kit-test-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).expect("temp dir");
    match client
        .audit_secrets_path(&tmp)
        .await
        .expect("audit_secrets_path")
    {
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
    println!(
        "Air-Gap: active={}, frozen={}",
        ag.active,
        ag.frozen_processes.len()
    );

    let sharing = client
        .sharing_services_status()
        .await
        .expect("sharing_services_status");
    assert!(!sharing.summary.is_empty());

    let bt = client
        .bluetooth_guard_status()
        .await
        .expect("bluetooth_guard_status");
    assert_eq!(bt.controller.is_shielded_on_untrusted, bt.guard_enabled);

    let usb = client.usb_guard_status().await.expect("usb_guard_status");
    assert!(!usb.summary.is_empty());
}

/// The tools added in 0.2.0 against the real `roamswitch-mcp`. Which of them
/// have anything to report depends on the host (root, Server Edition, a
/// Sensor, PathScope or AccessScope installed), so most assertions only say
/// the answer is well formed and says what it must say when something is
/// missing. A decode failure, or the server refusing an argument, fails the test.
#[tokio::test]
async fn test_roamswitch_client_tools_added_in_0_2_0() {
    let Some(bin) = find_binary() else {
        println!("roamswitch-mcp binary not found, skipping client integration test");
        return;
    };
    let client = RoamSwitchClient::new(Some(bin), None).expect("client creation");

    let v = client
        .verify_security_findings(Some(&["luks_encryption", "no_such_check"]), None)
        .await
        .expect("verify_security_findings");
    assert_eq!(v.results.len(), 2);
    assert_eq!(v.results[1].reason, "unknown_check_id");

    let all = client
        .verify_security_findings(None, Some(false))
        .await
        .expect("verify_security_findings (all)");
    assert!(all.results.len() > 10);

    let ps = client
        .get_port_scan_incidents()
        .await
        .expect("get_port_scan_incidents");
    println!("Port scans: {}", ps.incidents.len());
    let ssh = client
        .get_ssh_guard_incidents()
        .await
        .expect("get_ssh_guard_incidents");
    println!(
        "SSH guard: running={}, {} incident(s)",
        ssh.running,
        ssh.incidents.len()
    );

    let fleet = client.get_fleet_status().await.expect("get_fleet_status");
    assert!(!fleet.remote_command_channel);

    // The exec log is root-only and may not exist; either way the answer is well formed.
    let q = ExecEventQuery {
        limit: Some(5),
        since_minutes: Some(60),
        ..Default::default()
    };
    let events = client
        .search_exec_events(&q)
        .await
        .expect("search_exec_events");
    assert!(events.events.len() <= 5);
    if events.events.is_empty() && events.error.is_none() {
        println!("exec log is readable and has nothing in the last hour");
    }
    match client.get_process_tree(1).await {
        Ok(tree) => assert_eq!(tree.tree.pid, 1),
        Err(RoamSwitchClientError::ToolError(e)) => println!("process tree: {e}"),
        Err(e) => panic!("get_process_tree: {e}"),
    }

    let tmp = std::env::temp_dir().join(format!(
        "roamswitch-linux-kit-test-0-2-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&tmp).expect("temp dir");
    let scripts = client
        .run_package_lifecycle_script_scan(std::slice::from_ref(&tmp))
        .await
        .expect("run_package_lifecycle_script_scan");
    assert_eq!(scripts.scanned_folder_count, 1);
    assert!(scripts.findings.is_empty());
    let typo = client
        .run_typosquat_scan(std::slice::from_ref(&tmp))
        .await
        .expect("run_typosquat_scan");
    assert_eq!(typo.scanned_folder_count, 1);
    assert!(typo.findings.is_empty());

    // Off by default: with the default config this answers `enabled: false` and sends nothing.
    // A host that turned it on would run npm against the registry, so do not call it there.
    // (It is covered offline in tools_tests.rs.)

    let mcp = client.audit_mcp_configs().await.expect("audit_mcp_configs");
    assert_eq!(mcp.scanned_file_count, mcp.scanned_files.len());
    let agent = client.audit_agent_setup().await.expect("audit_agent_setup");
    assert_eq!(agent.scanned_file_count, agent.scanned_files.len());
    let sarif = client
        .audit_agent_setup_sarif()
        .await
        .expect("audit_agent_setup_sarif");
    assert_eq!(sarif["version"], "2.1.0");

    let cov = client
        .detection_coverage(None)
        .await
        .expect("detection_coverage");
    assert!(!cov.techniques.is_empty());
    assert_eq!(cov.summary.total, cov.techniques.len());
    let nav = client
        .detection_coverage_navigator(Some(true))
        .await
        .expect("detection_coverage_navigator");
    assert_eq!(nav["domain"], "enterprise-attack");

    let sensor_results = client
        .get_sensor_audit_results()
        .await
        .expect("get_sensor_audit_results");
    println!("Sensor audit results: {}", sensor_results.len());
    let ht = client
        .get_honeytoken_status(None)
        .await
        .expect("get_honeytoken_status");
    assert!(ht.edition == "client" || ht.edition == "server");
    let eg = client
        .get_ransomware_entropy_guard_status(None)
        .await
        .expect("get_ransomware_entropy_guard_status");
    assert!(eg.edition == "client" || eg.edition == "server");

    let overview = client
        .get_lan_sensor_overview()
        .await
        .expect("get_lan_sensor_overview");
    assert_eq!(overview.available, overview.data.is_some());
    let threats = client
        .get_lan_network_threats(Some(10), Some("medium"))
        .await
        .expect("get_lan_network_threats");
    assert_eq!(threats.available, threats.data.is_some());
    match client.get_lan_network_threats(Some(501), None).await {
        Err(RoamSwitchClientError::ToolError(_)) => {}
        other => panic!("a limit above 500 must be a tool error, got {other:?}"),
    }

    let pe = client
        .get_privilege_escalation_paths(None)
        .await
        .expect("get_privilege_escalation_paths");
    assert_eq!(pe.analyzed, pe.reason.is_none());
    let log = client
        .get_access_log_report(Some("24h"))
        .await
        .expect("get_access_log_report");
    assert_eq!(log.analyzed, log.report.is_some());
    match client.get_access_log_report(Some("91d")).await {
        Err(RoamSwitchClientError::ToolError(_)) => {}
        other => panic!("91d must be a tool error, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&tmp);
}
