//! The 26 tools that earlier versions already covered, checked against
//! responses recorded from the current `roamswitch-mcp`: every field the tool
//! sends must survive decoding into the type. A field that fails here is a
//! field the type is missing or spells differently from the server.

mod common;

use common::{assert_fixture_covered, with_fixture};
use roamswitch_linux_kit::*;
use serde_json::json;
use std::path::{Path, PathBuf};

#[tokio::test]
async fn security_report() {
    let (r, sent) = with_fixture("get_security_report", |c| async move {
        c.security_report().await
    })
    .await;
    let r = r.unwrap();
    assert_eq!(sent.tool, "get_security_report");
    assert_eq!(sent.arguments, json!({}));
    assert_eq!(r.total_checks as usize, r.items.len());
    assert!(r.items.iter().all(|i| !i.check_id.is_empty()));
    assert_fixture_covered("get_security_report", &r);
}

#[tokio::test]
async fn server_security_report() {
    let (r, sent) = with_fixture("get_security_report_server", |c| async move {
        c.server_security_report().await
    })
    .await;
    let r = r.unwrap();
    assert_eq!(sent.arguments, json!({"isServer": true}));
    assert_eq!(r.total_checks as usize, r.items.len());
    assert_fixture_covered("get_security_report_server", &r);
}

#[tokio::test]
async fn exposed_ports() {
    let (r, sent) = with_fixture("get_exposed_ports", |c| async move {
        c.exposed_ports(true).await
    })
    .await;
    let r = r.unwrap();
    assert_eq!(sent.arguments, json!({"includeLocalOnly": true}));
    assert_eq!(r.ports.len(), 2);
    assert!(r.ports[0].is_globally_exposed && r.ports[0].is_network_reachable);
    assert!(!r.ports[1].is_network_reachable);
    assert_fixture_covered("get_exposed_ports", &r);
}

#[tokio::test]
async fn run_active_vuln_scan() {
    let (r, sent) = with_fixture("run_active_vuln_scan", |c| async move {
        c.run_active_vuln_scan().await
    })
    .await;
    let r = r.unwrap();
    assert_eq!(sent.tool, "run_active_vuln_scan");
    assert!(!r.enabled, "off unless active_vuln_scan_enabled is set");
    assert_fixture_covered("run_active_vuln_scan", &r);
}

#[tokio::test]
async fn vulnerability_scan_history() {
    let (r, _) = with_fixture("get_vulnerability_scan_history", |c| async move {
        c.vulnerability_scan_history().await
    })
    .await;
    let r = r.unwrap();
    let original = common::payload("get_vulnerability_scan_history");
    common::assert_covers(
        &original["probes"],
        &serde_json::to_value(&r).unwrap(),
        "probes",
    );
}

#[tokio::test]
async fn guard_status() {
    let (r, _) = with_fixture(
        "get_guard_status",
        |c| async move { c.guard_status().await },
    )
    .await;
    let r = r.unwrap();
    assert!(!r.guards.is_empty());
    assert_fixture_covered("get_guard_status", &r);
}

#[tokio::test]
async fn audit_url_safety() {
    let (r, sent) = with_fixture("audit_url_safety", |c| async move {
        c.audit_url_safety("https://www.google.com").await
    })
    .await;
    let r = r.unwrap();
    assert_eq!(sent.arguments, json!({"url": "https://www.google.com"}));
    assert_fixture_covered("audit_url_safety", &r);

    let (r, _) = with_fixture("audit_url_safety__risky", |c| async move {
        c.audit_url_safety("hxxps://paypa1-secure[.]example.tk/login")
            .await
    })
    .await;
    let r = r.unwrap();
    assert_eq!(r.risk_level, "dangerous");
    assert_eq!(r.verdict, Verdict::Warn);
    assert!(r.risk_factors.iter().any(|f| f.is_severe));
    assert_fixture_covered("audit_url_safety__risky", &r);
}

#[tokio::test]
async fn audit_secrets_text() {
    let (r, sent) = with_fixture("audit_secrets_text", |c| async move {
        c.audit_secrets("x").await
    })
    .await;
    let r = r.unwrap();
    assert_eq!(sent.arguments, json!({"text": "x"}));
    assert!(r.has_leaks);
    assert_eq!(r.finding_count, 2);
    assert_fixture_covered("audit_secrets_text", &r);
    let (r, _) = with_fixture("audit_secrets_text_clean", |c| async move {
        c.audit_secrets("hello world").await
    })
    .await;
    let r = r.unwrap();
    assert!(!r.has_leaks);
    assert_fixture_covered("audit_secrets_text_clean", &r);
}

#[tokio::test]
async fn audit_secrets_path() {
    let (r, sent) = with_fixture("audit_secrets_path_dir", |c| async move {
        c.audit_secrets_path(Path::new("/home/alice/proj")).await
    })
    .await;
    let r = r.unwrap();
    assert_eq!(sent.arguments, json!({"path": "/home/alice/proj"}));
    assert!(matches!(r, SecretPathAuditResult::Directory(_)));
    assert_fixture_covered("audit_secrets_path_dir", &r);

    let (r, _) = with_fixture("audit_secrets_path_dir_leak", |c| async move {
        c.audit_secrets_path(Path::new("/home/alice/proj")).await
    })
    .await;
    let r = r.unwrap();
    match &r {
        SecretPathAuditResult::Directory(d) => {
            assert!(d.has_leaks);
            assert_eq!(d.flagged_files[0].path, "/home/alice/proj/.env");
        }
        other => panic!("expected a directory result, got {other:?}"),
    }
    assert_fixture_covered("audit_secrets_path_dir_leak", &r);

    let (r, _) = with_fixture("audit_secrets_path_file", |c| async move {
        c.audit_secrets_path(Path::new("/home/alice/proj/.env"))
            .await
    })
    .await;
    let r = r.unwrap();
    assert!(matches!(r, SecretPathAuditResult::File(_)));
    assert_fixture_covered("audit_secrets_path_file", &r);
}

#[tokio::test]
async fn audit_security_logs() {
    let (r, sent) = with_fixture("audit_security_logs", |c| async move {
        c.audit_security_logs(24).await
    })
    .await;
    let r = r.unwrap();
    assert_eq!(sent.arguments, json!({"hours": 24}));
    assert_eq!(r.hours, 24);
    assert_fixture_covered("audit_security_logs", &r);
}

#[tokio::test]
async fn get_app_help() {
    let (r, sent) = with_fixture("get_app_help", |c| async move {
        c.get_app_help(Some("nftables"), None).await
    })
    .await;
    let r = r.unwrap();
    assert_eq!(sent.tool, "get_app_help");
    assert_eq!(
        sent.arguments,
        json!({"query": "nftables"}),
        "a missing topic is not sent as null"
    );
    assert!(r.total_results >= 1);
    assert_fixture_covered("get_app_help", &r);
}

#[tokio::test]
async fn quarantine_status() {
    let (r, _) = with_fixture("get_quarantine_status", |c| async move {
        c.quarantine_status().await
    })
    .await;
    let r = r.unwrap();
    assert_fixture_covered("get_quarantine_status", &r);
}

#[tokio::test]
async fn canary_status() {
    let (r, _) = with_fixture(
        "get_canary_status",
        |c| async move { c.canary_status().await },
    )
    .await;
    let r = r.unwrap();
    assert!(r.monitored_files_count > 0);
    assert_fixture_covered("get_canary_status", &r);
}

#[tokio::test]
async fn package_cve_scan() {
    let (r, _) = with_fixture("run_package_cve_scan", |c| async move {
        c.package_cve_scan().await
    })
    .await;
    let r = r.unwrap();
    assert_fixture_covered("run_package_cve_scan", &r);
}

#[tokio::test]
async fn package_cve_scan_languages() {
    let folders = vec![PathBuf::from("/home/alice/proj")];
    let (r, sent) = with_fixture("run_package_cve_scan_languages", |c| async move {
        c.package_cve_scan_languages(&folders).await
    })
    .await;
    let r = r.unwrap();
    assert_eq!(
        sent.arguments,
        json!({"watchedFolders": ["/home/alice/proj"]})
    );
    assert_fixture_covered("run_package_cve_scan_languages", &r);
}

#[tokio::test]
async fn verify_fim_returns_the_critical_path_report() {
    // `roamswitch-mcp` wraps the report in `criticalPathFim` next to the lockfile report.
    let (r, sent) = with_fixture("verify_fim", |c| async move { c.verify_fim().await }).await;
    let r = r.unwrap();
    assert_eq!(sent.tool, "verify_fim");
    assert_eq!(sent.arguments, json!({}));
    assert!(r.is_healthy);
    assert_eq!(r.total_monitored, 39);
    assert_eq!(r.passed_count, 39);
    assert!(r.violations.is_empty());
}

#[tokio::test]
async fn verify_fim_full_returns_every_part() {
    let (r, _) = with_fixture("verify_fim", |c| async move { c.verify_fim_full().await }).await;
    let r = r.unwrap();
    assert_eq!(r.critical_path_fim.total_monitored, 39);
    match r.lockfile_fim.as_ref().expect("lockfileFim") {
        LockfileFimResult::Report(l) => assert_eq!(l.total_monitored, 1),
        other => panic!("expected a report, got {other:?}"),
    }
    assert!(r.recent_intrusion_context.is_empty());
    assert_fixture_covered("verify_fim", &r);
}

#[tokio::test]
async fn verify_fim_reports_a_modified_file() {
    let (r, _) = with_fixture("verify_fim__violation", |c| async move {
        c.verify_fim_full().await
    })
    .await;
    let r = r.unwrap();
    assert!(!r.critical_path_fim.is_healthy);
    let v = &r.critical_path_fim.violations[0];
    assert_eq!(v.path, "/etc/environment");
    assert_eq!(v.violation_type, "modified");
    assert_ne!(v.expected_sha256, v.actual_sha256);
    assert_eq!(v.pid, None);
    assert_fixture_covered("verify_fim__violation", &r);
}

#[tokio::test]
async fn verify_fim_without_a_baseline_is_a_tool_error() {
    let (r, _) = with_fixture("verify_fim__no_baseline", |c| async move {
        c.verify_fim().await
    })
    .await;
    match r {
        Err(RoamSwitchClientError::ToolError(msg)) => {
            assert!(
                msg.starts_with("FIM verification failed: FIM baseline DB not found"),
                "{msg}"
            )
        }
        other => panic!("expected ToolError, got {other:?}"),
    }
}

#[tokio::test]
async fn verify_fim_full_accepts_the_bare_report_of_an_older_roamswitch_mcp() {
    // The report as it was sent before it was wrapped in `criticalPathFim`.
    let bare = r#"{"total_monitored":2,"passed_count":2,"violations":[],"last_checked_at":"t","is_healthy":true}"#;
    let line = json!({"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":bare}]}});
    let file = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("verify_fim_bare-{}.json", std::process::id()));
    std::fs::write(&file, format!("{line}\n")).unwrap();
    let (r, _) =
        common::with_fixture_file(file, |c| async move { c.verify_fim_full().await }).await;
    let r = r.unwrap();
    assert_eq!(r.critical_path_fim.total_monitored, 2);
    assert!(r.lockfile_fim.is_none() && r.recent_intrusion_context.is_empty());
}

#[tokio::test]
async fn get_port_anomaly_incidents() {
    let (r, _) = with_fixture("get_port_anomaly_incidents", |c| async move {
        c.get_port_anomaly_incidents().await
    })
    .await;
    let r = r.unwrap();
    assert_fixture_covered("get_port_anomaly_incidents", &r);
}

#[tokio::test]
async fn get_ebpf_incidents() {
    let (r, _) = with_fixture("get_ebpf_incidents", |c| async move {
        c.get_ebpf_incidents().await
    })
    .await;
    let r = r.unwrap();
    assert_fixture_covered("get_ebpf_incidents", &r);
}

#[tokio::test]
async fn get_resource_guard_incidents() {
    let (r, _) = with_fixture("get_resource_guard_incidents", |c| async move {
        c.get_resource_guard_incidents().await
    })
    .await;
    let r = r.unwrap();
    assert_fixture_covered("get_resource_guard_incidents", &r);
}

#[tokio::test]
async fn get_file_scan_guard_status() {
    let (r, _) = with_fixture("get_file_scan_guard_status", |c| async move {
        c.get_file_scan_guard_status().await
    })
    .await;
    let r = r.unwrap();
    assert_fixture_covered("get_file_scan_guard_status", &r);
}

#[tokio::test]
async fn notification_history() {
    let (r, _) = with_fixture("get_notification_history", |c| async move {
        c.notification_history().await
    })
    .await;
    let r = r.unwrap();
    let original = common::payload("get_notification_history");
    common::assert_covers(
        &original["notifications"],
        &serde_json::to_value(&r).unwrap(),
        "notifications",
    );
}

#[tokio::test]
async fn get_incident_timeline() {
    let (r, _) = with_fixture("get_incident_timeline", |c| async move {
        c.get_incident_timeline().await
    })
    .await;
    let r = r.unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].source, "honeytoken");
    let original = common::payload("get_incident_timeline");
    common::assert_covers(
        &original["events"],
        &serde_json::to_value(&r).unwrap(),
        "events",
    );
}

#[tokio::test]
async fn vpn_status() {
    let (r, _) = with_fixture("get_vpn_status", |c| async move { c.vpn_status().await }).await;
    assert_fixture_covered("get_vpn_status", &r.unwrap());
}

#[tokio::test]
async fn link_guard_status() {
    let (r, _) = with_fixture("get_link_guard_status", |c| async move {
        c.link_guard_status().await
    })
    .await;
    assert_fixture_covered("get_link_guard_status", &r.unwrap());
}

#[tokio::test]
async fn air_gap_status() {
    let (r, _) = with_fixture(
        "get_air_gap_status",
        |c| async move { c.air_gap_status().await },
    )
    .await;
    assert_fixture_covered("get_air_gap_status", &r.unwrap());
}

#[tokio::test]
async fn sharing_services_status() {
    let (r, _) = with_fixture("get_sharing_services_status", |c| async move {
        c.sharing_services_status().await
    })
    .await;
    assert_fixture_covered("get_sharing_services_status", &r.unwrap());
}

#[tokio::test]
async fn bluetooth_guard_status() {
    let (r, _) = with_fixture("get_bluetooth_guard_status", |c| async move {
        c.bluetooth_guard_status().await
    })
    .await;
    assert_fixture_covered("get_bluetooth_guard_status", &r.unwrap());
}

#[tokio::test]
async fn usb_guard_status() {
    let (r, _) = with_fixture("get_usb_guard_status", |c| async move {
        c.usb_guard_status().await
    })
    .await;
    assert_fixture_covered("get_usb_guard_status", &r.unwrap());
}
