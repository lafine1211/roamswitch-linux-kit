//! One test per MCP tool added in 0.2.0 (and its variants). Each test runs the
//! client against a stand-in `roamswitch-mcp` that answers with a response
//! recorded from the real binary (`tests/fixtures/`), then checks:
//!
//! 1. the request the client sent (tool name and arguments, spelled as the
//!    MCP input schema spells them),
//! 2. the decoded values,
//! 3. that nothing in the recorded response was dropped by the type
//!    ([`common::assert_fixture_covered`]).

mod common;

use common::{assert_fixture_covered, with_fixture};
use roamswitch_linux_kit::*;
use serde_json::json;
use std::path::{Path, PathBuf};

// ---- verify_security_findings ---------------------------------------------

#[tokio::test]
async fn verify_security_findings_all_checks() {
    let (res, sent) = with_fixture("verify_security_findings", |c| async move {
        c.verify_security_findings(None, None).await
    })
    .await;
    let report = res.expect("decode");
    assert_eq!(sent.tool, "verify_security_findings");
    assert_eq!(
        sent.arguments,
        json!({}),
        "no ids and no edition: nothing is sent"
    );
    assert_eq!(report.results.len(), 32);
    assert!(report.timestamp.ends_with('Z'));

    let luks = report
        .results
        .iter()
        .find(|r| r.check_id == "luks_encryption")
        .unwrap();
    assert_eq!(luks.verdict, FindingVerdict::StillPresent);
    assert_eq!(luks.reason, "failing");
    assert_eq!(luks.verification_status, "verified");
    assert!(luks.counter_evidence.is_some() && luks.severity_changes_if.is_some());
    assert_eq!(luks.change.as_deref(), Some("no_earlier_check"));
    assert!(luks.previous_verdict.is_none());

    let boot = report
        .results
        .iter()
        .find(|r| r.check_id == "secure_boot")
        .unwrap();
    assert_eq!(boot.verdict, FindingVerdict::Resolved);
    assert_eq!(boot.verification_status, "false_positive");
    assert!(boot.counter_evidence.is_none());

    let tool_missing = report
        .results
        .iter()
        .find(|r| r.reason == "tool_missing")
        .unwrap();
    assert_eq!(tool_missing.verdict, FindingVerdict::Inconclusive);
    assert!(
        tool_missing.change.is_none(),
        "an inconclusive result has no change"
    );

    assert_fixture_covered("verify_security_findings", &report);
}

#[tokio::test]
async fn verify_security_findings_sends_ids_and_edition_as_the_schema_spells_them() {
    let (res, sent) = with_fixture("verify_security_findings", |c| async move {
        c.verify_security_findings(Some(&["sudo_hygiene", "server_syn_cookies"]), Some(true))
            .await
    })
    .await;
    res.expect("decode");
    assert_eq!(
        sent.arguments,
        json!({ "checkIds": ["sudo_hygiene", "server_syn_cookies"], "isServer": true })
    );
}

#[test]
fn finding_verdict_survives_a_verdict_it_does_not_know() {
    let v: FindingVerdict = serde_json::from_str("\"someNewVerdict\"").unwrap();
    assert_eq!(v, FindingVerdict::Unknown);
    let v: FindingVerdict = serde_json::from_str("\"stillPresent\"").unwrap();
    assert_eq!(v, FindingVerdict::StillPresent);
}

#[test]
fn finding_verification_decodes_history_fields() {
    let wire = r#"{"checkId":"x","title":"t","verdict":"resolved","reason":"passing","statusText":"s","detail":"d",
        "verificationStatus":"verified","rationale":"r","change":"fixed","previousVerdict":"stillPresent",
        "previousCheckedAt":"2026-11-01T00:00:00Z","futureField":1}"#;
    let r: FindingVerification = serde_json::from_str(wire).unwrap();
    assert_eq!(r.change.as_deref(), Some("fixed"));
    assert_eq!(r.previous_verdict, Some(FindingVerdict::StillPresent));
    assert_eq!(
        r.previous_checked_at.as_deref(),
        Some("2026-11-01T00:00:00Z")
    );
}

// ---- get_port_scan_incidents ----------------------------------------------

#[tokio::test]
async fn get_port_scan_incidents_decodes_incidents() {
    let (res, sent) = with_fixture("get_port_scan_incidents", |c| async move {
        c.get_port_scan_incidents().await
    })
    .await;
    let s = res.expect("decode");
    assert_eq!(sent.tool, "get_port_scan_incidents");
    assert_eq!(sent.arguments, json!({}));
    assert_eq!(s.incidents.len(), 2);
    let first = &s.incidents[0];
    assert_eq!(first.source_ip, "198.51.100.23");
    assert_eq!(first.distinct_port_count, 41);
    assert_eq!(
        first.sample_ports,
        vec![21, 22, 23, 25, 80, 443, 3306, 8080]
    );
    assert!(first.blocked);
    assert_eq!(first.block_duration_secs, Some(3600));
    assert!(!s.incidents[1].blocked);
    assert_eq!(s.incidents[1].block_duration_secs, None);
    assert_fixture_covered("get_port_scan_incidents", &s);
}

// ---- get_ssh_guard_incidents ----------------------------------------------

#[tokio::test]
async fn get_ssh_guard_incidents_decodes_status_bans_and_incidents() {
    let (res, sent) = with_fixture("get_ssh_guard_incidents", |c| async move {
        c.get_ssh_guard_incidents().await
    })
    .await;
    let s = res.expect("decode");
    assert_eq!(sent.tool, "get_ssh_guard_incidents");
    assert_eq!(sent.arguments, json!({}));
    assert!(s.running);
    assert_eq!(s.active_bans, 1);
    let status = s.status.as_ref().expect("status");
    assert_eq!(status.mode, "block");
    assert_eq!(status.ports, vec![22]);
    assert_eq!(status.active_bans, 1);
    assert_eq!(s.bans.len(), 1);
    assert_eq!(s.bans[0].target, "198.51.100.23");
    assert!(s.bans[0].enforced);
    assert!(s.bans[0].until > s.bans[0].banned_at);
    assert_eq!(s.incidents.len(), 2);
    assert_eq!(s.incidents[0].kind, "ban");
    assert!(s.incidents[0].banned);
    assert_eq!(s.incidents[0].ban_secs, Some(3600));
    assert_eq!(s.incidents[1].kind, "success_after_failures");
    assert_eq!(s.incidents[1].login_user.as_deref(), Some("alice"));
    assert_eq!(s.incidents[1].login_method.as_deref(), Some("password"));
    assert_fixture_covered("get_ssh_guard_incidents", &s);
}

#[test]
fn ssh_guard_summary_without_a_running_daemon() {
    // The shape the tool sends when no daemon refreshed the status file.
    let wire = r#"{"activeBans":0,"bans":[],"incidents":[],"reasonText":null,"running":false,"status":null}"#;
    let s: SshGuardIncidentsSummary = serde_json::from_str(wire).unwrap();
    assert!(!s.running);
    assert!(s.status.is_none() && s.reason_text.is_none());
}

// ---- get_fleet_status -----------------------------------------------------

#[tokio::test]
async fn fleet_status_of_a_device_that_is_not_enrolled() {
    let (res, sent) = with_fixture(
        "get_fleet_status",
        |c| async move { c.get_fleet_status().await },
    )
    .await;
    let s = res.expect("decode");
    assert_eq!(sent.tool, "get_fleet_status");
    assert_eq!(sent.arguments, json!({}));
    assert!(!s.fleet.enrolled);
    assert!(s.fleet.org_id.is_none() && s.fleet.device_id.is_none());
    assert_eq!(s.fleet.checkin_interval_s, 0);
    assert!(!s.remote_command_channel);
    assert_fixture_covered("get_fleet_status", &s);
}

#[test]
fn fleet_status_decodes_an_enrolled_device() {
    let wire = r#"{"fleet":{"enrolled":true,"org_id":"org-1","device_id":"dev-9","device_label":"web-01",
        "org_key_fp_prefix":"ab12cd34ef56ab12","org_key_epoch":2,"policy_version_applied":7,"policy_active":true,
        "policy_not_after":1900000000,"policy_unmapped_keys":["x"],"policy_restart_required":true,
        "policy_forwarding_destination":"logs.example.com:6514","policy_forwarding_status":"applied",
        "last_rejected_version":8,"last_rejected_code":"bad_signature","checkin_interval_s":3600,
        "last_attempt_at":1800000000,"last_ok_at":1800000000,"last_error":null,"consecutive_failures":0,
        "removed_reason":null,"removed_at":null,"revocation_last":"ignored:bad_signature","revocation_last_at":1799999999,
        "fleet_service_key_configured":true,"base_host":"fleet.example.com","updated_at":1800000001},
        "remote_command_channel":false}"#;
    let s: FleetStatusSummary = serde_json::from_str(wire).unwrap();
    assert!(s.fleet.enrolled && s.fleet.policy_active && s.fleet.policy_restart_required);
    assert_eq!(
        s.fleet.org_key_fp_prefix.as_deref(),
        Some("ab12cd34ef56ab12")
    );
    assert_eq!(s.fleet.last_rejected_version, Some(8));
    assert_eq!(
        s.fleet.revocation_last.as_deref(),
        Some("ignored:bad_signature")
    );
}

// ---- search_exec_events / get_process_tree --------------------------------

#[tokio::test]
async fn search_exec_events_decodes_records_chain_and_status() {
    let (res, sent) = with_fixture("search_exec_events", |c| async move {
        c.search_exec_events(&ExecEventQuery::default()).await
    })
    .await;
    let r = res.expect("decode");
    assert_eq!(sent.tool, "search_exec_events");
    assert_eq!(sent.arguments, json!({}), "an empty query sends no filter");
    assert!(r.error.is_none());
    assert_eq!(r.events.len(), 3);
    let newest = &r.events[0];
    assert_eq!(newest.pid, 4215);
    assert_eq!(newest.ppid, Some(4100));
    assert_eq!(newest.exe.as_deref(), Some("/usr/bin/sh"));
    assert_eq!(newest.argv, vec!["sh", "/tmp/x.sh"]);
    assert_eq!(newest.user.as_deref(), Some("alice"));
    assert_eq!(newest.loginuid, Some(1000));
    assert_eq!(newest.ancestry.len(), 2);
    assert_eq!(newest.ancestry[1].comm.as_deref(), Some("sshd"));
    assert!(!newest.exe_deleted && !newest.partial);
    assert!(newest.ld_env.is_none());
    let chain = r.chain_status.as_ref().expect("chainStatus");
    assert_eq!(chain.status, "ok");
    assert_eq!(chain.segments, Some(1));
    assert_eq!(chain.unchecked_records, Some(0));
    assert_eq!(r.chain.as_deref(), Some("Ok { segments: 1 }"));
    let status = r.status.as_ref().expect("status");
    assert_eq!(status.mode, "netlink");
    assert_eq!(status.recorded, 3);
    assert_eq!(status.chain_ok, Some(true));
    assert_fixture_covered("search_exec_events", &r);
}

#[tokio::test]
async fn search_exec_events_sends_filters_as_the_schema_spells_them() {
    let q = ExecEventQuery {
        since_minutes: Some(30),
        pid: Some(4210),
        exe: Some("curl".into()),
        user: Some("alice".into()),
        parent: Some("bash".into()),
        text: Some("x.sh".into()),
        limit: Some(10),
    };
    let (res, sent) = with_fixture("search_exec_events__filtered", |c| async move {
        c.search_exec_events(&q).await
    })
    .await;
    res.expect("decode");
    assert_eq!(
        sent.arguments,
        json!({"sinceMinutes": 30, "pid": 4210, "exe": "curl", "user": "alice", "parent": "bash", "text": "x.sh", "limit": 10})
    );
}

#[test]
fn exec_search_result_when_the_log_cannot_be_read() {
    // `search_exec_events` run as a user who may not read the root-only log.
    let wire = r#"{"error":"exec log is root-only (0700): run with sudo","events":[]}"#;
    let r: ExecEventSearch = serde_json::from_str(wire).unwrap();
    assert!(r.events.is_empty());
    assert_eq!(
        r.error.as_deref(),
        Some("exec log is root-only (0700): run with sudo")
    );
    assert!(r.chain_status.is_none() && r.status.is_none());
}

#[test]
fn exec_chain_status_decodes_a_broken_chain() {
    let wire = r#"{"status":"broken","seq":3,"reason":"segment_gap","reasonText":"segment 3 does not follow segment 1","previousSeq":1}"#;
    let c: ExecChainStatus = serde_json::from_str(wire).unwrap();
    assert_eq!(c.status, "broken");
    assert_eq!(c.seq, Some(3));
    assert_eq!(c.reason.as_deref(), Some("segment_gap"));
    assert_eq!(c.previous_seq, Some(1));
    let nc: ExecChainStatus = serde_json::from_str(r#"{"status":"not_chained"}"#).unwrap();
    assert_eq!(nc.status, "not_chained");
    assert!(nc.segments.is_none());
}

#[test]
fn exec_record_decodes_ld_env() {
    let wire = r#"{"kind":"exec","ts":"2026-11-04T01:00:00+00:00","ts_ms":1,"pid":9,"ppid":1,"argv":["x"],
        "exe_deleted":false,"exe_memfd":true,"exe_setuid":false,"ancestry":[],"partial":false,"src":"procscan",
        "ld_env":{"preload":"/tmp/evil.so","audit":null,"library_path":null}}"#;
    let r: ExecRecord = serde_json::from_str(wire).unwrap();
    assert!(r.exe_memfd);
    assert_eq!(r.ld_env.unwrap().preload.as_deref(), Some("/tmp/evil.so"));
}

#[tokio::test]
async fn get_process_tree_decodes_ancestry_and_tree() {
    let (res, sent) = with_fixture("get_process_tree", |c| async move {
        c.get_process_tree(4210).await
    })
    .await;
    let t = res.expect("decode");
    assert_eq!(sent.tool, "get_process_tree");
    assert_eq!(sent.arguments, json!({"pid": 4210}));
    assert_eq!(t.ancestry.len(), 2);
    assert_eq!(t.ancestry[0].pid, 4100);
    assert_eq!(t.tree.pid, 4210);
    assert_eq!(t.tree.exe.as_deref(), Some("/usr/bin/curl"));
    assert_eq!(t.tree.argv[0], "curl");
    assert!(t.tree.children.is_empty());
    assert_fixture_covered("get_process_tree", &t);
}

#[tokio::test]
async fn get_process_tree_for_a_pid_without_a_record_is_a_tool_error() {
    let (res, _) = with_fixture("get_process_tree__unknown_pid", |c| async move {
        c.get_process_tree(99999).await
    })
    .await;
    match res {
        Err(RoamSwitchClientError::ToolError(msg)) => {
            assert_eq!(msg, "no exec record for that pid")
        }
        other => panic!("expected ToolError, got {other:?}"),
    }
}

#[test]
fn process_tree_nests_children() {
    let wire = r#"{"ancestry":[],"tree":{"pid":1,"exe":"/sbin/init","argv":["init"],"ts":"t",
        "children":[{"pid":2,"exe":null,"argv":[],"ts":"t","children":[]}]}}"#;
    let t: ProcessTree = serde_json::from_str(wire).unwrap();
    assert_eq!(t.tree.children[0].pid, 2);
}

// ---- run_package_lifecycle_script_scan / run_typosquat_scan ---------------

#[tokio::test]
async fn package_lifecycle_script_scan_decodes_findings_and_dependency_confusion() {
    let folders = [PathBuf::from("/home/alice/proj")];
    let (res, sent) = with_fixture("run_package_lifecycle_script_scan", |c| async move {
        c.run_package_lifecycle_script_scan(&folders).await
    })
    .await;
    let r = res.expect("decode");
    assert_eq!(sent.tool, "run_package_lifecycle_script_scan");
    assert_eq!(
        sent.arguments,
        json!({"watchedFolders": ["/home/alice/proj"]})
    );
    assert_eq!(r.scanned_folder_count, 1);
    assert_eq!(r.findings.len(), 2);
    let evil = r
        .findings
        .iter()
        .find(|f| f.package_name == "evil-pkg")
        .unwrap();
    assert_eq!(evil.script_name, "postinstall");
    assert!(evil.is_danger_pattern);
    assert_eq!(evil.danger_pattern_label.as_deref(), Some("curl | sh"));
    let native = r
        .findings
        .iter()
        .find(|f| f.package_name == "native-pkg")
        .unwrap();
    assert!(!native.is_danger_pattern && native.danger_pattern_label.is_none());
    assert_eq!(r.dependency_confusion.len(), 2);
    assert_eq!(r.dependency_confusion[0].kind, "npm_private_unscoped");
    assert_eq!(r.dependency_confusion[0].host, "npm.internal.example");
    assert_eq!(r.dependency_confusion[0].package_count, 1);
    assert_eq!(r.dependency_confusion[1].kind, "release_age_gate_missing");
    assert_eq!(r.dependency_confusion[1].manager, "npm");
    assert!(
        r.baseline_accepted_at.is_none() && r.drift.is_empty() && r.uncovered_folders.is_empty()
    );
    assert_fixture_covered("run_package_lifecycle_script_scan", &r);
}

#[test]
fn package_install_drift_decodes() {
    let wire = r#"{"scannedFolderCount":1,"findings":[],"dependencyConfusion":[],"baselineAcceptedAt":"2026-11-01T00:00:00Z",
        "drift":[{"packageName":"left-pad","oldVersion":"1.0.0","newVersion":"1.0.1","kind":"script_added",
        "scriptName":"postinstall","severity":"high","dangerPatternLabel":"curl | sh"}],
        "uncoveredFolders":["/srv/app/node_modules"]}"#;
    let r: PackageLifecycleScriptScanResult = serde_json::from_str(wire).unwrap();
    assert_eq!(
        r.baseline_accepted_at.as_deref(),
        Some("2026-11-01T00:00:00Z")
    );
    assert_eq!(r.drift[0].kind, "script_added");
    assert_eq!(r.drift[0].old_version.as_deref(), Some("1.0.0"));
    assert_eq!(r.drift[0].severity, "high");
    assert_eq!(r.uncovered_folders, vec!["/srv/app/node_modules"]);
}

#[test]
fn package_lifecycle_script_scan_decodes_a_response_without_the_newer_fields() {
    let wire = r#"{"scannedFolderCount":0,"findings":[]}"#;
    let r: PackageLifecycleScriptScanResult = serde_json::from_str(wire).unwrap();
    assert!(r.dependency_confusion.is_empty() && r.drift.is_empty());
}

#[tokio::test]
async fn typosquat_scan_decodes_findings() {
    let folders = vec![PathBuf::from("/home/alice/proj")];
    let (res, sent) = with_fixture("run_typosquat_scan", |c| async move {
        c.run_typosquat_scan(&folders).await
    })
    .await;
    let r = res.expect("decode");
    assert_eq!(sent.tool, "run_typosquat_scan");
    assert_eq!(
        sent.arguments,
        json!({"watchedFolders": ["/home/alice/proj"]})
    );
    assert_eq!(r.scanned_folder_count, 1);
    assert_eq!(r.findings.len(), 1);
    assert_eq!(r.findings[0].dependency_name, "expres");
    assert_eq!(r.findings[0].suspected_target, "express");
    assert_eq!(r.findings[0].distance, 1);
    assert_eq!(r.findings[0].project_dir, "/home/alice/proj");
    assert_fixture_covered("run_typosquat_scan", &r);
}

// ---- run_npm_audit_signatures ---------------------------------------------

#[tokio::test]
async fn npm_audit_signatures_when_it_is_disabled() {
    let (res, sent) = with_fixture("run_npm_audit_signatures__disabled", |c| async move {
        c.run_npm_audit_signatures(Path::new("/home/alice/proj"))
            .await
    })
    .await;
    let r = res.expect("decode");
    assert_eq!(sent.tool, "run_npm_audit_signatures");
    assert_eq!(sent.arguments, json!({"directory": "/home/alice/proj"}));
    assert!(!r.enabled);
    assert!(r.message.as_deref().unwrap().contains("disabled"));
    assert!(r.raw_output.is_none() && r.exit_code.is_none() && r.has_issues.is_none());
    assert_fixture_covered("run_npm_audit_signatures__disabled", &r);
}

#[tokio::test]
async fn npm_audit_signatures_when_npm_reports_a_problem() {
    let (res, _) = with_fixture("run_npm_audit_signatures__issues", |c| async move {
        c.run_npm_audit_signatures(Path::new("/home/alice/proj"))
            .await
    })
    .await;
    let r = res.expect("decode");
    assert!(r.enabled);
    assert_eq!(r.directory.as_deref(), Some("/home/alice/proj"));
    assert_eq!(r.exit_code, Some(1));
    assert_eq!(r.has_issues, Some(true));
    assert!(r
        .raw_output
        .as_deref()
        .unwrap()
        .contains("invalid registry signature"));
    assert!(r.message.is_none());
    assert_fixture_covered("run_npm_audit_signatures__issues", &r);
}

#[tokio::test]
async fn npm_audit_signatures_when_npm_is_not_installed() {
    let (res, _) = with_fixture("run_npm_audit_signatures__npm_missing", |c| async move {
        c.run_npm_audit_signatures(Path::new("/home/alice/proj"))
            .await
    })
    .await;
    let r = res.expect("decode");
    assert!(r.enabled);
    assert!(r
        .message
        .as_deref()
        .unwrap()
        .contains("npm command was not found"));
    assert!(r.exit_code.is_none() && r.has_issues.is_none());
    assert_fixture_covered("run_npm_audit_signatures__npm_missing", &r);
}

// ---- audit_mcp_configs / audit_agent_setup --------------------------------

#[tokio::test]
async fn audit_mcp_configs_decodes_findings() {
    let (res, sent) = with_fixture("audit_mcp_configs", |c| async move {
        c.audit_mcp_configs().await
    })
    .await;
    let r = res.expect("decode");
    assert_eq!(sent.tool, "audit_mcp_configs");
    assert_eq!(sent.arguments, json!({}));
    assert_eq!(r.scanned_file_count, 1);
    assert_eq!(r.server_count, 3);
    assert!(r.unreadable_files.is_empty());
    let ids: Vec<&str> = r.findings.iter().map(|f| f.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "auto_approve",
            "unpinned_package_launcher",
            "remote_plain_http",
            "shell_wrapper"
        ]
    );
    assert_eq!(r.findings[0].severity, "high");
    assert_eq!(r.findings[0].server.as_deref(), Some("fetcher"));
    assert_eq!(
        r.findings[2].detail,
        "http:// to non-loopback host 10.1.1.1"
    );
    assert_fixture_covered("audit_mcp_configs", &r);
}

#[test]
fn mcp_config_finding_without_a_server() {
    let wire = r#"{"scannedFileCount":1,"scannedFiles":["/home/a/.claude/settings.json"],"serverCount":0,"unreadableFiles":[],
        "findings":[{"id":"auto_trust_project_servers","severity":"high","file":"/home/a/.claude/settings.json","server":null,"detail":"d","message":"m"}]}"#;
    let r: McpConfigAuditPayload = serde_json::from_str(wire).unwrap();
    assert!(r.findings[0].server.is_none());
}

#[tokio::test]
async fn audit_agent_setup_decodes_findings_with_tags() {
    let (res, sent) = with_fixture("audit_agent_setup", |c| async move {
        c.audit_agent_setup().await
    })
    .await;
    let r = res.expect("decode");
    assert_eq!(sent.tool, "audit_agent_setup");
    assert_eq!(
        sent.arguments,
        json!({}),
        "the JSON format is the default: no argument"
    );
    assert_eq!(r.scanned_file_count, 1);
    assert_eq!(r.skill_count, 0);
    assert!(!r.open_claw_config_found);
    assert!(r.baseline_accepted_at.is_none());
    assert_eq!(r.findings.len(), 2);
    assert_eq!(r.findings[0].id, "override_instruction");
    assert_eq!(r.findings[0].area, "instructions");
    assert_eq!(r.findings[0].owasp_llm, vec!["LLM01"]);
    assert!(r.findings[0].attack_id.is_empty());
    assert_eq!(r.findings[1].id, "remote_script_exec");
    assert_eq!(r.findings[1].attack_id, vec!["T1105"]);
    assert_fixture_covered("audit_agent_setup", &r);
}

#[tokio::test]
async fn audit_agent_setup_sarif_is_passed_on_as_json() {
    let (res, sent) = with_fixture("audit_agent_setup__sarif", |c| async move {
        c.audit_agent_setup_sarif().await
    })
    .await;
    let v = res.expect("decode");
    assert_eq!(sent.tool, "audit_agent_setup");
    assert_eq!(sent.arguments, json!({"format": "sarif"}));
    assert_eq!(v["version"], "2.1.0");
    assert!(v["runs"].is_array());
    assert_eq!(v, common::payload("audit_agent_setup__sarif"));
}

// ---- get_detection_coverage -----------------------------------------------

#[tokio::test]
async fn detection_coverage_decodes_techniques_and_guards() {
    let (res, sent) = with_fixture("get_detection_coverage", |c| async move {
        c.detection_coverage(None).await
    })
    .await;
    let r = res.expect("decode");
    assert_eq!(sent.tool, "get_detection_coverage");
    assert_eq!(sent.arguments, json!({}));
    assert_eq!(r.platform, "linux");
    assert_eq!(r.edition, "client");
    assert_eq!(r.summary.total, 38);
    assert_eq!(r.summary.partial, 31);
    assert_eq!(r.summary.none, 7);
    assert_eq!(r.summary.covered_but_off, 1);
    assert_eq!(r.techniques.len(), 38);
    let t = &r.techniques[0];
    assert_eq!(t.id, "T1685");
    assert_eq!(t.coverage, CoverageLevel::Partial);
    assert_eq!(t.covered_by, vec!["guardWatchdog", "criticalPathFim"]);
    assert_eq!(t.live_state, "unknown");
    assert!(r
        .techniques
        .iter()
        .any(|t| t.coverage == CoverageLevel::Nothing && t.covered_by.is_empty()));
    assert_eq!(r.guards[0].id, "guardWatchdog");
    assert_eq!(r.guards[0].state, "unknown");
    assert!(r.inactive.is_empty());
    assert_eq!(r.caveats.len(), 3);
    assert_fixture_covered("get_detection_coverage", &r);
}

#[tokio::test]
async fn detection_coverage_for_the_server_edition() {
    let (res, sent) = with_fixture("get_detection_coverage__server", |c| async move {
        c.detection_coverage(Some(true)).await
    })
    .await;
    let r = res.expect("decode");
    assert_eq!(sent.arguments, json!({"isServer": true}));
    assert_eq!(r.edition, "server");
    assert_eq!(r.summary.none, 13);
    assert_fixture_covered("get_detection_coverage__server", &r);
}

#[tokio::test]
async fn detection_coverage_navigator_is_passed_on_as_json() {
    let (res, sent) = with_fixture("get_detection_coverage__navigator", |c| async move {
        c.detection_coverage_navigator(Some(false)).await
    })
    .await;
    let v = res.expect("decode");
    assert_eq!(sent.tool, "get_detection_coverage");
    assert_eq!(
        sent.arguments,
        json!({"isServer": false, "format": "navigator"})
    );
    assert_eq!(v["versions"]["layer"], "4.5");
    assert_eq!(v["domain"], "enterprise-attack");
    assert!(v["techniques"].as_array().unwrap().len() > 10);
}

#[test]
fn coverage_level_survives_a_level_it_does_not_know() {
    let v: CoverageLevel = serde_json::from_str("\"full\"").unwrap();
    assert_eq!(v, CoverageLevel::Unknown);
    assert_eq!(
        serde_json::to_string(&CoverageLevel::Nothing).unwrap(),
        "\"none\""
    );
}

// ---- get_sensor_audit_results ---------------------------------------------

#[tokio::test]
async fn sensor_audit_results_unwraps_the_list() {
    let (res, sent) = with_fixture("get_sensor_audit_results", |c| async move {
        c.get_sensor_audit_results().await
    })
    .await;
    let list = res.expect("decode");
    assert_eq!(sent.tool, "get_sensor_audit_results");
    assert_eq!(sent.arguments, json!({}));
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].request_id, "req-0002");
    assert_eq!(list[0].status, "pending");
    assert!(list[0].findings.is_none() && list[0].completed_at.is_none());
    assert_eq!(list[1].status, "completed");
    assert_eq!(list[1].attempts, 2);
    assert_eq!(
        list[1].completed_at.as_deref(),
        Some("2026-11-03T20:06:41+00:00")
    );
    assert_eq!(
        list[1].findings.as_ref().unwrap()["open_ports"],
        json!([22, 8080])
    );
    let original = common::payload("get_sensor_audit_results");
    common::assert_covers(
        &original["auditResults"],
        &serde_json::to_value(&list).unwrap(),
        "auditResults",
    );
}

// ---- get_honeytoken_status / get_ransomware_entropy_guard_status ----------

#[tokio::test]
async fn honeytoken_status_decodes_placement_and_events() {
    let (res, sent) = with_fixture("get_honeytoken_status", |c| async move {
        c.get_honeytoken_status(None).await
    })
    .await;
    let r = res.expect("decode");
    assert_eq!(sent.tool, "get_honeytoken_status");
    assert_eq!(sent.arguments, json!({}));
    assert_eq!(r.edition, "client");
    assert_eq!(r.enabled, Some(true));
    assert_eq!(r.setting, "honeytokens_enabled");
    assert_eq!(r.setting_source, "config.json");
    assert!(r.config_readable && r.events_readable);
    assert!(r.inactive.is_none() && r.timeline_problem.is_none());
    let p = r.placement.as_ref().expect("placement");
    assert_eq!(p.home.as_deref(), Some("/home/alice"));
    assert!(p.home_visible);
    assert_eq!(p.home_source, "sudo_user");
    assert_eq!(p.deploy_ok, Some(true));
    assert_eq!(p.watcher_pid, 777);
    assert_eq!(p.restarts, 1);
    assert_eq!(p.other_homes, 2);
    assert_eq!(r.recent_events.len(), 1);
    let e = &r.recent_events[0];
    assert_eq!(e.event_type, "access");
    assert_eq!(e.kind.as_deref(), Some("aws_credentials"));
    assert_eq!(e.path.as_deref(), Some("/home/alice/.aws/credentials"));
    assert_eq!(e.severity, "Critical");
    assert_eq!(e.suspected_process.as_deref(), Some("curl"));
    assert_eq!(e.suspected_pid, Some(4210));
    assert_eq!(e.accessed_by.as_deref(), Some("alice (curl)"));
    assert_eq!(e.process_ancestry, vec!["bash", "sshd"]);
    assert_eq!(e.attack_technique.as_deref(), Some("T1552"));
    assert_eq!(r.hidden_events_count, 0);
    assert_fixture_covered("get_honeytoken_status", &r);
}

#[tokio::test]
async fn honeytoken_status_for_the_server_edition() {
    let (res, sent) = with_fixture("get_honeytoken_status__server", |c| async move {
        c.get_honeytoken_status(Some(true)).await
    })
    .await;
    let r = res.expect("decode");
    assert_eq!(sent.arguments, json!({"isServer": true}));
    assert_eq!(r.edition, "server");
    assert_eq!(r.setting_source, "server.conf");
    let p = r.placement.as_ref().unwrap();
    assert_eq!(p.home_source, "server_conf");
    assert_eq!(p.watcher_pid, 0, "the server edition reports no watcher");
    assert!(p.deploy_ok.is_none());
    assert_fixture_covered("get_honeytoken_status__server", &r);
}

#[tokio::test]
async fn ransomware_entropy_guard_status_decodes_incidents() {
    let (res, sent) = with_fixture("get_ransomware_entropy_guard_status", |c| async move {
        c.get_ransomware_entropy_guard_status(None).await
    })
    .await;
    let r = res.expect("decode");
    assert_eq!(sent.tool, "get_ransomware_entropy_guard_status");
    assert_eq!(sent.arguments, json!({}));
    assert_eq!(r.edition, "client");
    assert_eq!(r.enabled, Some(true));
    assert_eq!(r.freezes_on_detection, Some(true));
    assert!(r.config_readable && r.incidents_readable);
    assert_eq!(
        r.incidents_file,
        "/var/lib/roamswitch/entropy_incidents.json"
    );
    assert_eq!(
        r.settings.as_ref().unwrap()["system_wide_fanotify_enabled"],
        true
    );
    assert_eq!(r.recent_incidents.len(), 1);
    let i = &r.recent_incidents[0];
    assert_eq!(i.id, "evt-0001");
    assert_eq!(i.pid, 5521);
    assert_eq!(i.process_name, "encryptor");
    assert_eq!(i.affected_files.len(), 2);
    assert_eq!(i.affected_files_total, 24);
    assert_eq!(i.hidden_files, 22);
    assert!((i.avg_entropy - 7.93).abs() < 1e-9);
    assert!(i.frozen);
    assert_fixture_covered("get_ransomware_entropy_guard_status", &r);
}

#[tokio::test]
async fn ransomware_entropy_guard_status_for_the_server_edition() {
    let (res, sent) = with_fixture(
        "get_ransomware_entropy_guard_status__server",
        |c| async move { c.get_ransomware_entropy_guard_status(Some(true)).await },
    )
    .await;
    let r = res.expect("decode");
    assert_eq!(sent.arguments, json!({"isServer": true}));
    assert_eq!(r.edition, "server");
    assert_eq!(r.setting_source, "server.conf");
    assert_eq!(r.freezes_on_detection, Some(false));
    assert_eq!(
        r.settings.as_ref().unwrap()["entropy_watch_dirs"],
        json!(["/var/www", "/srv"])
    );
    assert_fixture_covered("get_ransomware_entropy_guard_status__server", &r);
}

// ---- get_lan_sensor_overview / get_lan_network_threats --------------------

#[tokio::test]
async fn lan_sensor_overview_decodes_the_sensor_reply() {
    let (res, sent) = with_fixture("get_lan_sensor_overview", |c| async move {
        c.get_lan_sensor_overview().await
    })
    .await;
    let r = res.expect("decode");
    assert_eq!(sent.tool, "get_lan_sensor_overview");
    assert_eq!(sent.arguments, json!({}));
    assert!(r.available);
    assert_eq!(r.schema_supported, Some(true));
    assert_eq!(r.schema, Some(1));
    assert!(r.coverage_gaps.is_empty() && r.mcp_caution.is_none());
    let d = r.data.as_ref().expect("data");
    assert_eq!(d.schema, 1);
    assert_eq!(d.sensor.site, "home-lab");
    assert!(!d.sensor.lockdown);
    assert_eq!(d.network.gateway_ip.as_deref(), Some("192.168.1.1"));
    assert_eq!(d.network.devices_total, 23);
    assert_eq!(d.network.devices_online, 17);
    assert_eq!(d.network.devices_unregistered, 4);
    assert_eq!(d.network.devices_ipv6_only, 1);
    assert_eq!(d.network.vlans, vec![10, 20]);
    assert_eq!(d.capture.state, "listening");
    assert_eq!(d.capture.interface, "eth0");
    assert_eq!(d.capture.frames, 1203344);
    assert_eq!(d.paired_endpoints, 2);
    assert_eq!(d.behavior.learned_devices, 9);
    assert_eq!(d.unmanaged_audits.kev_confirmed, 1);
    assert_eq!(d.threats.total, 3);
    assert_eq!(d.threats.by_severity["critical"], 1);
    assert_eq!(d.threats.by_category["unmanaged_weak_device"], 2);
    assert_fixture_covered("get_lan_sensor_overview", &r);
}

#[tokio::test]
async fn lan_sensor_overview_with_a_coverage_gap() {
    let (res, _) = with_fixture("get_lan_sensor_overview__coverage_gap", |c| async move {
        c.get_lan_sensor_overview().await
    })
    .await;
    let r = res.expect("decode");
    assert_eq!(r.coverage_gaps, vec!["capture_stalled"]);
    assert!(r
        .mcp_caution
        .as_deref()
        .unwrap()
        .contains("Zero threats does not mean nothing is wrong"));
    assert_eq!(
        r.data.as_ref().unwrap().capture.coverage_notes,
        vec!["capture_stalled"]
    );
    assert_fixture_covered("get_lan_sensor_overview__coverage_gap", &r);
}

#[tokio::test]
async fn lan_sensor_overview_without_a_sensor_is_an_answer_not_an_error() {
    let (res, _) = with_fixture("get_lan_sensor_overview__not_installed", |c| async move {
        c.get_lan_sensor_overview().await
    })
    .await;
    let r = res.expect("decode");
    assert!(!r.available);
    assert_eq!(r.reason.as_deref(), Some("not_installed"));
    assert!(r.data.is_none());
    assert!(r
        .mcp_note
        .as_deref()
        .unwrap()
        .contains("socket does not exist"));
    assert_fixture_covered("get_lan_sensor_overview__not_installed", &r);
}

#[tokio::test]
async fn lan_network_threats_decodes_threats() {
    let (res, sent) = with_fixture("get_lan_network_threats", |c| async move {
        c.get_lan_network_threats(None, None).await
    })
    .await;
    let r = res.expect("decode");
    assert_eq!(sent.tool, "get_lan_network_threats");
    assert_eq!(sent.arguments, json!({}));
    let d = r.data.as_ref().expect("data");
    assert_eq!(d.site, "home-lab");
    assert_eq!(d.threats.len(), 3);
    let rogue = &d.threats[0];
    assert_eq!(rogue.id, 412);
    assert_eq!(rogue.category, "rogue_dhcp");
    assert_eq!(rogue.kind, "dhcp_rogue_server");
    assert_eq!(rogue.severity, "critical");
    assert_eq!(rogue.subject, "aa:bb:cc:00:00:77");
    assert_eq!(rogue.detail["server_ip"], "192.168.1.77");
    let kev = &d.threats[1];
    assert_eq!(kev.id, 0);
    assert_eq!(kev.kind, "unmanaged_kev_confirmed");
    assert_eq!(kev.detail["cves"], json!(["CVE-2018-14847"]));
    assert!(d.coverage_notes.is_empty());
    assert_fixture_covered("get_lan_network_threats", &r);
}

#[tokio::test]
async fn lan_network_threats_sends_limit_and_min_severity_as_the_schema_spells_them() {
    let (res, sent) = with_fixture("get_lan_network_threats__min_high", |c| async move {
        c.get_lan_network_threats(Some(50), Some("high")).await
    })
    .await;
    let r = res.expect("decode");
    assert_eq!(sent.arguments, json!({"limit": 50, "minSeverity": "high"}));
    assert_eq!(r.data.as_ref().unwrap().threats.len(), 2);
    assert_fixture_covered("get_lan_network_threats__min_high", &r);
}

#[tokio::test]
async fn lan_network_threats_with_a_coverage_gap() {
    let (res, _) = with_fixture("get_lan_network_threats__coverage_gap", |c| async move {
        c.get_lan_network_threats(None, None).await
    })
    .await;
    let r = res.expect("decode");
    assert_eq!(r.coverage_gaps, vec!["capture_stalled"]);
    assert!(r.mcp_caution.is_some());
    assert_eq!(
        r.data.as_ref().unwrap().coverage_notes,
        vec!["capture_stalled"]
    );
}

#[tokio::test]
async fn lan_network_threats_out_of_range_limit_is_a_tool_error() {
    let (res, sent) = with_fixture("get_lan_network_threats__invalid_params", |c| async move {
        c.get_lan_network_threats(Some(0), None).await
    })
    .await;
    assert_eq!(sent.arguments, json!({"limit": 0}));
    match res {
        Err(RoamSwitchClientError::ToolError(msg)) => {
            assert_eq!(msg, "limit must be an integer from 1 to 500")
        }
        other => panic!("expected ToolError, got {other:?}"),
    }
}

#[test]
fn sensor_reply_with_an_unsupported_schema_has_no_data() {
    let wire = r#"{"available":true,"schemaSupported":false,"schema":2,"supportedSchema":1,"mcpNote":"n"}"#;
    let r: SensorReply<LanOverview> = serde_json::from_str(wire).unwrap();
    assert_eq!(r.schema_supported, Some(false));
    assert_eq!(r.schema, Some(2));
    assert_eq!(r.supported_schema, Some(1));
    assert!(r.data.is_none() && r.coverage_gaps.is_empty());
}

#[test]
fn sensor_reply_with_a_sensor_error() {
    let wire = r#"{"available":false,"reason":"sensor_error","mcpNote":"n","sensorError":"boom"}"#;
    let r: SensorReply<LanThreats> = serde_json::from_str(wire).unwrap();
    assert_eq!(r.reason.as_deref(), Some("sensor_error"));
    assert_eq!(r.sensor_error.as_deref(), Some("boom"));
}

#[test]
fn lan_overview_accepts_fields_added_later_and_a_missing_gateway() {
    let wire = r#"{"schema":1,"generated_at":"t","sensor":{"public_key":"k","version":"1","site":"s","lockdown":false,"new":1},
        "network":{"gateway_ip":null,"gateway_mac":null,"sensor_addr":null,"devices_total":0,"devices_online":0,
        "devices_unregistered":0,"devices_ipv6_only":0,"vlans":[],"last_updated":null},
        "capture":{"state":"off","interface":"","frames":0,"kernel_drops":0,"coverage_notes":[]},
        "paired_endpoints":0,"behavior":{"learned_devices":0,"anomalies_active":0},
        "unmanaged_audits":{"devices_audited":0,"kev_confirmed":0,"kev_product":0,"noauth_open":0},
        "threats":{"total":0,"by_severity":{},"by_category":{}},"future_section":{}}"#;
    let o: LanOverview = serde_json::from_str(wire).unwrap();
    assert!(o.network.gateway_ip.is_none() && o.network.last_updated.is_none());
}

// ---- get_privilege_escalation_paths ---------------------------------------

#[tokio::test]
async fn privilege_escalation_paths_decodes_an_analysis() {
    let (res, sent) = with_fixture("get_privilege_escalation_paths", |c| async move {
        c.get_privilege_escalation_paths(None).await
    })
    .await;
    let r = res.expect("decode");
    assert_eq!(sent.tool, "get_privilege_escalation_paths");
    assert_eq!(sent.arguments, json!({}));
    assert!(r.available && r.analyzed);
    assert_eq!(r.mode.as_deref(), Some("single"));
    assert_eq!(r.requested_user.as_deref(), Some("alice"));
    let a = &r.analysis;
    assert_eq!(a.goal.as_deref(), Some("root"));
    assert_eq!(a.os.as_deref(), Some("linux"));
    assert_eq!(a.privileged, Some(false));
    assert_eq!(a.paths, 1);
    assert_eq!(a.paths_shown.len(), 1);
    assert_eq!(a.paths_shown[0][0].kind.as_deref(), Some("docker_group"));
    assert_eq!(a.paths_shown[0][0].to.as_deref(), Some("root"));
    assert_eq!(a.urgent_total, 1);
    let fix = &a.urgent[0];
    assert_eq!(fix.impact, Some(1));
    assert_eq!(fix.priority.level.as_deref(), Some("critical"));
    assert_eq!(fix.priority.score, Some(100));
    assert_eq!(
        fix.attack.as_ref().unwrap().technique_id.as_deref(),
        Some("T1611")
    );
    assert!(fix
        .remediation_summary
        .as_deref()
        .unwrap()
        .contains("docker group"));
    assert_eq!(a.uncollected_by_kind["watched_path"], 6);
    assert!(!a.complete, "PathScope ran without root");
    assert!(a.mcp_caution.as_deref().unwrap().contains("without root"));
    assert_fixture_covered("get_privilege_escalation_paths", &r);
}

#[tokio::test]
async fn privilege_escalation_paths_sends_start_and_check_agent_users() {
    let (res, sent) = with_fixture("get_privilege_escalation_paths", |c| async move {
        c.get_privilege_escalation_paths(Some("alice")).await
    })
    .await;
    res.expect("decode");
    assert_eq!(sent.arguments, json!({"start": "alice"}));

    let (res, sent) = with_fixture(
        "get_privilege_escalation_paths__agent_users",
        |c| async move { c.get_privilege_escalation_paths_for_agent_users().await },
    )
    .await;
    let r = res.expect("decode");
    assert_eq!(sent.arguments, json!({"checkAgentUsers": true}));
    assert_eq!(r.mode.as_deref(), Some("agent_users"));
    assert_eq!(r.schema.as_deref(), Some("pathscope.agent-users/v1"));
    assert_eq!(r.accounts, Some(2));
    assert_eq!(r.users.len(), 2);
    assert_eq!(r.users[0].user.as_deref(), Some("alice"));
    assert_eq!(r.users[0].uid, Some(1000));
    assert_eq!(r.users[0].analysis.as_ref().unwrap().paths, 1);
    assert!(!r.analysis.complete);
    assert!(r.analysis.mcp_caution.is_some());
    assert_fixture_covered("get_privilege_escalation_paths__agent_users", &r);
}

#[tokio::test]
async fn privilege_escalation_paths_without_pathscope_is_an_answer_not_an_error() {
    let (res, _) = with_fixture(
        "get_privilege_escalation_paths__not_installed",
        |c| async move { c.get_privilege_escalation_paths(None).await },
    )
    .await;
    let r = res.expect("decode");
    assert!(!r.available && !r.analyzed);
    assert_eq!(r.reason.as_deref(), Some("not_installed"));
    assert!(r
        .mcp_note
        .as_deref()
        .unwrap()
        .contains("PathScope is not installed"));
    assert!(
        !r.analysis.complete,
        "nothing was analysed, so it is not complete"
    );
    assert_eq!(r.analysis.paths, 0);
    assert_fixture_covered("get_privilege_escalation_paths__not_installed", &r);
}

// ---- get_access_log_report ------------------------------------------------

#[tokio::test]
async fn access_log_report_decodes_the_summary_and_the_report() {
    let (res, sent) = with_fixture("get_access_log_report", |c| async move {
        c.get_access_log_report(Some("24h")).await
    })
    .await;
    let r = res.expect("decode");
    assert_eq!(sent.tool, "get_access_log_report");
    assert_eq!(sent.arguments, json!({"since": "24h"}));
    assert!(r.available && r.analyzed && r.complete);
    assert_eq!(r.schema_supported, Some(true));
    assert_eq!(r.schema.as_deref(), Some("accessscope-brief/1"));
    assert_eq!(r.since.as_deref(), Some("24h"));
    assert_eq!(r.risk_level.as_deref(), Some("low"));
    assert_eq!(r.risk_score, Some(2));
    assert_eq!(r.findings_total, Some(6));
    assert_eq!(r.findings_shown, Some(6));
    assert_eq!(r.coverage_partial, Some(false));
    assert_eq!(r.unread_sources, Some(0));
    assert!(r.mcp_caution.is_none());
    let report = r.report.as_ref().expect("report");
    assert_eq!(report.tool.name, "accessscope");
    assert_eq!(report.risk.level, "low");
    assert!(!report.coverage.partial);
    assert_eq!(report.coverage.notes, vec!["late_start"]);
    assert_eq!(report.coverage.lines.as_ref().unwrap()["parsed"], 49);
    assert_eq!(report.sources.read, 2);
    assert!(report.sources.unread.is_empty());
    assert_eq!(report.findings.len(), 6);
    let f = &report.findings[1];
    assert_eq!(f.n, 2);
    assert_eq!(f.kind, "ssh_bf");
    assert_eq!(f.confidence, "likely");
    assert_eq!(f.count, 15);
    assert_eq!(f.attack_id.as_deref(), Some("T1110"));
    assert!(f.subject.is_none());
    assert_eq!(f.ips, vec!["203.0.113.5"]);
    assert_eq!(f.evidence.len(), 1);
    assert!(f.evidence[0].text.contains("Failed password"));
    assert!(f.first.unwrap() < f.last.unwrap());
    assert_fixture_covered("get_access_log_report", &r);
}

#[tokio::test]
async fn access_log_report_sends_nothing_when_since_is_not_given() {
    let (res, sent) = with_fixture("get_access_log_report", |c| async move {
        c.get_access_log_report(None).await
    })
    .await;
    res.expect("decode");
    assert_eq!(
        sent.arguments,
        json!({}),
        "the tool refuses unknown arguments and null is not needed"
    );
}

#[tokio::test]
async fn access_log_report_without_accessscope_is_an_answer_not_an_error() {
    let (res, _) = with_fixture("get_access_log_report__not_installed", |c| async move {
        c.get_access_log_report(None).await
    })
    .await;
    let r = res.expect("decode");
    assert!(!r.available && !r.analyzed && !r.complete);
    assert_eq!(r.reason.as_deref(), Some("not_installed"));
    assert!(r.report.is_none());
    assert_fixture_covered("get_access_log_report__not_installed", &r);
}

#[test]
fn access_log_report_with_unread_sources_is_incomplete() {
    let wire = r#"{"available":true,"analyzed":true,"complete":false,"coveragePartial":true,"unreadSources":1,
        "mcpCaution":"Zero findings does NOT mean the host is safe: 1 log source(s) could not be read.",
        "schemaSupported":true,"schema":"accessscope-brief/1","since":"7d","findingsTotal":0,"findingsShown":0,
        "report":{"schema":"accessscope-brief/1","tool":{"name":"accessscope","version":"1.0.4"},"generated_at":1,
        "risk":{"score":0,"level":"none"},"coverage":{"partial":true},
        "sources":{"read":1,"unread":[{"path":"/var/log/auth.log","state":"unreadable"}]},
        "findings_total":0,"findings_shown":0,"findings":[],"added_later":true}}"#;
    let r: AccessLogReport = serde_json::from_str(wire).unwrap();
    assert!(!r.complete);
    assert_eq!(
        r.report.as_ref().unwrap().sources.unread[0].path,
        "/var/log/auth.log"
    );
    assert!(r.report.as_ref().unwrap().coverage.notes.is_empty());
}
