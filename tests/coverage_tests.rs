//! Every tool of `roamswitch-mcp` has a method in `RoamSwitchClient`.
//!
//! `tests/fixtures/tools_list.json` is the real `tools/list` response. When it is
//! replaced by a newer one that has a tool this table does not know, the first
//! test fails; when a tool is in the table but nothing in `src/client.rs` calls
//! it, the second one fails.

mod common;

/// (tool name, the `RoamSwitchClient` methods that call it)
const TOOLS: [(&str, &[&str]); 45] = [
    (
        "get_security_report",
        &["security_report", "server_security_report"],
    ),
    ("verify_security_findings", &["verify_security_findings"]),
    ("get_exposed_ports", &["exposed_ports"]),
    ("get_guard_status", &["guard_status"]),
    ("audit_url_safety", &["audit_url_safety"]),
    ("get_app_help", &["get_app_help"]),
    ("audit_secrets", &["audit_secrets", "audit_secrets_path"]),
    ("audit_security_logs", &["audit_security_logs"]),
    ("get_quarantine_status", &["quarantine_status"]),
    ("verify_fim", &["verify_fim", "verify_fim_full"]),
    (
        "get_port_anomaly_incidents",
        &["get_port_anomaly_incidents"],
    ),
    ("get_ebpf_incidents", &["get_ebpf_incidents"]),
    (
        "get_resource_guard_incidents",
        &["get_resource_guard_incidents"],
    ),
    ("get_port_scan_incidents", &["get_port_scan_incidents"]),
    ("get_ssh_guard_incidents", &["get_ssh_guard_incidents"]),
    ("get_canary_status", &["canary_status"]),
    ("get_notification_history", &["notification_history"]),
    ("get_incident_timeline", &["get_incident_timeline"]),
    ("get_fleet_status", &["get_fleet_status"]),
    ("search_exec_events", &["search_exec_events"]),
    ("get_process_tree", &["get_process_tree"]),
    (
        "get_file_scan_guard_status",
        &["get_file_scan_guard_status"],
    ),
    ("get_vpn_status", &["vpn_status"]),
    ("get_link_guard_status", &["link_guard_status"]),
    ("get_air_gap_status", &["air_gap_status"]),
    ("get_sharing_services_status", &["sharing_services_status"]),
    ("get_bluetooth_guard_status", &["bluetooth_guard_status"]),
    ("get_usb_guard_status", &["usb_guard_status"]),
    ("run_active_vuln_scan", &["run_active_vuln_scan"]),
    (
        "get_vulnerability_scan_history",
        &["vulnerability_scan_history"],
    ),
    ("run_package_cve_scan", &["package_cve_scan"]),
    (
        "run_package_cve_scan_languages",
        &["package_cve_scan_languages"],
    ),
    (
        "run_package_lifecycle_script_scan",
        &["run_package_lifecycle_script_scan"],
    ),
    ("run_typosquat_scan", &["run_typosquat_scan"]),
    ("run_npm_audit_signatures", &["run_npm_audit_signatures"]),
    (
        "get_detection_coverage",
        &["detection_coverage", "detection_coverage_navigator"],
    ),
    ("get_sensor_audit_results", &["get_sensor_audit_results"]),
    ("audit_mcp_configs", &["audit_mcp_configs"]),
    (
        "audit_agent_setup",
        &["audit_agent_setup", "audit_agent_setup_sarif"],
    ),
    ("get_honeytoken_status", &["get_honeytoken_status"]),
    (
        "get_ransomware_entropy_guard_status",
        &["get_ransomware_entropy_guard_status"],
    ),
    ("get_lan_sensor_overview", &["get_lan_sensor_overview"]),
    ("get_lan_network_threats", &["get_lan_network_threats"]),
    (
        "get_privilege_escalation_paths",
        &[
            "get_privilege_escalation_paths",
            "get_privilege_escalation_paths_for_agent_users",
        ],
    ),
    ("get_access_log_report", &["get_access_log_report"]),
];

#[test]
fn the_table_is_the_tool_list_of_roamswitch_mcp() {
    let list = common::response("tools_list");
    let mut real: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    let mut table: Vec<&str> = TOOLS.iter().map(|(t, _)| *t).collect();
    real.sort_unstable();
    table.sort_unstable();
    assert_eq!(real.len(), 45);
    assert_eq!(table, real);
}

#[test]
fn every_tool_is_called_by_a_method() {
    let src = include_str!("../src/client.rs");
    for (tool, methods) in TOOLS {
        assert!(
            src.contains(&format!("\"{tool}\"")),
            "no method calls {tool}"
        );
        for m in methods {
            assert!(
                src.contains(&format!("pub async fn {m}(")),
                "{tool}: no method {m}"
            );
        }
    }
}

/// The README states how many tools do not only read; the tool annotations are the source.
#[test]
fn three_tools_are_not_read_only_and_one_reaches_out() {
    let list = common::response("tools_list");
    let tools = list["result"]["tools"].as_array().unwrap();
    let not_read_only: Vec<&str> = tools
        .iter()
        .filter(|t| t["annotations"]["readOnlyHint"] == false)
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        not_read_only,
        [
            "audit_security_logs",
            "run_active_vuln_scan",
            "run_npm_audit_signatures"
        ]
    );
    let open_world: Vec<&str> = tools
        .iter()
        .filter(|t| t["annotations"]["openWorldHint"] == true)
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(open_world, ["run_npm_audit_signatures"]);
}
